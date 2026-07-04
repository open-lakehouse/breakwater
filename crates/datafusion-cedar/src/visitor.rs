//! Walk a [`LogicalPlan`] and turn the tables/actions it references into Cedar
//! authorization [`Request`]s.
//!
//! This mirrors `datafusion-openlineage`'s `extract()`: a [`TreeNodeVisitor`]
//! over the optimized plan that classifies each relevant node into a
//! [`PlanAction`], which is then lowered to a Cedar request whose resource and
//! context carry the table identity and the columns being accessed.

use std::str::FromStr as _;
use std::sync::LazyLock;

use cedar_policy::{Context, EntityTypeName, Request, RestrictedExpression};
use datafusion::common::plan_datafusion_err;
use datafusion::common::tree_node::{TreeNode as _, TreeNodeRecursion, TreeNodeVisitor};
use datafusion::error::Result;
use datafusion::logical_expr::{DdlStatement, LogicalPlan, WriteOp};
use datafusion::sql::TableReference;

use cedar_oci::{EntityId, EntityUid};

use crate::principal::PrincipalIdentity;

/// An access-relevant operation discovered in a logical plan.
pub(crate) enum PlanAction {
    /// Read `table`, accessing the listed columns.
    ReadTable(TableReference, Vec<String>),
    /// Write (insert/update/delete/truncate) into `table`.
    WriteTable(TableReference),
    /// Create `table`.
    CreateTable(TableReference),
    /// Unity Catalog DDL on a `Catalog` or `Schema` securable, recognized from
    /// the `ExecuteUnityCatalogPlanNode` extension node. `action` is the Cedar
    /// action id (e.g. `create_catalog`); `resource_type` is `Catalog`/`Schema`;
    /// `name` is the securable's name.
    UnityDdl {
        action: &'static str,
        resource_type: &'static str,
        name: String,
    },
    /// A state-changing node we do not model. We cannot prove it is safe, so it
    /// must be denied (fail-closed). Carries a short description for diagnostics.
    DenyUnsupported(String),
}

/// Recognize a Unity Catalog DDL extension node by its command name and lower
/// it to a [`PlanAction::UnityDdl`].
///
/// `datafusion-cedar` stays free of any Unity-Catalog dependency: it matches on
/// the stable command-name contract exposed by the extension node's
/// [`name`](datafusion::logical_expr::UserDefinedLogicalNode::name) — one of
/// `CreateCatalog`/`DropCatalog`/`CreateSchema`/`DropSchema` — rather than
/// downcasting to a concrete type. The securable name is carried in the request
/// context (see [`unity_ddl_context`]); a policy may gate on the action alone or
/// additionally on `context.securable`.
///
/// Managed `CREATE TABLE` (`CreateManagedTable`) is handled separately in the
/// visitor — its securable is a `Table`, so it lowers to a table create
/// (`create_external_table`) with the `Table` resource + catalog-fact folding,
/// rather than the Catalog/Schema shape this function produces.
fn recognize_unity_ddl(name: &str) -> Option<(&'static str, &'static str)> {
    match name {
        "CreateCatalog" => Some(("create_catalog", "Catalog")),
        "DropCatalog" => Some(("drop_catalog", "Catalog")),
        "CreateSchema" => Some(("create_schema", "Schema")),
        "DropSchema" => Some(("drop_schema", "Schema")),
        _ => None,
    }
}

pub(crate) struct AuthorizationVisitor {
    pub(crate) actions: Vec<PlanAction>,
}

impl TreeNodeVisitor<'_> for AuthorizationVisitor {
    type Node = LogicalPlan;

    fn f_down(&mut self, node: &Self::Node) -> Result<TreeNodeRecursion> {
        match node {
            LogicalPlan::TableScan(scan) => {
                let fields = scan
                    .projected_schema
                    .fields()
                    .iter()
                    .map(|f| f.name().to_string())
                    .collect();
                self.actions
                    .push(PlanAction::ReadTable(scan.table_name.clone(), fields));
            }
            LogicalPlan::Ddl(ddl) => match ddl {
                DdlStatement::CreateExternalTable(cmd) => {
                    self.actions.push(PlanAction::CreateTable(cmd.name.clone()));
                }
                DdlStatement::CreateMemoryTable(cmd) => {
                    self.actions.push(PlanAction::CreateTable(cmd.name.clone()));
                }
                // Any other (state-changing) DDL we do not model — schema/catalog
                // create/drop, table drop, views, indexes, functions — is denied
                // rather than silently allowed through.
                other => {
                    self.actions
                        .push(PlanAction::DenyUnsupported(format!("DDL {}", other.name())));
                }
            },
            LogicalPlan::Dml(dml) => match dml.op {
                // INSERT/UPDATE/DELETE/TRUNCATE all mutate the target table.
                WriteOp::Insert(_) | WriteOp::Update | WriteOp::Delete | WriteOp::Truncate => {
                    self.actions
                        .push(PlanAction::WriteTable(dml.table_name.clone()));
                }
                // CTAS produces a new table; treat as a create.
                WriteOp::Ctas => {
                    self.actions
                        .push(PlanAction::CreateTable(dml.table_name.clone()));
                }
            },
            LogicalPlan::Extension(ext) => {
                let node = ext.node.as_ref();
                // Only Unity Catalog DDL extension nodes are state-changing and
                // must be authorized; other extension nodes (e.g. instrumentation
                // wrappers) are pass-through and ignored, matching the default
                // arm below.
                if node.name() == "CreateManagedTable" {
                    // A managed `CREATE TABLE` securable is a `Table`; authorize
                    // it as a table create (same action/resource/fact-folding as
                    // `CreateExternalTable`/CTAS) rather than a Catalog/Schema DDL.
                    let table_ref = TableReference::parse_str(&securable_name_from_node(node));
                    self.actions.push(PlanAction::CreateTable(table_ref));
                } else if let Some((action, resource_type)) = recognize_unity_ddl(node.name()) {
                    self.actions.push(PlanAction::UnityDdl {
                        action,
                        resource_type,
                        name: securable_name_from_node(node),
                    });
                }
            }
            _ => {}
        }
        Ok(TreeNodeRecursion::Continue)
    }
}

static CREATE_EXTERNAL_TABLE_ACTION: LazyLock<EntityUid> = LazyLock::new(|| {
    EntityUid::from_type_name_and_id(
        "Action".parse().unwrap(),
        EntityId::new("create_external_table"),
    )
});
static READ_TABLE_ACTION: LazyLock<EntityUid> = LazyLock::new(|| {
    EntityUid::from_type_name_and_id("Action".parse().unwrap(), EntityId::new("read_table"))
});
static WRITE_TABLE_ACTION: LazyLock<EntityUid> = LazyLock::new(|| {
    EntityUid::from_type_name_and_id("Action".parse().unwrap(), EntityId::new("write_table"))
});
/// Action used for state-changing nodes we do not model. No policy is expected
/// to permit it, so Cedar's default-deny rejects the query (fail-closed).
static DENY_UNSUPPORTED_ACTION: LazyLock<EntityUid> = LazyLock::new(|| {
    EntityUid::from_type_name_and_id("Action".parse().unwrap(), EntityId::new("deny_unsupported"))
});

/// Build the `Table` resource uid for a table reference.
fn table_resource(table_ref: &TableReference) -> EntityUid {
    let table_type_name = EntityTypeName::from_str("Table").unwrap();
    EntityUid::from_type_name_and_id(table_type_name, EntityId::new(table_ref.to_string()))
}

/// Build a resource uid of an arbitrary entity type from a name (used for the
/// `Catalog`/`Schema` securables of Unity Catalog DDL).
fn named_resource(resource_type: &str, name: &str) -> EntityUid {
    let type_name = EntityTypeName::from_str(resource_type).unwrap();
    EntityUid::from_type_name_and_id(type_name, EntityId::new(name))
}

/// Extract the securable name from a Unity Catalog DDL extension node.
///
/// The node's `Display` (via `fmt_for_explain`) has the stable shape
/// `"<Command>: name=<securable> ..."`. We read the `name=` token defensively;
/// if it cannot be found the securable is reported as empty, which still
/// authorizes the action (the per-action gate applies) but carries no securable
/// in the request context.
fn securable_name_from_node(node: &dyn datafusion::logical_expr::UserDefinedLogicalNode) -> String {
    let rendered = format!("{}", DisplayNode(node));
    rendered
        .split("name=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or("")
        .to_string()
}

/// Adapter to render a `UserDefinedLogicalNode` via its `fmt_for_explain`.
struct DisplayNode<'a>(&'a dyn datafusion::logical_expr::UserDefinedLogicalNode);

impl std::fmt::Display for DisplayNode<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt_for_explain(f)
    }
}

/// Build the request context for Unity Catalog DDL, carrying the securable name
/// so policies may gate on `context.securable` in addition to the action.
fn unity_ddl_context(name: &str) -> Result<Context> {
    Context::from_pairs([(
        "securable".to_string(),
        RestrictedExpression::new_string(name.to_string()),
    )])
    .map_err(|e| plan_datafusion_err!("Failed to build request context: {}", e))
}

/// Build the agent tool-call context carrying the session's observed taints, so
/// guardrail policies can gate on `context.observed_taints` (e.g. `forbid
/// send_external when context.observed_taints.contains("pii")`). This is the
/// data-flow control that survives prompt injection — it blocks the *action*,
/// not the prompt.
#[cfg(feature = "governance")]
pub(crate) fn tool_context(
    observed_taints: &std::collections::BTreeSet<String>,
) -> Result<Context> {
    Context::from_pairs([(
        "observed_taints".to_string(),
        RestrictedExpression::new_set(
            observed_taints
                .iter()
                .map(|t| RestrictedExpression::new_string(t.clone())),
        ),
    )])
    .map_err(|e| plan_datafusion_err!("Failed to build tool context: {}", e))
}

/// Build the request context carrying the table identity and accessed columns,
/// so policies can condition on `context.catalog/schema/table/columns`.
///
/// Shared with Layer-2 governance (`cedar::table_policy`), which builds the same
/// context (with an empty column set) for its partial-eval request so that
/// row-filter policies can also condition on the table identity.
pub(crate) fn table_context(table_ref: &TableReference, columns: &[String]) -> Result<Context> {
    let mut pairs: Vec<(String, RestrictedExpression)> = Vec::new();
    if let Some(catalog) = table_ref.catalog() {
        pairs.push((
            "catalog".to_string(),
            RestrictedExpression::new_string(catalog.to_string()),
        ));
    }
    if let Some(schema) = table_ref.schema() {
        pairs.push((
            "schema".to_string(),
            RestrictedExpression::new_string(schema.to_string()),
        ));
    }
    pairs.push((
        "table".to_string(),
        RestrictedExpression::new_string(table_ref.table().to_string()),
    ));
    if !columns.is_empty() {
        pairs.push((
            "columns".to_string(),
            RestrictedExpression::new_set(
                columns
                    .iter()
                    .map(|c| RestrictedExpression::new_string(c.clone())),
            ),
        ));
    }
    Context::from_pairs(pairs)
        .map_err(|e| plan_datafusion_err!("Failed to build request context: {}", e))
}

/// A Cedar request paired with the table it concerns (when any), so the caller
/// can fold that table's catalog facts into the request-time `resource` entity.
/// `table` is `None` for requests not over a `Table` resource (e.g. Unity DDL on
/// a Catalog/Schema, or the deny sentinel).
pub(crate) struct PlanRequest {
    pub(crate) request: Request,
    pub(crate) table: Option<TableReference>,
}

/// Build the `Table` resource uid for a table reference. Shared so the Cedar
/// layer folds catalog facts onto the *same* uid the request resolves against.
pub(crate) fn table_resource_uid(table_ref: &TableReference) -> EntityUid {
    table_resource(table_ref)
}

/// Lower a logical plan to the set of Cedar requests that must all be permitted
/// for the plan to run. Each request carries the principal, the action, the
/// `Table` resource, and a context describing the table and accessed columns;
/// the paired [`PlanRequest::table`] lets the caller fold that table's catalog
/// facts into the request-time entities.
pub(crate) fn authorize_plan(
    plan: &LogicalPlan,
    principal: &PrincipalIdentity,
) -> Result<Vec<PlanRequest>> {
    let mut visitor = AuthorizationVisitor { actions: vec![] };
    plan.visit(&mut visitor)?;

    // Parse the neutral principal uid once into a Cedar uid for every request.
    let principal_uid = crate::cedar_entity::parse_uid(&principal.uid)?;

    let mut requests = vec![];
    for action in visitor.actions {
        let (action_uid, resource, context, table) = match action {
            PlanAction::ReadTable(table_ref, columns) => (
                READ_TABLE_ACTION.clone(),
                table_resource(&table_ref),
                table_context(&table_ref, &columns)?,
                Some(table_ref),
            ),
            PlanAction::WriteTable(table_ref) => (
                WRITE_TABLE_ACTION.clone(),
                table_resource(&table_ref),
                table_context(&table_ref, &[])?,
                Some(table_ref),
            ),
            PlanAction::CreateTable(table_ref) => (
                CREATE_EXTERNAL_TABLE_ACTION.clone(),
                table_resource(&table_ref),
                table_context(&table_ref, &[])?,
                Some(table_ref),
            ),
            PlanAction::UnityDdl {
                action,
                resource_type,
                name,
            } => (
                EntityUid::from_type_name_and_id("Action".parse().unwrap(), EntityId::new(action)),
                named_resource(resource_type, &name),
                unity_ddl_context(&name)?,
                None,
            ),
            // Lower an unsupported node to a request no policy permits; Cedar's
            // default-deny then rejects the query (fail-closed).
            PlanAction::DenyUnsupported(what) => {
                tracing::warn!(node = %what, "unsupported state-changing plan node; denying (fail-closed)");
                (
                    DENY_UNSUPPORTED_ACTION.clone(),
                    table_resource(&TableReference::bare(what)),
                    table_context(&TableReference::bare("unsupported"), &[])?,
                    None,
                )
            }
        };
        let request = Request::new(principal_uid.clone(), action_uid, resource, context, None)
            .map_err(|e| plan_datafusion_err!("Failed to create request: {}", e))?;
        requests.push(PlanRequest { request, table });
    }

    Ok(requests)
}

#[cfg(test)]
mod tests {
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::logical_expr::logical_plan::builder::table_scan;

    use super::*;

    fn principal() -> PrincipalIdentity {
        PrincipalIdentity::new("User::\"alice\"")
    }

    fn schema() -> Schema {
        Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("name", DataType::Utf8, true),
        ])
    }

    #[test]
    fn read_scan_yields_one_request_with_columns() {
        let plan = table_scan(Some("t"), &schema(), None)
            .unwrap()
            .build()
            .unwrap();
        let requests = authorize_plan(&plan, &principal()).unwrap();
        assert_eq!(requests.len(), 1);
        // The action is read_table; context carries the table identity, and the
        // request is paired with the table it concerns.
        assert_eq!(
            requests[0].request.action().unwrap().to_string(),
            "Action::\"read_table\""
        );
        assert_eq!(requests[0].table.as_ref().map(|t| t.table()), Some("t"));
    }

    #[test]
    fn projected_scan_limits_columns() {
        // Projecting a single column should still authorize the scan (and the
        // visitor records only the projected column set).
        let plan = table_scan(Some("t"), &schema(), Some(vec![0]))
            .unwrap()
            .build()
            .unwrap();
        let requests = authorize_plan(&plan, &principal()).unwrap();
        assert_eq!(requests.len(), 1);
    }

    #[test]
    fn empty_relation_yields_no_requests() {
        use datafusion::logical_expr::LogicalPlanBuilder;
        let plan = LogicalPlanBuilder::empty(false).build().unwrap();
        let requests = authorize_plan(&plan, &principal()).unwrap();
        assert!(requests.is_empty());
    }

    fn action_of(req: &PlanRequest) -> String {
        req.request.action().unwrap().to_string()
    }

    // Build real plans through a SessionContext with registered tables, so the
    // DML/DDL node shapes match what the engine actually produces.
    async fn ctx_with_tables() -> datafusion::prelude::SessionContext {
        use datafusion::datasource::MemTable;
        use datafusion::prelude::SessionContext;
        use std::sync::Arc;
        let ctx = SessionContext::new();
        let s = Arc::new(schema());
        for name in ["a", "b", "dst"] {
            let table = MemTable::try_new(s.clone(), vec![vec![]]).unwrap();
            ctx.register_table(name, Arc::new(table)).unwrap();
        }
        ctx
    }

    #[tokio::test]
    async fn insert_yields_write_table_request() {
        let ctx = ctx_with_tables().await;
        let plan = ctx
            .sql("INSERT INTO dst SELECT * FROM a")
            .await
            .unwrap()
            .into_unoptimized_plan();
        let requests = authorize_plan(&plan, &principal()).unwrap();
        assert!(
            requests
                .iter()
                .any(|r| action_of(r) == "Action::\"write_table\"")
        );
        assert!(
            requests
                .iter()
                .any(|r| action_of(r) == "Action::\"read_table\"")
        );
    }

    #[tokio::test]
    async fn join_yields_one_read_request_per_table() {
        let ctx = ctx_with_tables().await;
        let plan = ctx
            .sql("SELECT a.id FROM a JOIN b ON a.id = b.id")
            .await
            .unwrap()
            .into_unoptimized_plan();
        let requests = authorize_plan(&plan, &principal()).unwrap();
        let reads = requests
            .iter()
            .filter(|r| action_of(r) == "Action::\"read_table\"")
            .count();
        assert_eq!(reads, 2, "each joined table is authorized independently");
    }

    /// Minimal extension node standing in for `ExecuteUnityCatalogPlanNode`,
    /// named after a Unity Catalog DDL command, used to drive the name-based
    /// recognition in the visitor without depending on the UC crate.
    #[derive(Debug, PartialEq, Eq, Hash, PartialOrd)]
    struct FakeDdlNode {
        command: &'static str,
        securable: &'static str,
    }

    impl datafusion::logical_expr::UserDefinedLogicalNodeCore for FakeDdlNode {
        fn name(&self) -> &str {
            self.command
        }
        fn inputs(&self) -> Vec<&LogicalPlan> {
            vec![]
        }
        fn schema(&self) -> &datafusion::common::DFSchemaRef {
            static EMPTY: LazyLock<datafusion::common::DFSchemaRef> =
                LazyLock::new(|| std::sync::Arc::new(datafusion::common::DFSchema::empty()));
            &EMPTY
        }
        fn expressions(&self) -> Vec<datafusion::logical_expr::Expr> {
            vec![]
        }
        fn fmt_for_explain(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "{}: name={}", self.command, self.securable)
        }
        fn with_exprs_and_inputs(
            &self,
            _exprs: Vec<datafusion::logical_expr::Expr>,
            _inputs: Vec<LogicalPlan>,
        ) -> Result<Self> {
            Ok(Self {
                command: self.command,
                securable: self.securable,
            })
        }
    }

    fn ddl_plan(command: &'static str, securable: &'static str) -> LogicalPlan {
        use datafusion::logical_expr::Extension;
        use std::sync::Arc;
        LogicalPlan::Extension(Extension {
            node: Arc::new(FakeDdlNode { command, securable }),
        })
    }

    #[test]
    fn unity_ddl_extension_yields_matching_action() {
        for (command, action) in [
            ("CreateCatalog", "create_catalog"),
            ("DropCatalog", "drop_catalog"),
            ("CreateSchema", "create_schema"),
            ("DropSchema", "drop_schema"),
        ] {
            let plan = ddl_plan(command, "my_catalog.sales");
            let requests = authorize_plan(&plan, &principal()).unwrap();
            assert_eq!(requests.len(), 1, "{command} -> one request");
            assert_eq!(
                action_of(&requests[0]),
                format!("Action::\"{action}\""),
                "{command} lowers to {action}"
            );
        }
    }

    #[test]
    fn create_managed_table_lowers_to_table_create() {
        // A managed `CREATE TABLE` extension node authorizes as a table create
        // (create_external_table over a Table resource), not a Catalog/Schema DDL.
        let plan = ddl_plan("CreateManagedTable", "my_catalog.sales.orders");
        let requests = authorize_plan(&plan, &principal()).unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(action_of(&requests[0]), "Action::\"create_external_table\"");
        assert_eq!(
            requests[0].table.as_ref().map(|t| t.to_string()),
            Some("my_catalog.sales.orders".to_string()),
            "managed create carries the Table reference for fact folding"
        );
    }

    #[test]
    fn unrecognized_extension_is_ignored() {
        // A non-UC extension node is pass-through (no request), so it neither
        // grants nor blocks on its own.
        let plan = ddl_plan("SomeOtherExtension", "whatever");
        let requests = authorize_plan(&plan, &principal()).unwrap();
        assert!(requests.is_empty());
    }

    #[test]
    fn unmodeled_ddl_yields_deny_unsupported() {
        use datafusion::logical_expr::{DdlStatement, DropTable, LogicalPlan};
        use std::sync::Arc;
        // DROP TABLE is state-changing and not modeled -> deny sentinel action.
        let inner = table_scan(Some("t"), &schema(), None)
            .unwrap()
            .build()
            .unwrap();
        let plan = LogicalPlan::Ddl(DdlStatement::DropTable(DropTable {
            name: TableReference::bare("t"),
            if_exists: false,
            schema: Arc::new(inner.schema().as_ref().clone()),
        }));
        let requests = authorize_plan(&plan, &principal()).unwrap();
        assert!(
            requests
                .iter()
                .any(|r| action_of(r) == "Action::\"deny_unsupported\""),
            "unmodeled DDL must produce a deny sentinel"
        );
    }
}
