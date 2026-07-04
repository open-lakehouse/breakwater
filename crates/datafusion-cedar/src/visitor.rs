//! Lower the neutral [`PlanAction`] list into Cedar authorization
//! [`Request`]s.
//!
//! The "what does the plan touch" analysis is engine-neutral and lives in
//! [`datafusion_policy::plan_actions`]; this module is the Cedar-specific half —
//! it turns each [`PlanAction`] into a Cedar request whose resource and context
//! carry the table identity and the columns being accessed.

use std::str::FromStr as _;
use std::sync::LazyLock;

use cedar_policy::{Context, EntityTypeName, Request, RestrictedExpression};
use datafusion::common::plan_datafusion_err;
use datafusion::error::Result;
use datafusion::sql::TableReference;

use cedar_oci::{EntityId, EntityUid};
use datafusion_policy::{PlanAction, PrincipalIdentity, plan_actions};

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
#[cfg(feature = "fgac")]
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
/// Shared with Layer-2 governance (`cedar::constrain`), which builds the same
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
/// for the plan to run. The plan is first classified into neutral
/// [`PlanAction`]s by [`datafusion_policy::plan_actions`]; each action then
/// becomes a request carrying the principal, the action, the resource, and a
/// context describing the table and accessed columns. The paired
/// [`PlanRequest::table`] lets the caller fold that table's catalog facts into
/// the request-time entities.
pub(crate) fn authorize_plan(
    plan: &datafusion::logical_expr::LogicalPlan,
    principal: &PrincipalIdentity,
) -> Result<Vec<PlanRequest>> {
    let actions = plan_actions(plan)?;

    // Parse the neutral principal uid once into a Cedar uid for every request.
    let principal_uid = crate::cedar_entity::parse_uid(&principal.uid)?;

    let mut requests = vec![];
    for action in actions {
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
    use datafusion::logical_expr::LogicalPlan;
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

    fn action_of(req: &PlanRequest) -> String {
        req.request.action().unwrap().to_string()
    }

    #[test]
    fn read_scan_yields_one_request_over_the_table() {
        let plan = table_scan(Some("t"), &schema(), None)
            .unwrap()
            .build()
            .unwrap();
        let requests = authorize_plan(&plan, &principal()).unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(action_of(&requests[0]), "Action::\"read_table\"");
        assert_eq!(requests[0].table.as_ref().map(|t| t.table()), Some("t"));
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

    /// Minimal extension node standing in for a Unity Catalog DDL command, to
    /// drive the Cedar request lowering end-to-end.
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
    fn unmodeled_ddl_yields_deny_unsupported() {
        use datafusion::logical_expr::{DdlStatement, DropTable};
        use std::sync::Arc;
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
