//! Walk a [`LogicalPlan`] and classify the tables/actions it references into a
//! neutral [`PlanAction`] list — the "what does the plan touch" analysis every
//! policy engine needs.
//!
//! This mirrors `datafusion-openlineage`'s `extract()`: a [`TreeNodeVisitor`]
//! over the plan that classifies each access-relevant node. It names no policy
//! engine — an adapter lowers each [`PlanAction`] to its own authorization
//! request (see the Cedar adapter's request-building for one lowering).

use datafusion::common::tree_node::{TreeNode as _, TreeNodeRecursion, TreeNodeVisitor};
use datafusion::error::Result;
use datafusion::logical_expr::{DdlStatement, LogicalPlan, WriteOp};
use datafusion::sql::TableReference;

/// An access-relevant operation discovered in a logical plan.
///
/// Fields are public so an engine adapter can read the securable identity and
/// accessed columns off each variant when it builds its authorization request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanAction {
    /// Read `table`, accessing the listed columns.
    ReadTable(TableReference, Vec<String>),
    /// Write (insert/update/delete/truncate) into `table`.
    WriteTable(TableReference),
    /// Create `table`.
    CreateTable(TableReference),
    /// Unity Catalog DDL on a `Catalog` or `Schema` securable, recognized from
    /// the `ExecuteUnityCatalogPlanNode` extension node. `action` is the action
    /// id (e.g. `create_catalog`); `resource_type` is `Catalog`/`Schema`;
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
/// it to the `(action, resource_type)` pair a [`PlanAction::UnityDdl`] carries.
///
/// This layer stays free of any Unity-Catalog dependency: it matches on the
/// stable command-name contract exposed by the extension node's
/// [`name`](datafusion::logical_expr::UserDefinedLogicalNode::name) — one of
/// `CreateCatalog`/`DropCatalog`/`CreateSchema`/`DropSchema` — rather than
/// downcasting to a concrete type. The securable name is carried on the action
/// (see [`securable_name_from_node`]).
///
/// Managed `CREATE TABLE` (`CreateManagedTable`) is handled separately in the
/// visitor — its securable is a `Table`, so it lowers to a table create rather
/// than the Catalog/Schema shape this function produces.
fn recognize_unity_ddl(name: &str) -> Option<(&'static str, &'static str)> {
    match name {
        "CreateCatalog" => Some(("create_catalog", "Catalog")),
        "DropCatalog" => Some(("drop_catalog", "Catalog")),
        "CreateSchema" => Some(("create_schema", "Schema")),
        "DropSchema" => Some(("drop_schema", "Schema")),
        _ => None,
    }
}

struct AuthorizationVisitor {
    actions: Vec<PlanAction>,
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
                    // A managed `CREATE TABLE` securable is a `Table`; classify
                    // it as a table create (same shape as
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

/// Extract the securable name from a Unity Catalog DDL extension node.
///
/// The node's `Display` (via `fmt_for_explain`) has the stable shape
/// `"<Command>: name=<securable> ..."`. We read the `name=` token defensively;
/// if it cannot be found the securable is reported as empty, which still
/// classifies the action (the per-action gate applies) but carries no securable
/// name.
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

/// Walk `plan` and return the neutral [`PlanAction`]s that must be authorized
/// for it to run. An engine adapter lowers each action to its own request.
pub fn plan_actions(plan: &LogicalPlan) -> Result<Vec<PlanAction>> {
    let mut visitor = AuthorizationVisitor { actions: vec![] };
    plan.visit(&mut visitor)?;
    Ok(visitor.actions)
}

#[cfg(test)]
mod tests {
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::logical_expr::logical_plan::builder::table_scan;

    use super::*;

    fn schema() -> Schema {
        Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("name", DataType::Utf8, true),
        ])
    }

    #[test]
    fn read_scan_yields_one_read_action_with_columns() {
        let plan = table_scan(Some("t"), &schema(), None)
            .unwrap()
            .build()
            .unwrap();
        let actions = plan_actions(&plan).unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            PlanAction::ReadTable(table, cols) => {
                assert_eq!(table.table(), "t");
                assert_eq!(cols, &["id".to_string(), "name".to_string()]);
            }
            other => panic!("expected ReadTable, got {other:?}"),
        }
    }

    #[test]
    fn projected_scan_limits_columns() {
        let plan = table_scan(Some("t"), &schema(), Some(vec![0]))
            .unwrap()
            .build()
            .unwrap();
        let actions = plan_actions(&plan).unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            PlanAction::ReadTable(_, cols) => assert_eq!(cols, &["id".to_string()]),
            other => panic!("expected ReadTable, got {other:?}"),
        }
    }

    #[test]
    fn empty_relation_yields_no_actions() {
        use datafusion::logical_expr::LogicalPlanBuilder;
        let plan = LogicalPlanBuilder::empty(false).build().unwrap();
        assert!(plan_actions(&plan).unwrap().is_empty());
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
    async fn insert_yields_write_and_read_actions() {
        let ctx = ctx_with_tables().await;
        let plan = ctx
            .sql("INSERT INTO dst SELECT * FROM a")
            .await
            .unwrap()
            .into_unoptimized_plan();
        let actions = plan_actions(&plan).unwrap();
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, PlanAction::WriteTable(t) if t.table() == "dst"))
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, PlanAction::ReadTable(t, _) if t.table() == "a"))
        );
    }

    #[tokio::test]
    async fn join_yields_one_read_action_per_table() {
        let ctx = ctx_with_tables().await;
        let plan = ctx
            .sql("SELECT a.id FROM a JOIN b ON a.id = b.id")
            .await
            .unwrap()
            .into_unoptimized_plan();
        let reads = plan_actions(&plan)
            .unwrap()
            .into_iter()
            .filter(|a| matches!(a, PlanAction::ReadTable(..)))
            .count();
        assert_eq!(reads, 2, "each joined table is classified independently");
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
            use std::sync::LazyLock;
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
        for (command, expected) in [
            ("CreateCatalog", ("create_catalog", "Catalog")),
            ("DropCatalog", ("drop_catalog", "Catalog")),
            ("CreateSchema", ("create_schema", "Schema")),
            ("DropSchema", ("drop_schema", "Schema")),
        ] {
            let plan = ddl_plan(command, "my_catalog.sales");
            let actions = plan_actions(&plan).unwrap();
            assert_eq!(actions.len(), 1, "{command} -> one action");
            match &actions[0] {
                PlanAction::UnityDdl {
                    action,
                    resource_type,
                    name,
                } => {
                    assert_eq!((*action, *resource_type), expected, "{command}");
                    assert_eq!(name, "my_catalog.sales");
                }
                other => panic!("expected UnityDdl for {command}, got {other:?}"),
            }
        }
    }

    #[test]
    fn create_managed_table_lowers_to_table_create() {
        // A managed `CREATE TABLE` extension node classifies as a table create,
        // not a Catalog/Schema DDL.
        let plan = ddl_plan("CreateManagedTable", "my_catalog.sales.orders");
        let actions = plan_actions(&plan).unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            PlanAction::CreateTable(t) => {
                assert_eq!(t.to_string(), "my_catalog.sales.orders");
            }
            other => panic!("expected CreateTable, got {other:?}"),
        }
    }

    #[test]
    fn unrecognized_extension_is_ignored() {
        // A non-UC extension node is pass-through (no action).
        let plan = ddl_plan("SomeOtherExtension", "whatever");
        assert!(plan_actions(&plan).unwrap().is_empty());
    }

    #[test]
    fn unmodeled_ddl_yields_deny_unsupported() {
        use datafusion::logical_expr::{DdlStatement, DropTable, LogicalPlan};
        use std::sync::Arc;
        // DROP TABLE is state-changing and not modeled -> deny sentinel.
        let inner = table_scan(Some("t"), &schema(), None)
            .unwrap()
            .build()
            .unwrap();
        let plan = LogicalPlan::Ddl(DdlStatement::DropTable(DropTable {
            name: TableReference::bare("t"),
            if_exists: false,
            schema: Arc::new(inner.schema().as_ref().clone()),
        }));
        let actions = plan_actions(&plan).unwrap();
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, PlanAction::DenyUnsupported(_))),
            "unmodeled DDL must produce a deny sentinel"
        );
    }
}
