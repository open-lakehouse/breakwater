//! End-to-end `govern_plan` over the `AbacPolicyEngine`: fixture
//! [`PolicyBinding`]s in the catalog fact sink + a stub
//! [`CatalogFunctionResolver`], run against a real `MemTable`, asserting the
//! masked / filtered results for a matching vs a non-matching principal.
//!
//! This is the neutral counterpart to the Cedar crate's TPE integration tests:
//! it exercises the full decide → constrain → rewrite → optimize → execute path
//! with no Cedar and no catalog client.

#![cfg(feature = "fgac")]

use std::sync::Arc;

use datafusion::arrow::array::{Array, Int64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::common::Result;
use datafusion::datasource::MemTable;
use datafusion::logical_expr::{
    ColumnarValue, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
};
use datafusion::prelude::SessionContext;
use datafusion::scalar::ScalarValue;
use datafusion::sql::TableReference;

use olai_datafusion_policy::{
    AbacPolicyEngine, BindingKind, CatalogFactSink, CatalogFunctionResolver, ColumnMatch,
    EvalContext, FunctionArg, PolicyBinding, PrincipalIdentity, TableFacts, TagCondition,
    govern_plan,
};

/// A masking UDF that replaces its (string) argument with `"REDACTED"`.
#[derive(Debug, PartialEq, Eq, Hash)]
struct RedactUdf(Signature);
impl RedactUdf {
    fn new() -> Self {
        Self(Signature::variadic_any(Volatility::Immutable))
    }
}
impl ScalarUDFImpl for RedactUdf {
    fn name(&self) -> &str {
        "redact"
    }
    fn signature(&self) -> &Signature {
        &self.0
    }
    fn return_type(&self, _args: &[DataType]) -> Result<DataType> {
        Ok(DataType::Utf8)
    }
    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> Result<ColumnarValue> {
        // Replace every value with a constant redaction marker.
        let n = args.number_rows;
        let values = std::iter::repeat_n(Some("REDACTED"), n).collect::<StringArray>();
        Ok(ColumnarValue::Array(Arc::new(values)))
    }
}

/// A row-filter UDF: `keep_eu(region) -> region = 'eu'`.
#[derive(Debug, PartialEq, Eq, Hash)]
struct KeepEuUdf(Signature);
impl KeepEuUdf {
    fn new() -> Self {
        Self(Signature::variadic_any(Volatility::Immutable))
    }
}
impl ScalarUDFImpl for KeepEuUdf {
    fn name(&self) -> &str {
        "keep_eu"
    }
    fn signature(&self) -> &Signature {
        &self.0
    }
    fn return_type(&self, _args: &[DataType]) -> Result<DataType> {
        Ok(DataType::Boolean)
    }
    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> Result<ColumnarValue> {
        let ColumnarValue::Array(arr) = &args.args[0] else {
            return Ok(ColumnarValue::Scalar(ScalarValue::Boolean(Some(false))));
        };
        let region = arr
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("region is Utf8");
        let mask = region
            .iter()
            .map(|v| Some(v == Some("eu")))
            .collect::<datafusion::arrow::array::BooleanArray>();
        Ok(ColumnarValue::Array(Arc::new(mask)))
    }
}

/// Resolves the two fixture functions by name.
#[derive(Debug)]
struct FixtureResolver;

#[async_trait::async_trait]
impl CatalogFunctionResolver for FixtureResolver {
    async fn resolve(&self, name: &str) -> Result<Arc<ScalarUDF>> {
        match name {
            "hr.redact" => Ok(Arc::new(ScalarUDF::from(RedactUdf::new()))),
            "hr.keep_eu" => Ok(Arc::new(ScalarUDF::from(KeepEuUdf::new()))),
            other => Err(datafusion::common::plan_datafusion_err!(
                "no such function {other}"
            )),
        }
    }
}

fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("region", DataType::Utf8, true),
        Field::new("ssn", DataType::Utf8, true),
    ]))
}

/// A ctx with table `t` holding two rows: (1,"eu","AAA"), (2,"us","BBB").
async fn ctx() -> SessionContext {
    let ctx = SessionContext::new();
    let schema = schema();
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1, 2])),
            Arc::new(StringArray::from(vec!["eu", "us"])),
            Arc::new(StringArray::from(vec!["AAA", "BBB"])),
        ],
    )
    .unwrap();
    let table = MemTable::try_new(schema, vec![vec![batch]]).unwrap();
    ctx.register_table("t", Arc::new(table)).unwrap();
    ctx
}

/// Facts for `t`: ssn is `pii`-tagged; a mask binding redacts pii columns and a
/// row-filter binding keeps only `region = 'eu'` — both `TO analysts`.
fn eval_for(ctx_kind: &str) -> EvalContext {
    let sink = CatalogFactSink::new();
    let mask = PolicyBinding {
        name: "mask_pii".into(),
        kind: BindingKind::ColumnMask,
        to_principals: vec!["analysts".into()],
        except_principals: vec![],
        when_condition: vec![],
        match_columns: vec![ColumnMatch {
            condition: TagCondition {
                key: "pii".into(),
                value: None,
            },
            alias: "c".into(),
        }],
        function: "hr.redact".into(),
        using_args: vec![],
    };
    let row = PolicyBinding {
        name: "eu_only".into(),
        kind: BindingKind::RowFilter,
        to_principals: vec!["analysts".into()],
        except_principals: vec![],
        when_condition: vec![],
        match_columns: vec![ColumnMatch {
            condition: TagCondition {
                key: "region_tag".into(),
                value: None,
            },
            alias: "r".into(),
        }],
        function: "hr.keep_eu".into(),
        using_args: vec![FunctionArg::Alias("r".into())],
    };
    let policies = match ctx_kind {
        "both" => vec![mask, row],
        "mask" => vec![mask],
        _ => vec![],
    };
    sink.record(
        TableReference::bare("t"),
        TableFacts {
            governed_column_tags: std::collections::HashMap::from([
                (
                    "ssn".to_string(),
                    std::collections::BTreeMap::from([("pii".to_string(), "ssn".to_string())]),
                ),
                (
                    "region".to_string(),
                    std::collections::BTreeMap::from([(
                        "region_tag".to_string(),
                        "geo".to_string(),
                    )]),
                ),
            ]),
            policies,
            ..Default::default()
        },
    );
    EvalContext {
        catalog_facts: sink,
        function_resolver: Some(Arc::new(FixtureResolver)),
        ..Default::default()
    }
}

fn analyst() -> PrincipalIdentity {
    let mut p = PrincipalIdentity::new("User::\"alice\"");
    p.groups = vec!["analysts".to_string()];
    p
}

async fn run(sql: &str, principal: &PrincipalIdentity, eval: &EvalContext) -> Vec<RecordBatch> {
    let ctx = ctx().await;
    let plan = ctx.sql(sql).await.unwrap().into_unoptimized_plan();
    let engine = AbacPolicyEngine::new();
    let governed = govern_plan(&plan, &engine, principal, eval).await.unwrap();
    let optimized = ctx.state().optimize(&governed).unwrap();
    ctx.execute_logical_plan(optimized)
        .await
        .unwrap()
        .collect()
        .await
        .unwrap()
}

fn ssn_values(batches: &[RecordBatch]) -> Vec<String> {
    batches
        .iter()
        .flat_map(|b| {
            let col = b.column(b.schema().index_of("ssn").unwrap());
            let arr = col.as_any().downcast_ref::<StringArray>().unwrap();
            (0..arr.len())
                .map(|i| arr.value(i).to_string())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[tokio::test]
async fn matching_principal_gets_masked_and_filtered() {
    let eval = eval_for("both");
    let batches = run("SELECT id, region, ssn FROM t", &analyst(), &eval).await;
    let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    // Row filter keeps only region='eu' -> 1 row.
    assert_eq!(rows, 1, "row filter should keep only the eu row");
    // ssn is redacted.
    assert_eq!(ssn_values(&batches), vec!["REDACTED".to_string()]);
}

#[tokio::test]
async fn non_matching_principal_sees_raw_data() {
    // A principal not in `analysts` matches no binding.
    let eval = eval_for("both");
    let outsider = PrincipalIdentity::new("User::\"bob\"");
    let batches = run("SELECT id, region, ssn FROM t", &outsider, &eval).await;
    let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(rows, 2, "no filter applies; both rows visible");
    let mut ssns = ssn_values(&batches);
    ssns.sort();
    assert_eq!(ssns, vec!["AAA".to_string(), "BBB".to_string()]);
}

#[tokio::test]
async fn mask_only_leaves_all_rows_but_redacts_column() {
    let eval = eval_for("mask");
    let batches = run("SELECT id, region, ssn FROM t", &analyst(), &eval).await;
    let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(rows, 2, "no row filter -> all rows");
    assert_eq!(
        ssn_values(&batches),
        vec!["REDACTED".to_string(), "REDACTED".to_string()]
    );
}
