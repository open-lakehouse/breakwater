//! The checked-in typed fixtures (`config/policies/lakehouse.*`) must stay valid:
//! the schema parses, the showcase policy set parses and validates against the
//! schema, and the sample entities load against the schema. This guards the
//! fixtures that back both the governance tests and the `fact_gathering_walkthrough`
//! example from silently rotting.

use std::str::FromStr;

use cedar_policy::{Entities, PolicySet, Schema, Validator};

const SCHEMA: &str = include_str!("../../../config/policies/lakehouse.cedarschema");
const POLICY: &str = include_str!("../../../config/policies/lakehouse.cedar");
const ENTITIES: &str = include_str!("../../../config/policies/lakehouse.entities.json");

fn schema() -> Schema {
    let (schema, _warnings) =
        Schema::from_cedarschema_str(SCHEMA).expect("lakehouse.cedarschema parses");
    schema
}

#[test]
fn schema_parses() {
    let _ = schema();
}

#[test]
fn policy_set_validates_against_schema() {
    let policies = PolicySet::from_str(POLICY).expect("lakehouse.cedar parses");
    let validator = Validator::new(schema());
    let result = validator.validate(&policies, cedar_policy::ValidationMode::default());
    assert!(
        result.validation_passed(),
        "lakehouse.cedar must validate against the schema: {:?}",
        result.validation_errors().collect::<Vec<_>>()
    );
}

#[test]
fn entities_load_against_schema() {
    let schema = schema();
    Entities::from_json_str(ENTITIES, Some(&schema))
        .expect("lakehouse.entities.json loads against the schema");
}
