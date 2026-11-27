# OPA inputs replayed against the OPA route

Request bodies as Unity Catalog's OPA authorizers send them to
`POST …/v1/data/uc/authz`, replayed by `src/opa_tests.rs`. The expected
decision of each is in that test's table, together with the grants it sets up.

## `uc-java/`: UC Java 0.8, `unitycatalog/unitycatalog` at `f59e83d3`

- `select-table.json` is the body that `OpaAuthorizerTest.java:166-173`
  asserts, with concrete UUIDs in its `%s` slots: alice
  (`external_id` `subject-123`) asking for `SELECT` on `analytics.reports.orders`.
- The others vary the privilege and the securable, in exactly the shapes that
  `OpaInputBuilderTest.java` asserts for each type (`OpaInputBuilder.java:36-137`):
  - `principal` is `{id, email, external_id?}`;
  - `privilege` is `Privileges.name()` (`USE_CATALOG`);
  - `type` is the `SecurableType` constant;
  - `name` is the leaf name, and `parents` are nearest-first with no metastore;
  - the metastore has no `name`;
  - external locations and credentials have no parents;
  - there is no `context`.
- `select-table-bob.json` is a user without an `external_id`.

## `unitycatalog-rs/`: `open-lakehouse/unitycatalog-rs` `main`

`crates/uc-server/src/authz/opa.rs`, blob `babc31f`.

- `select-table.json` is the input that `builds_upstreams_input_with_ours_on_top`
  expects (`opa.rs:195-241`), wrapped in `{"input": …}` as
  `uc-auth/src/authz/opa.rs:102` posts it.
- `create-catalog-metastore.json` is that test's metastore resource
  (`opa.rs:243-245`).
- `owner-table-bob.json` and `use-catalog-server-token.json` vary the
  principal and the context. The second carries every context key the server
  sets (`AuthContext::for_identity` plus `auth_layer`'s `request_time` and
  `source_ip`) for a `server-token` caller with `groups: []`, as
  `uc-server/tests/opa.rs:212-237` asserts.
