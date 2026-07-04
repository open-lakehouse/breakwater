//! Fetch policies from OCI registries.
use std::{fmt::Debug, str::FromStr, sync::Arc};

use cedar_local_agent::public::{
    EntityProviderError, PolicySetProviderError, SimpleEntityProvider, SimplePolicySetProvider,
};
use cedar_policy::{Entities, PolicySet, Request, Schema};
use oci_client::{
    Client, Reference,
    client::{ClientConfig, ClientProtocol},
    secrets::RegistryAuth,
};
use tokio::sync::RwLock;
use tracing::instrument;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CedarOciMediaTypes {
    PolicySet,
    Schema,
    Entities,
}

impl AsRef<str> for CedarOciMediaTypes {
    fn as_ref(&self) -> &str {
        match self {
            CedarOciMediaTypes::PolicySet => "application/vnd.cedar.policyset.v1",
            CedarOciMediaTypes::Schema => "application/vnd.cedar.schema.v1",
            CedarOciMediaTypes::Entities => "application/vnd.cedar.entities.v1",
        }
    }
}

pub fn build_client_config() -> ClientConfig {
    let protocol = ClientProtocol::Http;

    ClientConfig {
        protocol,
        ..Default::default()
    }
}

pub struct OciPolicyProvider {
    /// OCI client retained for re-fetching the policy image (the `RwLock` fields
    /// below are built for reload); not read after the initial pull yet.
    #[allow(dead_code)]
    client: Client,
    reference: Reference,
    entities: RwLock<Arc<Entities>>,
    policy_set: RwLock<Arc<PolicySet>>,
    /// The Cedar schema pulled alongside the policy set, if the image carried
    /// one. Retained for schema-aware authorization and fine-grained governance
    /// (residual evaluation validates resource attributes against it).
    schema: RwLock<Option<Arc<Schema>>>,
}

impl Debug for OciPolicyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OciPolicyProvider")
            .field("reference", &self.reference)
            .finish()
    }
}

impl OciPolicyProvider {
    #[instrument(skip(client), err(Debug))]
    pub async fn try_new(
        client: Client,
        reference: Reference,
    ) -> Result<Self, EntityProviderError> {
        let accepted_media_types = vec![
            CedarOciMediaTypes::PolicySet.as_ref(),
            CedarOciMediaTypes::Schema.as_ref(),
            CedarOciMediaTypes::Entities.as_ref(),
        ];

        let image = client
            .pull(&reference, &RegistryAuth::Anonymous, accepted_media_types)
            .await
            .map_err(|e| EntityProviderError::General(e.into()))?;

        let mut schema = None;
        let mut entities_raw = vec![];
        let mut policy_sets_raw = vec![];
        for layer in image.layers {
            if layer.media_type.as_str() == CedarOciMediaTypes::Schema.as_ref() {
                if schema.is_some() {
                    return Err(EntityProviderError::General(
                        "Multiple schema layers found".to_string().into(),
                    ));
                }
                let schema_raw = String::from_utf8(layer.data.to_vec())
                    .map_err(|e| EntityProviderError::General(e.into()))?;
                schema = Some(
                    Schema::from_str(&schema_raw)
                        .map_err(|e| EntityProviderError::General(e.into()))?,
                );
            } else if layer.media_type.as_str() == CedarOciMediaTypes::Entities.as_ref() {
                entities_raw.push(
                    String::from_utf8(layer.data.to_vec())
                        .map_err(|e| EntityProviderError::General(e.into()))?,
                );
            } else if layer.media_type.as_str() == CedarOciMediaTypes::PolicySet.as_ref() {
                policy_sets_raw.push(
                    String::from_utf8(layer.data.to_vec())
                        .map_err(|e| EntityProviderError::General(e.into()))?,
                );
            }
        }

        let mut entities = Entities::empty();
        for entity_str in entities_raw {
            entities = entities
                .add_entities_from_json_str(&entity_str, schema.as_ref())
                .map_err(|e| EntityProviderError::General(e.into()))?;
        }

        let mut policy_set = PolicySet::new();
        for policy_str in policy_sets_raw {
            let new_set = PolicySet::from_str(&policy_str)
                .map_err(|e| EntityProviderError::General(e.into()))?;
            policy_set
                .merge(&new_set, false)
                .map_err(|e| EntityProviderError::General(e.into()))?;
        }

        Ok(Self {
            client,
            reference,
            entities: RwLock::new(Arc::new(entities)),
            policy_set: RwLock::new(Arc::new(policy_set)),
            schema: RwLock::new(schema.map(Arc::new)),
        })
    }

    /// Build a provider from an OCI reference string (e.g.
    /// `localhost:10100/hydrofoil/plan-policy:latest`), using the default
    /// (anonymous, HTTP) client configuration.
    pub async fn from_reference(reference: &str) -> Result<Self, EntityProviderError> {
        let client = Client::new(build_client_config());
        let reference: Reference = reference
            .parse()
            .map_err(|e: oci_client::ParseError| EntityProviderError::General(e.into()))?;
        Self::try_new(client, reference).await
    }

    /// The Cedar schema pulled with the policy image, if any.
    pub async fn schema(&self) -> Option<Arc<Schema>> {
        self.schema.read().await.clone()
    }
}

#[async_trait::async_trait]
impl SimpleEntityProvider for OciPolicyProvider {
    #[instrument(skip_all, err(Debug))]
    async fn get_entities(&self, _: &Request) -> Result<Arc<Entities>, EntityProviderError> {
        Ok(self.entities.read().await.clone())
    }
}

#[async_trait::async_trait]
impl SimplePolicySetProvider for OciPolicyProvider {
    #[instrument(skip_all, err(Debug))]
    async fn get_policy_set(&self, _: &Request) -> Result<Arc<PolicySet>, PolicySetProviderError> {
        Ok(self.policy_set.read().await.clone())
    }
}

#[cfg(test)]
mod tests {

    use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};
    use cedar_policy::{Context, EntityId, EntityTypeName, EntityUid};

    use super::*;

    // Live integration test: pulls a policy image from a local OCI registry
    // (zot) on :10100. Ignored by default (run with `cargo test -- --ignored`
    // after `just push_policy`) so the unit suite / CI stays green without the
    // registry. Doubles as the end-to-end check for the OCI policy load path.
    #[ignore = "requires a local zot OCI registry on :10100 with a pushed policy image"]
    #[tokio::test]
    async fn test_fetch_policy() {
        let client_config = build_client_config();
        let client = Client::new(client_config);
        let reference: Reference = "localhost:10100/hydrofoil/plan-policy:latest"
            .parse()
            .unwrap();

        let provider = Arc::new(OciPolicyProvider::try_new(client, reference).await.unwrap());
        // The plan-policy image ships a Cedar schema layer; confirm we retained it.
        assert!(
            provider.schema().await.is_some(),
            "expected the pulled policy image to carry a Cedar schema"
        );
        let authorizer = Authorizer::new(
            AuthorizerConfigBuilder::default()
                .policy_set_provider(provider.clone())
                .entity_provider(provider)
                .build()
                .unwrap(),
        );

        let user_type_name = EntityTypeName::from_str("User").unwrap();
        let action_type_name = EntityTypeName::from_str("Action").unwrap();
        let table_type_name = EntityTypeName::from_str("Table").unwrap();

        let principal = EntityUid::from_type_name_and_id(user_type_name, EntityId::new("alice"));
        let action =
            EntityUid::from_type_name_and_id(action_type_name, EntityId::new("read_table"));
        let resource =
            EntityUid::from_type_name_and_id(table_type_name, EntityId::new("protected_table"));

        let request = Request::new(principal, action, resource, Context::empty(), None).unwrap();

        let decision = authorizer
            .is_authorized(&request, &Entities::empty())
            .await
            .unwrap();

        println!("Decision: {:?}", decision);
    }
}
