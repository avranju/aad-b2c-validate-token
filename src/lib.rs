#![warn(missing_debug_implementations, unsafe_code)]
#![deny(rust_2018_idioms, warnings)]

use std::{collections::HashMap, fmt::Debug, time::Instant};

use error::Error;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{de::DeserializeOwned, Deserialize};

pub mod error;

/// How often should we refresh validation keys from Azure AD B2C?
const KEYS_REFRESH_FREQUENCY_SECONDS: u64 = 60 * 60 * 8;

#[derive(Debug)]
pub enum ValidationResult<T> {
    Valid(T),
    NeedKeyRefresh,
}

impl<T> ValidationResult<T> {
    pub fn ok(self) -> Option<T> {
        match self {
            ValidationResult::Valid(t) => Some(t),
            ValidationResult::NeedKeyRefresh => None,
        }
    }
}

#[derive(Clone)]
pub struct AzureAd {
    tenant_name: String,
    policy_name: String,
    keys: HashMap<String, DecodingKey>,
    last_key_refresh_time: Instant,
    validation: Validation,
}

impl Debug for AzureAd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureAd")
            .field("tenant_name", &self.tenant_name)
            .field("policy_name", &self.policy_name)
            .field("keys", &self.keys.keys())
            .field("last_key_refresh_time", &self.last_key_refresh_time)
            .field("validation", &self.validation)
            .finish()
    }
}

impl AzureAd {
    pub async fn new(
        tenant_name: String,
        policy_name: String,
        app_ids: Option<Vec<String>>,
    ) -> Result<Self, Error> {
        // initalize list of acceptable keys
        let (issuer, keys) = refresh_keys(&tenant_name, &policy_name).await?;

        // initialize validation params
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["iss", "sub", "exp", "nbf", "aud"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        if let Some(app_ids) = app_ids {
            validation.set_audience(&app_ids);
        }
        if let Some(issuer) = issuer {
            validation.set_issuer(&[issuer]);
        }

        Ok(Self {
            tenant_name,
            policy_name,
            keys,
            validation,
            last_key_refresh_time: Instant::now(),
        })
    }

    pub async fn refresh_validation_keys(&mut self) -> Result<(), Error> {
        // if we tried refreshing keys too recently then fail
        if self.last_key_refresh_time.elapsed().as_secs() < KEYS_REFRESH_FREQUENCY_SECONDS {
            return Err(Error::StrangeKid);
        }

        let (issuer, keys) = refresh_keys(&self.tenant_name, &self.policy_name).await?;
        self.keys = keys;
        if let Some(issuer) = issuer {
            self.validation.set_issuer(&[issuer]);
        }
        self.last_key_refresh_time = Instant::now();

        Ok(())
    }

    pub fn validate_access_token<T: DeserializeOwned + Debug>(
        &self,
        access_token: &str,
    ) -> Result<ValidationResult<T>, Error> {
        // decode header and locate the public key from oid metadata
        let header = decode_header(access_token)?;
        let key_id = header.kid.ok_or(Error::MissingKid)?;

        Ok(self
            .keys
            .get(&key_id)
            .map(|key| decode(access_token, key, &self.validation))
            .transpose()?
            .map(|v| ValidationResult::Valid(v.claims))
            .unwrap_or(ValidationResult::NeedKeyRefresh))
    }
}

async fn refresh_keys(
    tenant_name: &str,
    policy_name: &str,
) -> Result<(Option<String>, HashMap<String, DecodingKey>), Error> {
    // fetch oid metadata
    let metadata_uri = format!(
        "https://{}.b2clogin.com/{}.onmicrosoft.com/{}/v2.0/.well-known/openid-configuration",
        tenant_name, tenant_name, policy_name
    );
    let oid_metadata = reqwest::get(&metadata_uri)
        .await?
        .json::<OidMetadata>()
        .await?;

    let keys_metadata = reqwest::get(&oid_metadata.jwks_uri)
        .await?
        .json::<KeysMetadata>()
        .await?;

    Ok((
        oid_metadata.issuer,
        keys_metadata
            .keys
            .into_iter()
            .map(|key| {
                Ok((
                    key.key_id,
                    DecodingKey::from_rsa_components(&key.rsa_modulus, &key.rsa_exponent)?,
                ))
            })
            .collect::<Result<_, Error>>()?,
    ))
}

#[derive(Deserialize, Debug, Clone)]
pub struct OidMetadata {
    issuer: Option<String>,
    jwks_uri: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct KeysMetadata {
    keys: Vec<KeyMetadata>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct KeyMetadata {
    #[serde(rename = "kid")]
    key_id: String,

    #[serde(rename = "n")]
    rsa_modulus: String,

    #[serde(rename = "e")]
    rsa_exponent: String,
}
