# Azure AD B2C Token Validation Library

This is a small Rust library to aid in validating OAuth access tokens issued
by Azure AD B2C.

Here's an example of how you might use this library to validate a token.

```rust
#[derive(Deserialize, Debug, Clone)]
pub struct Claims {
    #[serde(rename = "iss")]
    pub issuer: String,

    #[serde(rename = "aud")]
    pub audience: String,

    #[serde(rename = "oid")]
    pub object_id: String,

    #[serde(rename = "sub")]
    pub subject: String,

    #[serde(rename = "tfp")]
    pub policy_name: String,

    #[serde(rename = "scp")]
    pub scopes: String,

    pub given_name: String,
    pub family_name: String,
    pub name: String,
}

async fn check_token(token: &str) -> Result<Claims, Error> {
    let aad = AzureAd::new(
        "AAD tenant name",
        "AAD B2C policy/user flow name",
        Some(vec!["App ID1", "App ID2"]), // list of App IDs we should look for in
                                          // the token's 'aud' claim
    )
    .await?

    match aad.validate_access_token(token)? {
        ValidationResult::Valid(claims) => Ok(claims),
        ValidationResult::NeedKeyRefresh => {
            aad.refresh_validation_keys().await.ok()?;
            aad.validate_access_token(token)?
              .ok()
              .ok_or(Error::from("Unknown key id in JWT token"))
        }
    }
}
```
