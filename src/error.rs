use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Missing key ID field in JWT header")]
    MissingKid, // Heh :)

    #[error("Key ID in JWT header is not in the list of acceptable keys")]
    StrangeKid, // Heh :)

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("{0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Unknown error occurred")]
    Unknown,
}
