// src/jwt.rs
use jsonwebtoken::{encode, decode, Header, Algorithm, EncodingKey, DecodingKey, Validation, errors::Error};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // Subject (typically user ID)
    pub exp: usize,   // Expiration time (as UTC timestamp)
}

// Function to create a new token
pub fn create_token(user_id: &str, secret: &str, expiration: usize) -> Result<String, Error> {
    let claims = Claims {
        sub: user_id.to_string(),
        exp: expiration,
    };
    let header = Header::new(Algorithm::HS256);
    encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref()))
}

// Function to verify a token
pub fn verify_token(token: &str, secret: &str) -> Result<Claims, Error> {
    let validation = Validation::new(Algorithm::HS256);
    decode::<Claims>(token, &DecodingKey::from_secret(secret.as_ref()), &validation).map(|data| data.claims)
}
