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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_token() {
        let user_id = "test_user";
        let secret = "test_secret";
        let expiration = 10000000000; // Example expiration timestamp
        let token = create_token(user_id, secret, expiration);
        assert!(token.is_ok());
    }

    #[test]
    fn test_verify_token() {
        let user_id = "test_user";
        let secret = "test_secret";
        let expiration = 10000000000; // Example expiration timestamp
        let token = create_token(user_id, secret, expiration).unwrap();

        let result = verify_token(&token, secret);
        assert!(result.is_ok());

        let claims = result.unwrap();
        assert_eq!(claims.sub, user_id);
    }

    #[test]
    fn test_verify_token_invalid() {
        let invalid_token = "invalid_token";
        let secret = "test_secret";
        let result = verify_token(invalid_token, secret);
        assert!(result.is_err());
    }
}
