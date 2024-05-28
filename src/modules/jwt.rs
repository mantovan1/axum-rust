use chrono::Utc;
use jsonwebtoken::{decode, encode, Validation, Header, DecodingKey, EncodingKey};
use crate::schemas::{
    user::User,
    claims::Claims
};

pub async fn generate_jwt(user: &User, role_names: &Vec<String>) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims {
        sub: user.email.clone(),
        roles: role_names.clone(),
        iss: "issuer".to_string(),
        exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
    };

    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret("secret".as_ref()))?;
    Ok(token)
}