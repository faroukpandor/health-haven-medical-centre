// src/main.rs

use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use serde::Deserialize;
use std::env;
use dotenv::dotenv;

mod jwt; // Assuming you have a `jwt.rs` module for JWT functions

#[derive(Deserialize)]
struct LoginInfo {
    user_id: String,
}

// Endpoint to log in and create a JWT token
async fn login(info: web::Json<LoginInfo>) -> impl Responder {
    // Retrieve the JWT secret from environment variables
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "default_secret".to_string());
    let expiration = 10000; // Set expiration time (in seconds)

    match jwt::create_token(&info.user_id, &secret, expiration) {
        Ok(token) => HttpResponse::Ok().json(token), // Return the token as JSON
        Err(_) => HttpResponse::InternalServerError().finish(), // Handle error
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables from the .env file
    dotenv().ok();

    // Initialize the server
    HttpServer::new(|| {
        App::new()
            .route("/login", web::post().to(login)) // Define the login route
    })
    .bind("127.0.0.1:8080")? // Bind to the address and port
    .run()
    .await
}
