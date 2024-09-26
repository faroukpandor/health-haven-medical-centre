use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use serde::Deserialize;
use std::env;
use dotenv::dotenv;

mod jwt;

#[derive(Deserialize)]
struct LoginInfo {
    user_id: String,
}

async fn login(info: web::Json<LoginInfo>) -> impl Responder {
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "default_secret".to_string());
    let expiration = 10000;

    match jwt::create_token(&info.user_id, &secret, expiration) {
        Ok(token) => HttpResponse::Ok().json(token),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    HttpServer::new(|| {
        App::new()
            .route("/login", web::post().to(login))
    })
    .bind("0.0.0.0:8080")?  // Changed here
    .run()
    .await
}
