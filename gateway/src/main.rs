use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Deserialize)]
struct UserInput {
    username: String,
    password: String,
}

struct User {
    id: Uuid,
    username: String,
    password: String,
}

struct AppState {
    users: Mutex<Vec<User>>,
}

async fn signup(user_input: web::Form<UserInput>, data: web::Data<AppState>) -> impl Responder {
    let mut users = data.users.lock().unwrap();
    let id = uuid::Uuid::new_v4();
    users.push(User {
        id,
        username: user_input.username.clone(),
        password: user_input.password.clone(),
    });
    tracing::info!("user {} signed", id);
    HttpResponse::Found()
        .append_header(("LOCATION", "https://127.0.0.1:3000/login.html"))
        .finish()
}

async fn login(user_input: web::Form<UserInput>, data: web::Data<AppState>) -> impl Responder {
    let users = data.users.lock().unwrap();
    if let Some(user) = users
        .iter()
        .find(|user| user_input.username == user.username && user_input.password == user.password)
    {
        tracing::info!("user {} logged", user.id);
        HttpResponse::Found()
            .append_header(("LOCATION", "https://127.0.0.1:3000/orders.html"))
            .finish()
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let shared_data = web::Data::new(AppState {
        users: Mutex::new(Vec::new()),
    });
    let config = common::load_rustls_config();
    HttpServer::new(move || {
        App::new()
            .app_data(shared_data.clone())
            .wrap(Cors::default().allowed_origin("https://127.0.0.1:3000"))
            .route("/signup", web::post().to(signup))
            .route("/login", web::post().to(login))
            .wrap(Logger::default())
    })
    .bind_rustls_0_23(("127.0.0.1", 3001), config)?
    .run()
    .await
}
