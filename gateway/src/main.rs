use actix_cors::Cors;
use actix_web::{
    cookie::Cookie, middleware::Logger, web, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::{
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Deserialize, Debug)]
struct UserInput {
    username: String,
    password: String,
}

struct User {
    id: Uuid,
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: Uuid,
    exp: usize,
}

struct AppState {
    users: Mutex<Vec<User>>,
}

const SECRET_KEY: &[u8] = b"secret_key";

async fn signup(user_input: web::Form<UserInput>, data: web::Data<AppState>) -> impl Responder {
    tracing::info!("{user_input:?}");
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
    tracing::info!("{user_input:?}");
    let users = data.users.lock().unwrap();
    if let Some(user) = users
        .iter()
        .find(|user| user_input.username == user.username && user_input.password == user.password)
    {
        tracing::info!("user {} logged", user.id);
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize
            + 60 * 60;
        let claims = Claims {
            sub: user.id,
            exp: expiration,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(SECRET_KEY),
        )
        .unwrap();
        let cookie = Cookie::build("token", token)
            .http_only(true)
            .secure(true)
            .finish();
        HttpResponse::Found()
            .cookie(cookie)
            .append_header(("LOCATION", "https://127.0.0.1:3000/orders.html"))
            .finish()
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

async fn orders(req: HttpRequest) -> impl Responder {
    tracing::info!("{req:?}");
    let cookie = req.cookie("token");
    if let Some(cookie) = cookie {
        let token = cookie.value();
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(SECRET_KEY),
            &Validation::default(),
        );

        match token_data {
            Ok(token_data) => {
                HttpResponse::Ok().body(format!(r#""logged as {}""#, token_data.claims.sub))
            }
            Err(err) => {
                tracing::error!("{err:?}");
                HttpResponse::Unauthorized().finish()
            }
        }
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
            .wrap(
                Cors::default()
                    .allowed_origin("https://127.0.0.1:3000")
                    .allow_any_method()
                    .allow_any_header()
                    .supports_credentials()
                    .max_age(3600),
            )
            .route("/signup", web::post().to(signup))
            .route("/login", web::post().to(login))
            .route("/orders", web::get().to(orders))
            .wrap(Logger::default())
    })
    .bind_rustls_0_23(("127.0.0.1", 3001), config)?
    .run()
    .await
}
