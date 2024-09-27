use actix_cors::Cors;
use actix_web::{
    cookie::CookieBuilder, middleware::Logger, web, App, HttpRequest, HttpResponse, HttpServer,
    Responder,
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

#[derive(Serialize, Deserialize, Debug)]
struct Claims {
    sub: Uuid,
    exp: usize,
}

struct AppState {
    users: Mutex<Vec<User>>,
}

const SECRET_KEY: &[u8] = b"secret_key";
const REFRESH_SECRET_KEY: &[u8] = b"refresh_secret_key";
const ACCESS_TOKEN_EXPIRATION: usize = 60 * 2;
const REFRESH_TOKEN_EXPIRATION: usize = 60 * 60 * 24 * 7;

async fn signup(user_input: web::Form<UserInput>, data: web::Data<AppState>) -> impl Responder {
    tracing::info!("{user_input:?}");
    let mut users = data.users.lock().unwrap();
    let id = Uuid::new_v4();
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
        let expiration_time = unix_timestamp() + ACCESS_TOKEN_EXPIRATION;
        let access_token = generate_token(user.id, expiration_time, SECRET_KEY);
        let refresh_token_exp = unix_timestamp() + REFRESH_TOKEN_EXPIRATION;
        let refresh_token = generate_token(user.id, refresh_token_exp, REFRESH_SECRET_KEY);
        let access_cookie = CookieBuilder::new("access_token", access_token)
            .http_only(true)
            .secure(true)
            .finish();
        let refresh_cookie = CookieBuilder::new("refresh_token", refresh_token)
            .http_only(true)
            .secure(true)
            .finish();
        HttpResponse::Found()
            .cookie(access_cookie)
            .cookie(refresh_cookie)
            .append_header(("LOCATION", "https://127.0.0.1:3000/orders.html"))
            .finish()
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

fn token_is_expiring(claims: &Claims) -> bool {
    let time_left = claims.exp.saturating_sub(unix_timestamp());
    tracing::info!("access token expires in {} seconds", time_left,);
    // 10 seconds window
    time_left < 110
}

fn unix_timestamp() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("failed to get system time")
        .as_secs() as usize
}

fn generate_token(user_id: Uuid, expiration: usize, secret: &[u8]) -> String {
    let claims = Claims {
        sub: user_id,
        exp: expiration,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .unwrap()
}

async fn orders(req: HttpRequest) -> impl Responder {
    tracing::info!("{req:?}");
    let cookie = req.cookie("access_token");
    if let Some(cookie) = cookie {
        let access_token = cookie.value();
        let access_token_data = decode::<Claims>(
            access_token,
            &DecodingKey::from_secret(SECRET_KEY),
            &Validation::default(),
        );
        match access_token_data {
            Ok(token_data) => {
                tracing::info!("access token found for a user");
                if token_is_expiring(&token_data.claims) {
                    if let Some(refresh_cookie) = req.cookie("refresh_token") {
                        let refresh_token_data = decode::<Claims>(
                            refresh_cookie.value(),
                            &DecodingKey::from_secret(REFRESH_SECRET_KEY),
                            &Validation::default(),
                        );
                        if let Ok(refresh_data) = refresh_token_data {
                            let new_expiration_time = unix_timestamp() + ACCESS_TOKEN_EXPIRATION;
                            let new_access_token = generate_token(
                                refresh_data.claims.sub,
                                new_expiration_time,
                                SECRET_KEY,
                            );
                            let new_access_cookie =
                                CookieBuilder::new("access_token", new_access_token)
                                    .http_only(true)
                                    .secure(true)
                                    .finish();
                            tracing::info!("issued new access token");
                            return HttpResponse::Ok().cookie(new_access_cookie).body(format!(
                                r#""{} got his token refreshed""#,
                                refresh_data.claims.sub
                            ));
                        }
                    }
                }
                HttpResponse::Ok().body(format!(r#""{} have a token""#, token_data.claims.sub))
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
    let seed_user = User {
        id: Uuid::new_v4(),
        username: "tester".to_string(),
        password: "tester".to_string(),
    };
    let shared_data = web::Data::new(AppState {
        users: Mutex::new(vec![seed_user]),
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
