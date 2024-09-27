use actix_cors::Cors;
use actix_web::{
    cookie::{time::OffsetDateTime, Cookie, CookieBuilder},
    middleware::Logger,
    web, App, HttpRequest, HttpResponse, HttpServer, Responder, ResponseError,
};
use core::fmt;
use jsonwebtoken::{
    decode, encode, errors::ErrorKind, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::{
    env,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Deserialize, Debug)]
struct UserInput {
    username: String,
    password: String,
}

#[derive(Debug)]
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
    pool: PgPool,
}

const SECRET_KEY: &[u8] = b"secret_key";
const REFRESH_SECRET_KEY: &[u8] = b"refresh_secret_key";
const ACCESS_TOKEN_EXPIRATION: usize = 60 * 2;
const REFRESH_TOKEN_EXPIRATION: usize = 60 * 60 * 24 * 7;

async fn signup(user_input: web::Form<UserInput>, data: web::Data<AppState>) -> impl Responder {
    tracing::info!("{user_input:?}");
    get_users(&data.pool).await;
    let mut users = data.users.lock().unwrap();
    let id = Uuid::new_v4();
    users.push(User {
        id,
        username: user_input.username.clone(),
        password: user_input.password.clone(),
    });
    tracing::info!("user {} signed", id);
    HttpResponse::SeeOther()
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
        HttpResponse::SeeOther()
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

async fn logout() -> impl Responder {
    tracing::info!("logout");
    let now = OffsetDateTime::now_utc();
    let access_cookie = CookieBuilder::new("access_token", "")
        .http_only(true)
        .secure(true)
        .expires(Some(now))
        .finish();
    let refresh_cookie = CookieBuilder::new("refresh_token", "")
        .http_only(true)
        .secure(true)
        .expires(Some(now))
        .finish();
    // client side redirect here
    HttpResponse::Ok()
        .cookie(access_cookie)
        .cookie(refresh_cookie)
        .finish()
}

async fn orders(req: HttpRequest) -> Result<HttpResponse, Error> {
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
                    tracing::info!("access token is expiring");
                    let new_access_cookie =
                        try_access_cookie_from_refresh_token(req.cookie("refresh_token"))?;
                    tracing::info!("issued new access token");
                    return Ok(HttpResponse::Ok()
                        .cookie(new_access_cookie)
                        .body(format!(r#""token refreshed""#)));
                }
                Ok(HttpResponse::Ok().body(format!(r#""found a valid token""#)))
            }
            Err(err) => match err.kind() {
                ErrorKind::ExpiredSignature => {
                    let new_access_cookie =
                        try_access_cookie_from_refresh_token(req.cookie("refresh_token"))?;
                    tracing::info!("issued new access token after expied signature");
                    return Ok(HttpResponse::Ok()
                        .cookie(new_access_cookie)
                        .body(format!(r#""token refreshed after expired signature""#,)));
                }
                _ => {
                    tracing::error!("{err:?}");
                    Ok(HttpResponse::Unauthorized().finish())
                }
            },
        }
    } else {
        Ok(HttpResponse::Unauthorized().finish())
    }
}

async fn get_users(pool: &PgPool) {
    let users = sqlx::query_as!(User, "SELECT * FROM users")
        .fetch_all(pool)
        .await
        .expect("failed to query db");
    tracing::info!("{users:?}");
}

#[derive(Debug)]
enum Error {
    NoRefreshToken,
    NoRefreshData,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self)
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        match *self {
            Error::NoRefreshToken => {
                HttpResponse::Unauthorized().body(r#""didn't found refresh token""#)
            }
            Error::NoRefreshData => HttpResponse::Unauthorized().body(r#""invalid refresh data""#),
        }
    }
}

fn try_access_cookie_from_refresh_token(cookie: Option<Cookie>) -> Result<Cookie, Error> {
    if let Some(refresh_cookie) = cookie {
        let refresh_token_data = decode::<Claims>(
            refresh_cookie.value(),
            &DecodingKey::from_secret(REFRESH_SECRET_KEY),
            &Validation::default(),
        );
        if let Ok(refresh_data) = refresh_token_data {
            let new_expiration_time = unix_timestamp() + ACCESS_TOKEN_EXPIRATION;
            let new_access_token =
                generate_token(refresh_data.claims.sub, new_expiration_time, SECRET_KEY);
            let new_access_cookie = CookieBuilder::new("access_token", new_access_token)
                .http_only(true)
                .secure(true)
                .finish();
            Ok(new_access_cookie)
        } else {
            Err(Error::NoRefreshData)
        }
    } else {
        Err(Error::NoRefreshToken)
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    dotenv::dotenv().ok();
    let seed_user = User {
        id: Uuid::new_v4(),
        username: "tester".to_string(),
        password: "tester".to_string(),
    };
    let config = common::load_rustls_config();
    let database_url = env::var("DATABASE_URL").expect("make sure DATABASE_URL is set");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("failed to create a connection pool to db");
    let shared_data = web::Data::new(AppState {
        users: Mutex::new(vec![seed_user]),
        pool,
    });
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
            .route("/logout", web::get().to(logout))
            .wrap(Logger::default())
    })
    .workers(1)
    .bind_rustls_0_23(("127.0.0.1", 3001), config)?
    .run()
    .await
}
