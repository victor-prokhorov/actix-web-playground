use actix_cors::Cors;
use actix_web::{
    cookie::{time::OffsetDateTime, Cookie, CookieBuilder},
    middleware::Logger,
    web, App, HttpRequest, HttpResponse, HttpServer, Responder, ResponseError,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use core::fmt;
use jsonwebtoken::{
    decode, encode, errors::ErrorKind, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use std::{
    env,
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

struct AppData {
    pool: PgPool,
    access_token_secret: Vec<u8>,
    refresh_token_secret: Vec<u8>,
}

const ACCESS_TOKEN_EXPIRATION: usize = 60 * 2;
const REFRESH_TOKEN_EXPIRATION: usize = 60 * 60 * 24 * 7;

async fn signup(
    user_input: web::Form<UserInput>,
    app_data: web::Data<AppData>,
) -> Result<HttpResponse, Error> {
    let id = Uuid::new_v4();
    let password = hash(user_input.password.clone(), DEFAULT_COST)
        .map_err(|err| Error::ImpossibleToAddUser(err.into()))?;
    let user = User {
        id,
        username: user_input.username.clone(),
        password,
    };
    try_insert_new_user(&app_data.pool, user).await?;
    Ok(HttpResponse::SeeOther()
        .append_header(("LOCATION", "https://127.0.0.1:3000/login.html"))
        .finish())
}

async fn try_insert_new_user(pool: &PgPool, user: User) -> Result<(), Error> {
    match sqlx::query!(
        "INSERT INTO users(id, username, password) VALUES($1, $2, $3)",
        user.id,
        user.username,
        user.password,
    )
    .execute(pool)
    .await
    {
        Err(err) => {
            if let Some(dberr) = err.as_database_error() {
                if let Some(constraint) = dberr.constraint() {
                    if constraint == "users_username_key" {
                        return Err(Error::UserWithSameNameExists);
                    }
                }
            }
            Err(Error::ImpossibleToAddUser(err.into()))
        }
        Ok(query_result) => {
            tracing::info!("{query_result:?}");
            Ok(())
        }
    }
}

async fn login(
    user_input: web::Form<UserInput>,
    app_data: web::Data<AppData>,
) -> Result<HttpResponse, Error> {
    let user_input = user_input.into_inner();
    let user = find_user_by_username(&app_data.pool, &user_input).await?;
    match verify(&user_input.password, &user.password) {
        // the error is for the bcrypt itself
        Err(err) => Err(Error::UserNotFound(err.into())),
        Ok(matched) => {
            if matched {
                let expiration_time = unix_timestamp() + ACCESS_TOKEN_EXPIRATION;
                let access_token =
                    generate_token(user.id, expiration_time, &app_data.access_token_secret);
                let refresh_token_exp = unix_timestamp() + REFRESH_TOKEN_EXPIRATION;
                let refresh_token =
                    generate_token(user.id, refresh_token_exp, &app_data.refresh_token_secret);
                let access_cookie = CookieBuilder::new("access_token", access_token)
                    .http_only(true)
                    .secure(true)
                    .finish();
                let refresh_cookie = CookieBuilder::new("refresh_token", refresh_token)
                    .http_only(true)
                    .secure(true)
                    .finish();
                Ok(HttpResponse::SeeOther()
                    .cookie(access_cookie)
                    .cookie(refresh_cookie)
                    .append_header(("LOCATION", "https://127.0.0.1:3000/orders.html"))
                    .finish())
            } else {
                Err(Error::UserNotFound("password didn't matched".into()))
            }
        }
    }
}

async fn find_user_by_username(pool: &PgPool, user_input: &UserInput) -> Result<User, Error> {
    Ok(sqlx::query_as!(
        User,
        "SELECT username, password, id FROM users WHERE username = $1",
        user_input.username,
    )
    .fetch_one(pool)
    .await
    .map_err(|err| Error::UserNotFound(err.into()))?)
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

#[derive(FromRow, Deserialize, Serialize, Debug, Clone)]
struct OrderContent {
    content: Option<String>,
}

async fn get_order(
    id: web::Path<Uuid>,
    app_data: web::Data<AppData>,
) -> Result<HttpResponse, Error> {
    let order: OrderContent = sqlx::query_as!(
        OrderContent,
        "SELECT content FROM orders WHERE id = $1",
        id.into_inner()
    )
    .fetch_one(&app_data.pool)
    .await
    .map_err(|err| Error::Db(err.into()))?;
    Ok(HttpResponse::Ok().json(order))
}

#[derive(FromRow, Deserialize, Serialize, Debug, Clone)]
struct OrderId {
    id: Uuid,
}

#[derive(FromRow, Deserialize, Serialize, Debug, Clone)]
struct OrderInput {
    id: Uuid,
    user_id: Option<Uuid>,
    content: Option<String>,
}

async fn post_order(
    app_data: web::Data<AppData>,
    order_input: web::Json<OrderInput>,
) -> Result<HttpResponse, Error> {
    let order_id: OrderId = sqlx::query_as!(
        OrderId,
        "INSERT INTO orders(id, user_id, content) VALUES($1, $2, $3) RETURNING id",
        order_input.id,
        order_input.user_id,
        order_input.content,
    )
    .fetch_one(&app_data.pool)
    .await
    .map_err(|err| Error::Db(err.into()))?;
    Ok(HttpResponse::Ok().json(order_id))
}

#[derive(FromRow, Deserialize, Serialize, Debug, Clone)]
struct OrderUpdateInput {
    content: Option<String>,
    user_id: Option<Uuid>,
}

async fn put_order(
    id: web::Path<Uuid>,
    app_data: web::Data<AppData>,
    order_update_input: web::Json<OrderUpdateInput>,
) -> Result<HttpResponse, Error> {
    sqlx::query!(
        "UPDATE orders SET content = $1, user_id = $2 WHERE id = $3",
        order_update_input.content,
        order_update_input.user_id,
        id.into_inner()
    )
    .execute(&app_data.pool)
    .await
    .map_err(|err| Error::Db(err.into()))?;
    Ok(HttpResponse::Ok().finish())
}

async fn delete_order(
    id: web::Path<Uuid>,
    app_data: web::Data<AppData>,
) -> Result<HttpResponse, Error> {
    sqlx::query!("DELETE FROM orders WHERE id = $1", id.into_inner())
        .execute(&app_data.pool)
        .await
        .map_err(|err| Error::Db(err.into()))?;
    Ok(HttpResponse::Ok().finish())
}

async fn get_orders(req: HttpRequest, app_data: web::Data<AppData>) -> Result<HttpResponse, Error> {
    let cookie = req.cookie("access_token");
    if let Some(cookie) = cookie {
        let access_token = cookie.value();
        let access_token_data = decode::<Claims>(
            access_token,
            &DecodingKey::from_secret(&app_data.access_token_secret),
            &Validation::default(),
        );
        match access_token_data {
            Ok(token_data) => {
                tracing::info!("access token found for a user");
                if token_is_expiring(&token_data.claims) {
                    tracing::info!("access token is expiring");
                    let new_access_cookie = try_access_cookie_from_refresh_token(
                        req.cookie("refresh_token"),
                        &app_data.refresh_token_secret,
                        &app_data.access_token_secret,
                    )?;
                    tracing::info!("issued new access token");
                    return Ok(HttpResponse::Ok()
                        .cookie(new_access_cookie)
                        .body(format!(r#""token refreshed""#)));
                }
                Ok(HttpResponse::Ok().body(format!(r#""found a valid token""#)))
            }
            Err(err) => match err.kind() {
                ErrorKind::ExpiredSignature => {
                    let new_access_cookie = try_access_cookie_from_refresh_token(
                        req.cookie("refresh_token"),
                        &app_data.refresh_token_secret,
                        &app_data.access_token_secret,
                    )?;
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

type GenericError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
enum Error {
    NoRefreshToken,
    NoRefreshData,
    ImpossibleToAddUser(GenericError),
    UserWithSameNameExists,
    UserNotFound(GenericError),
    Db(GenericError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self)
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        match self {
            Error::NoRefreshToken => {
                HttpResponse::Unauthorized().body(r#""didn't found refresh token""#)
            }
            Error::NoRefreshData => HttpResponse::Unauthorized().body(r#""invalid refresh data""#),
            Error::ImpossibleToAddUser(internal) => {
                tracing::error!("{internal:?}");
                HttpResponse::BadRequest().json(r#""try again""#)
            }
            Error::UserWithSameNameExists => {
                HttpResponse::BadRequest().json(r#""try different name""#)
            }
            Error::UserNotFound(internal) => {
                tracing::error!("{internal:?}");
                HttpResponse::Unauthorized().finish()
            }
            Error::Db(internal) => {
                tracing::error!("{internal:?}");
                HttpResponse::InternalServerError().finish()
            }
        }
    }
}

fn try_access_cookie_from_refresh_token<'refresh, 'access, 'cookie>(
    cookie: Option<Cookie>,
    refresh_token_secret: &'refresh [u8],
    access_token_secret: &'access [u8],
) -> Result<Cookie<'cookie>, Error> {
    if let Some(refresh_cookie) = cookie {
        let refresh_token_data = decode::<Claims>(
            refresh_cookie.value(),
            &DecodingKey::from_secret(refresh_token_secret),
            &Validation::default(),
        );
        if let Ok(refresh_data) = refresh_token_data {
            let new_expiration_time = unix_timestamp() + ACCESS_TOKEN_EXPIRATION;
            let new_access_token = generate_token(
                refresh_data.claims.sub,
                new_expiration_time,
                access_token_secret,
            );
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
    let config = common::load_rustls_config();
    let database_url = env::var("DATABASE_URL").expect("make sure DATABASE_URL is set");
    let access_token_secret = env::var("ACCESS_TOKEN_SECRET")
        .expect("ACCESS_TOKEN_SECRET not set")
        .bytes()
        .collect();
    let refresh_token_secret = env::var("REFRESH_TOKEN_SECRET")
        .expect("REFRESH_TOKEN_SECRET not set")
        .bytes()
        .collect();
    let pool = PgPool::connect(&database_url)
        .await
        .expect("failed to create a connection pool to db");
    let app_data = web::Data::new(AppData {
        pool,
        access_token_secret,
        refresh_token_secret,
    });
    HttpServer::new(move || {
        App::new()
            .app_data(app_data.clone())
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
            .service(
                web::scope("/orders")
                    .route("/", web::get().to(get_orders))
                    .route("/", web::post().to(post_order))
                    .route("/{id}", web::get().to(get_order))
                    .route("/{id}", web::put().to(put_order))
                    .route("/{id}", web::delete().to(delete_order)),
            )
            .route("/logout", web::get().to(logout))
            .wrap(Logger::default())
    })
    .workers(1)
    .bind_rustls_0_23(("127.0.0.1", 3001), config)?
    .run()
    .await
}
