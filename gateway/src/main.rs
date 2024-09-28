use actix_cors::Cors;
use actix_web::{
    body::MessageBody,
    cookie::{time::OffsetDateTime, Cookie, CookieBuilder},
    dev::{ServiceRequest, ServiceResponse},
    http::header::LOCATION,
    middleware::{from_fn, Logger, Next},
    rt,
    web::{self, Data},
    App, HttpRequest, HttpResponse, HttpServer, Responder, ResponseError,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use core::fmt;
use futures_util::StreamExt;
use hello_world::greeter_client::GreeterClient;
use hello_world::HelloRequest;
use jsonwebtoken::{
    decode, encode, errors::ErrorKind, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgListener, FromRow, PgPool};
use std::{
    env,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tonic::Request;
use tracing::instrument;
use uuid::Uuid;

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

// #[tokio::main]
async fn not_main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = GreeterClient::connect("http://[::1]:50051").await?;

    let request = tonic::Request::new(HelloRequest {
        name: "Tonic".into(),
    });

    let response = client.say_hello(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}

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

#[derive(Debug)]
struct AppData {
    pool: PgPool,
    access_token_secret: Vec<u8>,
    refresh_token_secret: Vec<u8>,
}

const ACCESS_TOKEN_EXPIRATION: usize = 60 * 2;
const REFRESH_TOKEN_EXPIRATION: usize = 60 * 60 * 24 * 7;
/// Should be half (or less) of the acceptable client timeout.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// How long before lack of client response causes a timeout.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

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
        .append_header((LOCATION, "https://127.0.0.1:3000/login.html"))
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
                    .append_header((LOCATION, "https://127.0.0.1:3000/orders.html"))
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
        // TODO:
        // i just found `add_removal_cookie` method i guess it's more readable then hand written
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

#[instrument]
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
    user_id: Option<Uuid>,
    content: Option<String>,
}

#[derive(FromRow, Deserialize, Serialize, Debug, Clone)]
struct Order {
    id: Uuid,
    user_id: Option<Uuid>,
    content: Option<String>,
}

#[tracing::instrument]
async fn post_order(
    app_data: web::Data<AppData>,
    order_input: web::Json<OrderInput>,
) -> Result<HttpResponse, Error> {
    let order_id = sqlx::query_as!(
        OrderId,
        "INSERT INTO orders(id, user_id, content) VALUES($1, $2, $3) RETURNING id",
        Uuid::new_v4(),
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

#[instrument(
    skip(app_data),
    fields(content = ?order_update_input.content, user_id = ?order_update_input.user_id, id = ?id)
)]
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

async fn get_orders(app_data: web::Data<AppData>) -> Result<HttpResponse, Error> {
    let orders: Vec<Order> = sqlx::query_as!(Order, "SELECT id, user_id, content FROM orders")
        .fetch_all(&app_data.pool)
        .await
        .map_err(|err| Error::Db(err.into()))?;

    // TODO: init client once store in app_state i guess
    let mut client = GreeterClient::connect("http://[::1]:50051")
        .await
        .map_err(|e| Error::Grpc(e.into()))?;
    let request = Request::new(HelloRequest {
        name: "Tonic".into(),
    });
    let response = client
        .say_hello(request)
        .await
        .map_err(|e| Error::Grpc(e.into()))?;
    tracing::info!("RESPONSE={:?}", response);

    Ok(HttpResponse::Ok().json(orders))
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
    Auth(GenericError),
    Grpc(GenericError),
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
            Error::Auth(internal) => {
                tracing::error!("{internal:?}");
                HttpResponse::Unauthorized().finish()
            }
            Error::Grpc(internal) => {
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
                    .wrap(from_fn(auth_middleware))
                    .route("/", web::get().to(get_orders))
                    .route("/", web::post().to(post_order))
                    .route("/{id}", web::get().to(get_order))
                    .route("/{id}", web::put().to(put_order))
                    .route("/{id}", web::delete().to(delete_order)),
            )
            .service(
                web::resource("/ws")
                    .route(web::get().to(orders_ws))
                    .wrap(from_fn(auth_middleware)),
            )
            .route("/logout", web::get().to(logout))
            .wrap(Logger::default())
    })
    .workers(1)
    .bind_rustls_0_23(("127.0.0.1", 3001), config)?
    .run()
    .await
}

async fn orders_ws(
    req: HttpRequest,
    stream: web::Payload,
    app_data: web::Data<AppData>,
) -> Result<HttpResponse, actix_web::Error> {
    // do not await!
    let (res, mut session, mut msg_stream) = actix_ws::handle(&req, stream)?;
    let app_data = app_data.clone();
    let pool = &app_data.pool;
    let mut listener = PgListener::connect_with(pool).await.unwrap();
    listener.listen("orders").await.unwrap();
    tracing::info!("started listening to orders");
    rt::spawn(async move {
        let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
        let mut last_heartbeat = Instant::now();
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if Instant::now().duration_since(last_heartbeat) > CLIENT_TIMEOUT {
                        tracing::info!("timed out");
                        break;
                    }
                    if let Err(err) = session.ping(b"ping").await {
                        tracing::error!("{err:?}");
                        break;
                    }
                }
                Some(msg) = msg_stream.next() => {
                    match msg {
                        Ok(actix_ws::Message::Ping(ping)) => {
                            tracing::info!("received ping from client");
                            if let Err(err) = session.pong(&ping).await {
                                tracing::error!("{err:?}");
                                break;
                            }
                        }
                        Ok(actix_ws::Message::Pong(_)) => {
                            tracing::info!("received pong from client");
                            last_heartbeat = Instant::now();
                        }
                        Ok(actix_ws::Message::Text(text)) => {
                            tracing::info!("text: {}", text);
                        }
                        Ok(actix_ws::Message::Close(reason)) => {
                            tracing::info!("closed: {:?}", reason);
                            break;
                        }
                        Err(err) => {
                            tracing::error!("error: {err:?}");
                            break;
                        }
                        _ => {}
                    }
                },
                Ok(notification) = listener.recv() => {
                    let message = notification.payload().to_string();
                    tracing::info!("pg notified: {}", message);
                    if let Err(err) = session.text(message).await {
                        tracing::error!("failed to send message to client: {err:?}");
                        break;
                    }
                },
                else => {
                    tracing::error!("else");
                    break;
                }
            }
        }
        tracing::info!("session closed");
    });
    Ok(res)
}

#[instrument(skip(next))]
pub async fn auth_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    let app_data: Data<AppData> = req
        .app_data()
        .cloned()
        .expect("failed to exctract app state");
    let access_cookie = req.cookie("access_token");
    let refresh_cookie = req.cookie("refresh_token");
    let mut response = next.call(req).await?;
    if let Some(cookie) = access_cookie {
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
                        refresh_cookie,
                        &app_data.refresh_token_secret,
                        &app_data.access_token_secret,
                    )?;
                    tracing::info!("issued new access token");
                    response.response_mut().add_cookie(&new_access_cookie)?;
                    return Ok(response);
                }
                tracing::info!("found valid existing token");
                Ok(response)
            }
            Err(err) => match err.kind() {
                ErrorKind::ExpiredSignature => {
                    let new_access_cookie = try_access_cookie_from_refresh_token(
                        refresh_cookie,
                        &app_data.refresh_token_secret,
                        &app_data.access_token_secret,
                    )?;
                    tracing::info!("issued new access token after expied signature");
                    response.response_mut().add_cookie(&new_access_cookie)?;
                    return Ok(response);
                }
                _ => Err(Error::Auth(err.into()).into()),
            },
        }
    } else {
        Err(Error::Auth("anonymous user without a cookie".into()).into())
    }
}
