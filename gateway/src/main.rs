use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use std::sync::Mutex;

#[derive(Debug, Deserialize)]
struct User {
    username: String,
    password: String,
}

struct AppState {
    users: Mutex<Vec<User>>,
}

async fn signup(user: web::Form<User>, data: web::Data<AppState>) -> impl Responder {
    dbg!(&user);
    let mut users = data.users.lock().unwrap();
    users.push(User {
        username: user.username.clone(),
        password: user.password.clone(),
    });
    dbg!(&users);
    HttpResponse::Ok().body("user registered successfully")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let shared_data = web::Data::new(AppState {
        users: Mutex::new(Vec::new()),
    });
    HttpServer::new(move || {
        App::new()
            .app_data(shared_data.clone())
            .route("/signup", web::post().to(signup))
    })
    .bind("127.0.0.1:3001")?
    .run()
    .await
}
