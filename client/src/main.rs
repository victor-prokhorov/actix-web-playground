use actix_files::{Files, NamedFile};
use actix_web::{middleware::Logger, web, App, HttpServer, Responder};

async fn index() -> impl Responder {
    NamedFile::open_async("./static/ws/index.html")
        .await
        .unwrap()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let config = common::load_rustls_config();
    HttpServer::new(|| {
        App::new()
            .service(Files::new("/", "./static/").index_file("index.html"))
            .service(web::resource("/ws").to(index))
            .wrap(Logger::default())
    })
    .workers(1)
    .bind_rustls_0_23(("127.0.0.1", 3000), config)?
    .run()
    .await
}
