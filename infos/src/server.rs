use hello_world::greeter_server::{Greeter, GreeterServer};
use hello_world::{HelloReply, HelloRequest};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use tonic::metadata::MetadataValue;
use tonic::{transport::Server, Request, Response, Status};
use uuid::Uuid;

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

#[derive(Debug, Default)]
pub struct MyGreeter {}

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        println!("Got a request: {:?}", request);

        let reply = HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };

        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let greeter = MyGreeter::default();
    Server::builder()
        .add_service(GreeterServer::with_interceptor(greeter, check_auth))
        .serve(addr)
        .await?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize,
    sub: Uuid,
}

use dotenv::dotenv;
use std::env;

fn check_auth(req: Request<()>) -> Result<Request<()>, Status> {
    dotenv().ok();
    let access_token = match req.metadata().get("authorization") {
        Some(t) => match t.to_str() {
            Ok(s) => s,
            _ => {
                return Err(Status::unauthenticated(
                    "failed to get a str from metadata value while parsing",
                ))
            }
        },
        _ => return Err(Status::unauthenticated("no authorizatoin at all")),
    };
    let access_token_data = decode::<Claims>(
        access_token,
        &DecodingKey::from_secret(
            &env::var("ACCESS_TOKEN_SECRET")
                .expect("set ACEESS_TOKEN_SECRET")
                .bytes()
                .collect::<Vec<_>>(),
        ),
        &Validation::default(),
    );
    match access_token_data {
        Err(e) => Err(Status::unauthenticated(format!(
            "failed to decode i guess: {e:?}"
        ))),
        Ok(_token_data) => Ok(req),
    }
}
