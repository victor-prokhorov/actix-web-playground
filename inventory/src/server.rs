use dotenv::dotenv;
// use hello_world::greeter_server::{Greeter, GreeterServer};
// use hello_world::{HelloReply, HelloRequest};
use common::inventory::inventory_service_server::{
    InventoryService, InventoryServiceServer, SERVICE_NAME,
};
use common::inventory::{
    GetStockRequest, GetStockResponse, Product, ProductStock, UpdateStockRequest,
    UpdateStockResponse,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::env;
use tonic::{transport::Server, Request, Response, Status};
use uuid::Uuid;

// pub mod hello_world {
//     tonic::include_proto!("helloworld");
// }
//
pub struct InventoryServer {
    pool: PgPool,
}

#[tonic::async_trait]
impl InventoryService for InventoryServer {
    async fn update_stock(
        &self,
        _req: Request<UpdateStockRequest>,
    ) -> Result<Response<UpdateStockResponse>, Status> {
        todo!()
    }
    async fn get_stock(
        &self,
        _req: Request<GetStockRequest>,
    ) -> Result<Response<GetStockResponse>, Status> {
        todo!()
    }
    // async fn say_hello(
    //     &self,
    //     request: Request<HelloRequest>,
    // ) -> Result<Response<HelloReply>, Status> {
    //     println!("Got a request: {:?}", request);
    //     let reply = HelloReply {
    //         message: format!("Hello {}!", request.into_inner().name),
    //     };
    //     let r = sqlx::query!("SELECT 1 as x").fetch_one(&self.pool).await;
    //     dbg!(r);
    //     Ok(Response::new(reply))
    // }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let addr = "[::1]:50051".parse()?;
    let database_url = env::var("DATABASE_URL").unwrap();
    let pool = PgPool::connect(&database_url).await.unwrap();
    let r = sqlx::query!("SELECT 1 AS ok_check").fetch_one(&pool).await;
    assert!(
        r.is_ok_and(|x| x.ok_check.is_some_and(|x| x == 1)),
        "make sure you spawned db"
    );
    let inventory_server = InventoryServer { pool };
    Server::builder()
        .add_service(InventoryServiceServer::with_interceptor(
            inventory_server,
            check_auth,
        ))
        .serve(addr)
        .await?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize,
    sub: Uuid,
}

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
