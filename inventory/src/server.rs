use common::inventory::inventory_service_server::{
    InventoryService, InventoryServiceServer, SERVICE_NAME,
};
use common::inventory::{
    GetStockRequest, GetStockResponse, ProductStock, UpdateStockRequest, UpdateStockResponse,
    UpdateStockResponseV2,
};
use dotenv::dotenv;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::env;
use tonic::{transport::Server, Request, Response, Status};
use tracing;
use uuid::Uuid;

pub struct InventoryServer {
    pool: PgPool,
}

#[tonic::async_trait]
impl InventoryService for InventoryServer {
    async fn update_stock_v2(
        &self,
        req: Request<UpdateStockRequest>,
    ) -> Result<Response<UpdateStockResponseV2>, Status> {
        let update_stock_request = req.into_inner();
        let remaining_quantity = sqlx::query_scalar!(
            "UPDATE product_stock
            SET available_quantity = available_quantity - 1
            WHERE product_id = $1
            RETURNING available_quantity",
            Uuid::parse_str(&update_stock_request.product_id).unwrap(),
        )
        .fetch_one(&self.pool)
        .await
        .expect("failed to fetch all stocks");
        let why_not_ten = 10;
        if remaining_quantity > why_not_ten {
            Ok(Response::new(UpdateStockResponseV2 {
                success: true,
                remaining_quantity,
            }))
        } else {
            Ok(Response::new(UpdateStockResponseV2 {
                success: false,
                remaining_quantity,
            }))
        }
    }
    async fn update_stock(
        &self,
        req: Request<UpdateStockRequest>,
    ) -> Result<Response<UpdateStockResponse>, Status> {
        let update_stock_request = req.into_inner();
        let quantity_remaining = sqlx::query_scalar!(
            "UPDATE product_stock
            SET available_quantity = available_quantity - 1
            WHERE product_id = $1
            RETURNING available_quantity",
            Uuid::parse_str(&update_stock_request.product_id).unwrap(),
        )
        .fetch_one(&self.pool)
        .await
        .expect("failed to fetch all stocks");
        let why_not_ten = 10;
        if quantity_remaining > why_not_ten {
            Ok(Response::new(UpdateStockResponse { success: true }))
        } else {
            Ok(Response::new(UpdateStockResponse { success: false }))
        }
    }
    async fn get_stock(
        &self,
        req: Request<GetStockRequest>,
    ) -> Result<Response<GetStockResponse>, Status> {
        let ids: Vec<Uuid> = req
            .into_inner()
            .product_ids
            .into_iter()
            .map(|id| Uuid::parse_str(&id).expect("internal service did not provided valid uuid"))
            .collect();
        tracing::info!("received {ids:?}");
        let stocks = sqlx::query_as!(
            ProductStock,
            "SELECT available_quantity, product_id FROM product_stock WHERE product_id = ANY($1)",
            &ids
        )
        .fetch_all(&self.pool)
        .await
        .expect("failed to fetch all stocks");
        tracing::info!("found {stocks:?}");
        Ok(Response::new(GetStockResponse { stocks }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    tracing::info!("{} init", SERVICE_NAME);
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
    tracing::info!(
        "i need one for grpcurl\n{}\n",
        req.metadata()
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap()
    );
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
