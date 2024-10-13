use futures::StreamExt;
use lapin::{options::*, types::FieldTable, BasicProperties, Connection, ConnectionProperties};
use std::fmt::Display;
use std::thread;
use std::time::Duration;

#[derive(Debug)]
enum Error {
    MissingReplyTo,
    MissingCorrelationId,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::MissingReplyTo => write!(f, "Missing 'reply to' property"),
            Error::MissingCorrelationId => write!(f, "Missing 'correlation id' property"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "amqp://127.0.0.1:5672";
    let conn = Connection::connect(addr, ConnectionProperties::default()).await?;
    let channel = conn.create_channel().await?;
    channel
        .queue_declare(
            "restock_queue",
            QueueDeclareOptions::default(),
            FieldTable::default(),
        )
        .await?;
    channel.basic_qos(1, BasicQosOptions::default()).await?;
    let mut consumer = channel
        .basic_consume(
            "restock_queue",
            "rpc_server",
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await?;

    println!(" [x] Awaiting RPC requests");

    while let Some(delivery) = consumer.next().await {
        if let Ok(delivery) = delivery {
            for done in 0..=10 {
                println!("{}% done, working... thread sleep btw", done * 10);
                thread::sleep(Duration::from_secs(1));
            }
            let payload = common::RestockResponse {
                id: uuid::Uuid::parse_str("06fdd1be-5d59-41c2-8bcf-70bf279e83a3")?,
                restocked_amount: 10,
            };
            let serialized_payload = serde_json::to_vec(&payload)?;

            let routing_key = delivery
                .properties
                .reply_to()
                .as_ref()
                .ok_or(Error::MissingReplyTo)?
                .as_str();

            let correlation_id = delivery
                .properties
                .correlation_id()
                .clone()
                .ok_or(Error::MissingCorrelationId)?;

            channel
                .basic_publish(
                    "",
                    routing_key,
                    BasicPublishOptions::default(),
                    &serialized_payload,
                    BasicProperties::default().with_correlation_id(correlation_id),
                )
                .await?;

            channel
                .basic_ack(delivery.delivery_tag, BasicAckOptions::default())
                .await?;
        }
    }

    Ok(())
}
