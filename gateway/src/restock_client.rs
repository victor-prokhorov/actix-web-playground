use futures::StreamExt;
use lapin::{
    options::*, types::FieldTable, types::ShortString, BasicProperties, Channel, Connection,
    ConnectionProperties, Consumer, Queue,
};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt::Display;
use std::sync::Arc;
use tokio::runtime::Handle;
use uuid::Uuid;

#[derive(Debug)]
enum Error {
    CannotDecodeReply,
    NoReply,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::CannotDecodeReply => write!(f, "Cannot decode reply"),
            Error::NoReply => write!(f, "No reply arrived"),
        }
    }
}

#[derive(Debug)]
pub struct FibonacciRpcClient {
    conn: Arc<Connection>,
    channel: Channel,
    callback_queue: Queue,
    consumer: Consumer,
    correlation_id: ShortString,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct MyPayload {
    id: u32,
    message: String,
}

impl FibonacciRpcClient {
    pub async fn new() -> Result<Self, lapin::Error> {
        let addr = "amqp://127.0.0.1:5672";
        let conn = Connection::connect(addr, ConnectionProperties::default()).await?;
        let channel = conn.create_channel().await?;
        let callback_queue = channel
            .queue_declare(
                "",
                QueueDeclareOptions {
                    exclusive: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await?;

        let consumer = channel
            .basic_consume(
                callback_queue.name().as_str(),
                "restock_client",
                BasicConsumeOptions {
                    no_ack: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await?;

        let correlation_id = Uuid::new_v4().to_string().into();

        Ok(Self {
            conn: Arc::new(conn),
            channel,
            callback_queue,
            consumer,
            correlation_id,
        })
    }

    pub async fn call(&mut self, n: u64) -> Result<MyPayload, Box<dyn std::error::Error>> {
        self.channel
            .basic_publish(
                "",
                "restock_queue",
                BasicPublishOptions::default(),
                &*n.to_le_bytes().to_vec(),
                BasicProperties::default()
                    .with_reply_to(self.callback_queue.name().clone())
                    .with_correlation_id(self.correlation_id.clone()),
            )
            .await?
            .await?;
        tracing::info!("published to restock queue");
        while let Some(delivery) = self.consumer.next().await {
            if let Ok(delivery) = delivery {
                if delivery.properties.correlation_id().as_ref() == Some(&self.correlation_id) {
                    // Deserialize the payload
                    let payload: MyPayload = serde_json::from_slice(&delivery.data)
                        .map_err(|_| "Failed to deserialize payload")?;
                    return Ok(payload);
                    // return Ok(u64::from_le_bytes(
                    //     delivery
                    //         .data
                    //         .as_slice()
                    //         .try_into()
                    //         .map_err(|_| Error::CannotDecodeReply)?,
                    // ));
                }
            }
        }

        Err(Box::new(Error::NoReply))
    }

    // async fn close(&self) -> Result<(), lapin::Error> {
    //     // well since i can't call this directly i move the client struct to `app_data`
    //     // thus i will have to do gracefull shutdown in a separate task
    //     self.conn.close(0, "").await
    // }
}

impl Drop for FibonacciRpcClient {
    fn drop(&mut self) {
        let conn = self.conn.clone();
        if let Ok(handle) = Handle::try_current() {
            // task that will drive the cleanup
            // because drop cannot be async!
            handle.spawn(async move {
                if let Err(e) = conn.close(0, "").await {
                    tracing::error!("gracefull shutdown failed: {e}");
                } else {
                    tracing::info!("all resources where cleaned");
                }
            });
        } else {
            tracing::error!("no rt");
        }
    }
}
