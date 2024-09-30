// Inventory Service

use lapin::{options::*, types::FieldTable, Channel, Connection, ConnectionProperties};
use sqlx::PgPool;

struct InventoryService {
    channel: Channel,
    db_pool: PgPool,
}

impl InventoryService {
    async fn new(amqp_addr: &str, db_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let conn = Connection::connect(amqp_addr, ConnectionProperties::default()).await?;
        let channel = conn.create_channel().await?;
        let db_pool = PgPool::connect(db_url).await?;

        Ok(Self { channel, db_pool })
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.channel
            .queue_declare(
                "restock_complete",
                QueueDeclareOptions::default(),
                FieldTable::default(),
            )
            .await?;

        let mut consumer = self
            .channel
            .basic_consume(
                "restock_complete",
                "inventory_consumer",
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await?;

        while let Some(delivery) = consumer.next().await {
            if let Ok(delivery) = delivery {
                let item_id = String::from_utf8_lossy(&delivery.data);
                self.update_stock(&item_id).await?;
                self.channel
                    .basic_ack(delivery.delivery_tag, BasicAckOptions::default())
                    .await?;
            }
        }

        Ok(())
    }

    async fn update_stock(&self, item_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "UPDATE inventory SET stock = stock + 100 WHERE id = $1",
            item_id
        )
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }
}

// Restock Service

use lapin::{options::*, types::FieldTable, Channel, Connection, ConnectionProperties};

struct RestockService {
    channel: Channel,
}

impl RestockService {
    async fn new(amqp_addr: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let conn = Connection::connect(amqp_addr, ConnectionProperties::default()).await?;
        let channel = conn.create_channel().await?;
        Ok(Self { channel })
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.channel
            .queue_declare(
                "restock_request",
                QueueDeclareOptions::default(),
                FieldTable::default(),
            )
            .await?;

        let mut consumer = self
            .channel
            .basic_consume(
                "restock_request",
                "restock_consumer",
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await?;

        while let Some(delivery) = consumer.next().await {
            if let Ok(delivery) = delivery {
                let item_id = String::from_utf8_lossy(&delivery.data);
                self.process_restock(&item_id).await?;
                self.channel
                    .basic_ack(delivery.delivery_tag, BasicAckOptions::default())
                    .await?;
            }
        }

        Ok(())
    }

    async fn process_restock(&self, item_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Simulate long-living task
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        // Send completion message back to inventory service
        self.channel
            .basic_publish(
                "",
                "restock_complete",
                BasicPublishOptions::default(),
                item_id.as_bytes(),
                BasicProperties::default(),
            )
            .await?;

        Ok(())
    }
}
