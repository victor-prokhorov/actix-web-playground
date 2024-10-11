// $ garage -c ./garage.toml status
// ==== HEALTHY NODES ====
// ID                Hostname  Address         Tags  Zone  Capacity   DataAvail
// f3f676a26fe56979  pop-os    127.0.0.1:3901  []    dc1   1000.0 MB  183.7 GB (37.2%)
//
// Key ID: GK098e34fb7f80e87921fc9b72
// Secret key: dd173761470b179f7354f513af0e699f460bb3d2e13647fe9fbe92e3b1ab8e99

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::result_large_err)]

use anyhow::Error;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::{
    config::{Credentials, Region},
    meta::PKG_VERSION,
    Client,
};
use clap::Parser;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
struct Opt {
    /// The AWS Region.
    #[structopt(short, long)]
    region: Option<String>,

    /// The name of the bucket.
    #[structopt(short, long)]
    bucket: String,

    /// The name of the file to upload.
    #[structopt(short, long)]
    filename: String,

    /// The name of the object in the bucket.
    #[structopt(short, long)]
    key: String,

    /// Whether to display additional information.
    #[structopt(short, long)]
    verbose: bool,
}

// Example for creating a bucket before uploading
async fn ensure_bucket_exists(client: &aws_sdk_s3::Client, bucket: &str) -> Result<(), Error> {
    match client.head_bucket().bucket(bucket).send().await {
        Ok(_) => {
            println!("Bucket '{}' exists", bucket);
        }
        Err(_) => {
            println!("Bucket '{}' does not exist, creating it", bucket);
            client.create_bucket().bucket(bucket).send().await?;
        }
    }
    Ok(())
}

// snippet-start:[s3.rust.s3-helloworld]
/// S3 Hello World Example using the AWS SDK for Rust.
///
/// This example lists the objects in a bucket, uploads an object to that bucket,
/// and then retrieves the object and prints some S3 information about the object.
/// This shows a number of S3 features, including how to use built-in paginators
/// for large data sets.
///
/// # Arguments
///
/// * `client` - an S3 client configured appropriately for the environment.
/// * `bucket` - the bucket name that the object will be uploaded to. Must be present in the region the `client` is configured to use.
/// * `filename` - a reference to a path that will be read and uploaded to S3.
/// * `key` - the string key that the object will be uploaded as inside the bucket.
async fn list_bucket_and_upload_object(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    filepath: &Path,
    key: &str,
) -> Result<(), Error> {
    ensure_bucket_exists(&client, &bucket).await?;

    // List the buckets in this account
    let mut objects = client
        .list_objects_v2()
        .bucket(bucket)
        .into_paginator()
        .send();
    let r = client.list_objects().bucket(bucket).send().await;
    dbg!(r);

    println!("key\tetag\tlast_modified\tstorage_class");
    while let Some(Ok(object)) = objects.next().await {
        for item in object.contents() {
            println!(
                "{}\t{}\t{}\t{}",
                item.key().unwrap_or_default(),
                item.e_tag().unwrap_or_default(),
                item.last_modified()
                    .map(|lm| format!("{lm}"))
                    .unwrap_or_default(),
                item.storage_class()
                    .map(|sc| format!("{sc}"))
                    .unwrap_or_default()
            );
        }
    }

    // Prepare a ByteStream around the file, and upload the object using that ByteStream.
    let body = aws_sdk_s3::primitives::ByteStream::from_path(filepath).await?;

    let resp = client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(body)
        .send()
        .await?;

    println!(
        "Upload success. Version: {:?}",
        resp.version_id()
            .expect("S3 Object upload missing version ID")
    );

    // Retrieve the just-uploaded object.
    let resp = client.get_object().bucket(bucket).key(key).send().await?;
    println!("etag: {}", resp.e_tag().unwrap_or("(missing)"));
    println!("version: {}", resp.version_id().unwrap_or("(missing)"));

    Ok(())
}
// snippet-end:[s3.rust.s3-helloworld]

/// Lists your buckets and uploads a file to a bucket.
/// # Arguments
///
/// * `-b BUCKET` - The bucket to which the file is uploaded.
/// * `-k KEY` - The name of the file to upload to the bucket.
/// * `[-r REGION]` - The Region in which the client is created.
///    If not supplied, uses the value of the **AWS_REGION** environment variable.
///    If the environment variable is not set, defaults to **us-west-2**.
/// * `[-v]` - Whether to display additional information.
#[tokio::main]
async fn main() -> Result<(), Error> {
    // tracing_subscriber::fmt::init();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let Opt {
        bucket,
        filename,
        key,
        region,
        verbose,
    } = Opt::parse();

    let filename = PathBuf::from(filename);
    if !filename.exists() {
        eprintln!("Cannot find {} for upload!", filename.display());
    }

    let region_provider = RegionProviderChain::first_try(region.map(Region::new))
        .or_default_provider()
        .or_else(Region::new("garage"));

    if verbose {
        println!("S3 client version: {}", PKG_VERSION);
        println!(
            "Region:            {}",
            region_provider.region().await.unwrap().as_ref()
        );
        println!("Bucket:            {}", &bucket);
        println!("Filename:          {:?}", &filename);
        println!("Key:               {}", &key);
        println!();
    }

    // let credentials = Credentials::new(
    //     "GK098e34fb7f80e87921fc9b72", // Key ID
    //     "dd173761470b179f7354f513af0e699f460bb3d2e13647fe9fbe92e3b1ab8e99", // Secret key
    //     None,                         // No session token
    //     None,                         // No expiration
    //     "custom-source",              // Source description (optional)
    // );

    let shared_config = aws_config::from_env()
        .endpoint_url("http://localhost:3900")
        .load()
        .await;
    let shared_config = Into::<aws_sdk_s3::config::Builder>::into(&shared_config)
        .force_path_style(true)
        .build();
    let s3_client = aws_sdk_s3::Client::from_conf(shared_config);

    // let shared_config = aws_config::from_env()
    //     .region(region_provider)
    //     .credentials_provider(credentials)
    //     .endpoint_url("http://localhost:3900")
    //     .load()
    //     .await;
    // let client = Client::new(&shared_config);

    list_bucket_and_upload_object(&s3_client, &bucket, &filename, &key).await
}
