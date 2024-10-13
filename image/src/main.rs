use anyhow::Error;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::{config::Region, meta::PKG_VERSION, Client};
use clap::Parser;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use tracing::trace;

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

/// https://docs.aws.amazon.com/sdk-for-rust/latest/dg/rust_s3_code_examples.html
async fn get_object(client: Client, bucket: &str, key: &str) -> Result<usize, anyhow::Error> {
    let mut file = std::fs::File::create("./dl-this-test.txt")?;
    let mut object = client.get_object().bucket(bucket).key(key).send().await?;
    let mut byte_count = 0_usize;
    while let Some(bytes) = object.body.try_next().await? {
        let bytes_len = bytes.len();
        file.write_all(&bytes)?;
        trace!("Intermediate write of {bytes_len}");
        byte_count += bytes_len;
    }
    Ok(byte_count)
}

/// # Arguments
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
    let mut objects = client
        .list_objects_v2()
        .bucket(bucket)
        .into_paginator()
        .send();
    // let r = client.list_objects().bucket(bucket).send().await;
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
    // let body = aws_sdk_s3::primitives::ByteStream::from_path(filepath).await?;
    // let resp = client
    //     .put_object()
    //     .bucket(bucket)
    //     .key(key)
    //     .body(body)
    //     .send()
    //     .await?;

    // println!(
    //     "Upload success. Version: {:?}",
    //     resp.version_id()
    //         .expect("S3 Object upload missing version ID")
    // );
    // let resp = client.get_object().bucket(bucket).key(key).send().await?;
    // println!("etag: {}", resp.e_tag().unwrap_or("(missing)"));
    // println!("version: {}", resp.version_id().unwrap_or("(missing)"));
    Ok(())
}

/// Lists your buckets and uploads a file to a bucket.
/// # Arguments
///
/// * `-b BUCKET` - The bucket to which the file is uploaded.
/// * `-k KEY` - The name of the file to upload to the bucket.
/// * `[-r REGION]` - The Region in which the client is created.
///    If not supplied, uses the value of the **AWS_REGION** environment variable.
///    If the environment variable is not set, defaults to **us-west-2**.
/// * `[-v]` - Whether to display additional information.
// #[tokio::main]
/// `cargo watch -q -x 'r -- --bucket image-bucket --filename ./solid-grey.jpg --key solid-grey.jpg'`
async fn not_main() -> Result<(), Error> {
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
    let shared_config = aws_config::from_env()
        .endpoint_url("http://localhost:3900")
        .load()
        .await;
    let shared_config = Into::<aws_sdk_s3::config::Builder>::into(&shared_config)
        .force_path_style(true)
        .build();
    let s3_client = aws_sdk_s3::Client::from_conf(shared_config);
    list_bucket_and_upload_object(&s3_client, &bucket, &filename, &key).await?;
    get_object(s3_client, &bucket, &key).await?;
    Ok(())
}

use aws_sdk_s3::operation::create_multipart_upload::CreateMultipartUploadOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::CompletedMultipartUpload;
use aws_sdk_s3::types::CompletedPart;
use common::image_service::image_service_server::*;
use common::image_service::{FileChunk, UploadStatus};
use futures::StreamExt;
use tonic::{transport::Server, Request, Response, Status};

#[derive(Default)]
pub struct Service;

#[tonic::async_trait]
impl ImageService for Service {
    async fn upload_image(
        &self,
        request: Request<tonic::Streaming<FileChunk>>,
    ) -> Result<Response<UploadStatus>, Status> {
        println!("request to upload image received starting to process");
        let bucket_name = "image-bucket";
        let key = uuid::Uuid::new_v4().to_string();
        let shared_config = aws_config::from_env()
            .endpoint_url("http://localhost:3900")
            .load()
            .await;
        let shared_config = Into::<aws_sdk_s3::config::Builder>::into(&shared_config)
            .force_path_style(true)
            .build();
        let client = aws_sdk_s3::Client::from_conf(shared_config);
        println!("client created");

        // check if the client is actually working
        list_bucket_and_upload_object(&client, &bucket_name, &PathBuf::from(""), &key)
            .await
            .map_err(|e| Status::internal(format!("failed to read bucket: {}", e)))?;

        let multipart_upload_res: CreateMultipartUploadOutput = client
            .create_multipart_upload()
            .bucket(bucket_name)
            .key(key.clone())
            .send()
            .await
            .map_err(|e| Status::internal(format!("failed to create multipart upload: {}", e)))?;
        let upload_id = multipart_upload_res.upload_id().ok_or(Status::internal(
            "missing upload_id after CreateMultipartUpload",
        ))?;
        let mut upload_parts: Vec<CompletedPart> = Vec::new();
        let mut chunk_index = 0;
        let mut stream = request.into_inner();
        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|e| Status::internal(format!("failed to read chunk: {}", e)))?;
            println!("received chunk of size: {}", chunk.content.len());
            let stream = ByteStream::from(chunk.content.clone());
            let part_number = chunk_index + 1;
            let upload_part_res = client
                .upload_part()
                .bucket(bucket_name)
                .key(key.clone())
                .upload_id(upload_id.to_string())
                .part_number(part_number)
                .body(stream)
                .send()
                .await
                .map_err(|e| Status::internal(format!("failed to upload part: {}", e)))?;
            upload_parts.push(
                CompletedPart::builder()
                    .e_tag(upload_part_res.e_tag.unwrap_or_default())
                    .part_number(part_number)
                    .build(),
            );
            chunk_index += 1;
            println!("chunk index: {chunk_index}");
        }
        let completed_multipart_upload: CompletedMultipartUpload =
            CompletedMultipartUpload::builder()
                .set_parts(Some(upload_parts))
                .build();
        client
            .complete_multipart_upload()
            .bucket(bucket_name)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(completed_multipart_upload)
            .send()
            .await
            .map_err(|e| Status::internal(format!("failed to complete multipart upload: {}", e)))?;
        println!("end of the reponse");
        Ok(Response::new(UploadStatus { success: true }))
    }
}

/// make sure to source .awsrc ! errors this would generate are not super clear
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50052".parse()?;
    let image_service = Service::default();
    Server::builder()
        .add_service(ImageServiceServer::new(image_service))
        .serve(addr)
        .await?;
    Ok(())
}
