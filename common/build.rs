use dotenv::dotenv;
use std::env;
use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();
    let pdir = PathBuf::from(env::var("PROTO_OUT_DIR")?);
    let invetory = "proto/inventory.proto";
    let image = "proto/image.proto";
    tonic_build::configure()
        .build_server(true)
        .out_dir(pdir)
        .type_attribute("Product", "#[derive(serde::Deserialize, serde::Serialize)]")
        .type_attribute(
            "ProductStock",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .compile_protos(&[invetory, image], &["."])?;
    Ok(())
}
