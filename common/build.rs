use dotenv::dotenv;
use std::env;
use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();
    let pdir = PathBuf::from(env::var("PROTO_OUT_DIR")?);
    let pf = "proto/inventory.proto";
    tonic_build::configure()
        .build_server(true)
        .out_dir(pdir)
        .type_attribute("Product", "#[derive(serde::Deserialize, serde::Serialize)]")
        .type_attribute(
            "ProductStock",
            "#[derive(serde::Deserialize, serde::Serialize)]",
        )
        .compile_protos(&[pf], &["."])?;
    Ok(())
}
