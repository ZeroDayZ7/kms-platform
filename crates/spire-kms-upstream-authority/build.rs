fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().build_server(true).compile_protos(
        &[
            "proto/spire/common/plugin/plugin.proto",
            "proto/spire/service/private/init/v1/init.proto",
            "proto/spire/server/upstreamauthority/v1/upstreamauthority.proto",
        ],
        &["proto"],
    )?;

    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
