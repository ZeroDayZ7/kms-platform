fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("PROTOC").is_none() {
        let protoc_path = protoc_bin_vendored::protoc_bin_path()?;
        unsafe {
            std::env::set_var("PROTOC", protoc_path);
        }
    }

    let proto_files = &[
        "proto/spire/common/plugin/plugin.proto",
        "proto/spire/config/v1/config.proto",
        "proto/spire/service/private/init/v1/init.proto",
        "proto/spire/server/upstreamauthority/v1/upstreamauthority.proto",
        "proto/plugin/grpc_controller.proto",
        "proto/plugin/grpc_stdio.proto",
        "proto/plugin/grpc_broker.proto",
    ];

    tonic_build::configure()
        .build_server(true)
        .compile_protos(proto_files, &["proto"])?;

    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
