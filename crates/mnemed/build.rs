fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use a vendored `protoc` unless the environment already provides one, so the
    // build never depends on a system protobuf-compiler (CI e2e-daemon runners and
    // fresh local checkouts both lack it). tonic-build/prost-build honor the
    // `PROTOC` env var. `set_var` is `unsafe` in edition 2024; the build script is
    // single-threaded at this point, so this is sound.
    if std::env::var_os("PROTOC").is_none() {
        if let Ok(path) = protoc_bin_vendored::protoc_bin_path() {
            unsafe {
                std::env::set_var("PROTOC", path);
            }
        }
    }
    tonic_build::compile_protos("proto/mneme.proto")?;
    Ok(())
}
