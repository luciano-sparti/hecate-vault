fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(
            &[
                "proto/hsm.proto",
                "proto/policy.proto",
                "proto/agent.proto",
                "proto/admin.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
