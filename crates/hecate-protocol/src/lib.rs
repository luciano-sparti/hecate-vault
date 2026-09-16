pub mod hsm {
    tonic::include_proto!("hecate.hsm");
}

pub mod policy {
    tonic::include_proto!("hecate.policy");
}

pub mod agent {
    tonic::include_proto!("hecate.agent");
}

pub mod admin {
    tonic::include_proto!("hecate.admin");
}

pub use admin::*;
pub use agent::*;
pub use hsm::*;
pub use policy::*;
