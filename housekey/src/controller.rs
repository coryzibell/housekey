use std::collections::HashMap;
use std::path::PathBuf;

use thiserror::Error;

use crate::discovery::DiscoveredAccessory;

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("not paired with accessory {0}")]
    NotPaired(String),
    #[error("already paired with accessory {0}")]
    AlreadyPaired(String),
    #[error("pairing store error: {0}")]
    StoreError(String),
    #[error(transparent)]
    Discovery(#[from] crate::discovery::DiscoveryError),
    #[error(transparent)]
    Pairing(#[from] crate::pairing::PairingError),
    #[error(transparent)]
    Accessory(#[from] crate::accessory::AccessoryError),
    #[error(transparent)]
    Transport(#[from] crate::transport::TransportError),
}

pub struct Controller {
    store_path: PathBuf,
    paired_devices: HashMap<String, PairedDevice>,
}

struct PairedDevice {
    accessory_id: String,
    accessory_ltpk: [u8; 32],
    controller_ltsk: [u8; 32],
    controller_ltpk: [u8; 32],
}

impl Controller {
    pub fn new(store_path: PathBuf) -> Self {
        Self {
            store_path,
            paired_devices: HashMap::new(),
        }
    }

    pub async fn discover(&self) -> Result<Vec<DiscoveredAccessory>, ControllerError> {
        todo!()
    }

    pub async fn pair(
        &mut self,
        accessory: &DiscoveredAccessory,
        pin: &str,
    ) -> Result<(), ControllerError> {
        todo!()
    }

    pub async fn unpair(&mut self, accessory_id: &str) -> Result<(), ControllerError> {
        todo!()
    }
}
