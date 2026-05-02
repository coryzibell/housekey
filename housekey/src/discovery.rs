use std::collections::HashMap;
use std::net::IpAddr;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("mDNS browse failed: {0}")]
    BrowseFailed(String),
    #[error("accessory not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Clone)]
pub struct DiscoveredAccessory {
    pub name: String,
    pub id: String,
    pub addr: IpAddr,
    pub port: u16,
    pub model: String,
    pub state_number: u8,
    pub feature_flags: u8,
    pub status_flags: u8,
    pub category: AccessoryCategory,
    pub txt_records: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AccessoryCategory {
    Other = 1,
    Bridge = 2,
    Fan = 3,
    GarageDoorOpener = 4,
    Lightbulb = 5,
    DoorLock = 6,
    Outlet = 7,
    Switch = 8,
    Thermostat = 9,
    Sensor = 10,
    SecuritySystem = 11,
    Door = 12,
    Window = 13,
    WindowCovering = 14,
    ProgrammableSwitch = 15,
    IpCamera = 17,
    VideoDoorbell = 18,
    AirPurifier = 19,
    Heater = 20,
    AirConditioner = 21,
    Humidifier = 22,
    Dehumidifier = 23,
    Sprinkler = 28,
    Faucet = 29,
    ShowerSystem = 30,
    Router = 32,
}

impl AccessoryCategory {
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::Other,
            2 => Self::Bridge,
            3 => Self::Fan,
            4 => Self::GarageDoorOpener,
            5 => Self::Lightbulb,
            6 => Self::DoorLock,
            7 => Self::Outlet,
            8 => Self::Switch,
            9 => Self::Thermostat,
            10 => Self::Sensor,
            11 => Self::SecuritySystem,
            12 => Self::Door,
            13 => Self::Window,
            14 => Self::WindowCovering,
            15 => Self::ProgrammableSwitch,
            17 => Self::IpCamera,
            18 => Self::VideoDoorbell,
            19 => Self::AirPurifier,
            20 => Self::Heater,
            21 => Self::AirConditioner,
            22 => Self::Humidifier,
            23 => Self::Dehumidifier,
            28 => Self::Sprinkler,
            29 => Self::Faucet,
            30 => Self::ShowerSystem,
            32 => Self::Router,
            _ => Self::Other,
        }
    }
}
