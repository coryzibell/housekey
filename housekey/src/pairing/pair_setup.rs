use super::PairingError;

pub struct PairSetup {
    pin: String,
}

impl PairSetup {
    pub fn new(pin: &str) -> Result<Self, PairingError> {
        if !is_valid_pin(pin) {
            return Err(PairingError::InvalidPin);
        }
        Ok(Self {
            pin: pin.to_string(),
        })
    }
}

fn is_valid_pin(pin: &str) -> bool {
    let digits: String = pin.chars().filter(|c| c.is_ascii_digit()).collect();
    digits.len() == 8
}
