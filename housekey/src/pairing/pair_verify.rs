use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use super::{PairingError, check_error, check_state};
use crate::crypto::session::EncryptedSession;
use crate::crypto::{hap_decrypt, hap_encrypt, hkdf_derive};
use crate::tlv::{self, TlvMap, TlvType};

pub struct PairVerifyResult {
    pub session: EncryptedSession,
}

pub struct PairVerify {
    controller_ltsk: SigningKey,
    controller_pairing_id: Vec<u8>,
    accessory_ltpk: VerifyingKey,
    ephemeral_secret: EphemeralSecret,
    ephemeral_public: X25519PublicKey,
}

impl PairVerify {
    pub fn new(
        controller_ltsk: &[u8; 32],
        controller_pairing_id: &[u8],
        accessory_ltpk: &[u8; 32],
    ) -> Result<Self, PairingError> {
        let ltsk = SigningKey::from_bytes(controller_ltsk);
        let acc_ltpk = VerifyingKey::from_bytes(accessory_ltpk)
            .map_err(|_| PairingError::SignatureVerificationFailed)?;

        let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let public = X25519PublicKey::from(&secret);

        Ok(Self {
            controller_ltsk: ltsk,
            controller_pairing_id: controller_pairing_id.to_vec(),
            accessory_ltpk: acc_ltpk,
            ephemeral_secret: secret,
            ephemeral_public: public,
        })
    }

    pub fn build_m1(&self) -> Vec<u8> {
        let mut tlvs = TlvMap::new();
        tlvs.insert(TlvType::State, vec![0x01]);
        tlvs.insert(
            TlvType::PublicKey,
            self.ephemeral_public.as_bytes().to_vec(),
        );
        tlv::encode(&tlvs)
    }

    pub fn process_m2(self, data: &[u8]) -> Result<PairVerifyM3, PairingError> {
        let tlvs = tlv::decode(data)?;

        check_state(&tlvs, 0x02)?;
        check_error(&tlvs)?;

        let accessory_epk_bytes =
            tlvs.get(&TlvType::PublicKey)
                .ok_or(PairingError::UnexpectedState {
                    expected: 0x02,
                    got: 0x00,
                })?;

        let encrypted_data =
            tlvs.get(&TlvType::EncryptedData)
                .ok_or(PairingError::UnexpectedState {
                    expected: 0x02,
                    got: 0x00,
                })?;

        let accessory_epk_array: [u8; 32] = accessory_epk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| PairingError::SignatureVerificationFailed)?;
        let accessory_epk = X25519PublicKey::from(accessory_epk_array);

        let shared_secret = self.ephemeral_secret.diffie_hellman(&accessory_epk);

        let session_key = hkdf_derive(
            shared_secret.as_bytes(),
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
        )
        .map_err(PairingError::Crypto)?;

        let decrypted =
            hap_decrypt(&session_key, b"PV-Msg02", encrypted_data).map_err(PairingError::Crypto)?;

        let sub_tlvs = tlv::decode(&decrypted)?;

        let accessory_id = sub_tlvs
            .get(&TlvType::Identifier)
            .ok_or(PairingError::SignatureVerificationFailed)?;
        let accessory_signature = sub_tlvs
            .get(&TlvType::Signature)
            .ok_or(PairingError::SignatureVerificationFailed)?;

        // accessory_info = accessory_epk || accessory_id || controller_epk
        let mut accessory_info = Vec::new();
        accessory_info.extend_from_slice(accessory_epk.as_bytes());
        accessory_info.extend_from_slice(accessory_id);
        accessory_info.extend_from_slice(self.ephemeral_public.as_bytes());

        let signature = ed25519_dalek::Signature::from_slice(accessory_signature)
            .map_err(|_| PairingError::SignatureVerificationFailed)?;

        self.accessory_ltpk
            .verify(&accessory_info, &signature)
            .map_err(|_| PairingError::SignatureVerificationFailed)?;

        // Derive the transport session keys
        let controller_to_accessory_key = hkdf_derive(
            shared_secret.as_bytes(),
            b"Control-Salt",
            b"Control-Read-Encryption-Key",
        )
        .map_err(PairingError::Crypto)?;

        let accessory_to_controller_key = hkdf_derive(
            shared_secret.as_bytes(),
            b"Control-Salt",
            b"Control-Write-Encryption-Key",
        )
        .map_err(PairingError::Crypto)?;

        Ok(PairVerifyM3 {
            controller_ltsk: self.controller_ltsk,
            controller_pairing_id: self.controller_pairing_id,
            controller_epk: self.ephemeral_public,
            accessory_epk,
            session_key,
            send_key: controller_to_accessory_key,
            recv_key: accessory_to_controller_key,
        })
    }
}

pub struct PairVerifyM3 {
    controller_ltsk: SigningKey,
    controller_pairing_id: Vec<u8>,
    controller_epk: X25519PublicKey,
    accessory_epk: X25519PublicKey,
    session_key: [u8; 32],
    send_key: [u8; 32],
    recv_key: [u8; 32],
}

impl PairVerifyM3 {
    pub fn build_m3(&self) -> Result<Vec<u8>, PairingError> {
        // controller_info = controller_epk || controller_id || accessory_epk
        let mut controller_info = Vec::new();
        controller_info.extend_from_slice(self.controller_epk.as_bytes());
        controller_info.extend_from_slice(&self.controller_pairing_id);
        controller_info.extend_from_slice(self.accessory_epk.as_bytes());

        let signature = self.controller_ltsk.sign(&controller_info);

        let mut sub_tlvs = TlvMap::new();
        sub_tlvs.insert(TlvType::Identifier, self.controller_pairing_id.clone());
        sub_tlvs.insert(TlvType::Signature, signature.to_bytes().to_vec());
        let sub_tlv_bytes = tlv::encode(&sub_tlvs);

        let encrypted = hap_encrypt(&self.session_key, b"PV-Msg03", &sub_tlv_bytes)
            .map_err(PairingError::Crypto)?;

        let mut tlvs = TlvMap::new();
        tlvs.insert(TlvType::State, vec![0x03]);
        tlvs.insert(TlvType::EncryptedData, encrypted);

        Ok(tlv::encode(&tlvs))
    }

    pub fn process_m4(self, data: &[u8]) -> Result<PairVerifyResult, PairingError> {
        let tlvs = tlv::decode(data)?;

        check_state(&tlvs, 0x04)?;
        check_error(&tlvs)?;

        Ok(PairVerifyResult {
            session: EncryptedSession::new(&self.send_key, &self.recv_key),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_m1_with_public_key() {
        let controller_ltsk = SigningKey::generate(&mut rand::thread_rng());
        let accessory_ltsk = SigningKey::generate(&mut rand::thread_rng());

        let pv = PairVerify::new(
            &controller_ltsk.to_bytes(),
            b"test-controller",
            &accessory_ltsk.verifying_key().to_bytes(),
        )
        .unwrap();

        let m1_bytes = pv.build_m1();
        let tlvs = tlv::decode(&m1_bytes).unwrap();

        assert_eq!(tlvs.get(&TlvType::State).unwrap(), &[0x01]);
        assert_eq!(tlvs.get(&TlvType::PublicKey).unwrap().len(), 32);
    }
}
