
use anyhow::anyhow;
use libsecp256k1::{PublicKey, SecretKey};
use sha3::{Digest, Keccak256};

#[derive(Debug, PartialEq)]
pub struct EthereumAddress([u8; 20]);

impl TryFrom<&str> for EthereumAddress {
    type Error = anyhow::Error;

    fn try_from(private_key_hex: &str) -> anyhow::Result<Self> {
        // Take the private key and remove the 0x prefix if it exists.
        let private_key_hex = if let Some(stripped_private_key_hex) = private_key_hex.strip_prefix("0x") {
            stripped_private_key_hex
        } else {
            private_key_hex
        };

        // Check that the private key is 256 bits.
        if private_key_hex.len() != 64 {
            return Err(anyhow!("Invalid private key length"));
        }

        // Convert the private key from hex to bytes.
        let secret_key_bytes = hex::decode(private_key_hex)
            .map_err(|e| anyhow!("Invalid hex: {}", e))?;

        let secret_key = SecretKey::parse_slice(&secret_key_bytes)
            .map_err(|e| anyhow!("Failed to parse secret key: {}", e))?;

        // Generate the public key from the secret key.
        // Libsecp256k1 uses Jacobian coordinates, which is a way can avoid of division.
        let public_key = PublicKey::from_secret_key(&secret_key);

        // It is worth noting that the public key is not formatted with the prefix (hex) 04 when the address is calculated.
        let hash = Keccak256::digest(&public_key.serialize()[1..]);

        // Then we keep only the last 20 bytes (least significant bytes), which is our Ethereum address:
        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..]);

        Ok(EthereumAddress(address_bytes))
    }
}

impl EthereumAddress {
    pub fn new(private_key_hex: &str) -> anyhow::Result<Self> {
        private_key_hex.try_into()
    }

    pub fn hex_encode_address(&self) -> String {
        hex::encode(self.0)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethereum_address_from_hex() {
        let private_key_hex = "f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315";
        let address = EthereumAddress::new(private_key_hex).unwrap();
        assert_eq!(address.hex_encode_address(), "001d3f1ef827552ae1114027bd3ecf1f086ba0f9");
    }

    #[test]
    fn test_ethereum_address_from_hex_with_prefix() {
        let private_key_hex = "0xf8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315";
        let address = EthereumAddress::new(private_key_hex).unwrap();
        assert_eq!(address.hex_encode_address(), "001d3f1ef827552ae1114027bd3ecf1f086ba0f9");
    }

    #[test]
    fn test_invalid_ethereum_address_from_hex() {
        let private_key_hex = "f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f31";
        let address = EthereumAddress::new(private_key_hex);
        assert!(address.is_err());
    }

    #[test]
    fn test_invalid_ethereum_address_from_hex_with_prefix() {
        let private_key_hex = "0xf8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f31";
        let address = EthereumAddress::new(private_key_hex);
        assert!(address.is_err());
    }

    #[test]
    fn test_invalid_ethereum_address_from_hex_with_prefix_and_suffix() {
        let private_key_hex = "0xf8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f31";
        let address = EthereumAddress::new(private_key_hex);
        assert!(address.is_err());
    }

    #[test]
    fn test_invalid_ethereum_address_from_hex_with_suffix() {
        let private_key_hex = "f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f31";
        let address = EthereumAddress::new(private_key_hex);
        assert!(address.is_err());
    }
}