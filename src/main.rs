use crate::ethereum_address::EthereumAddress;

mod ethereum_address;

fn main() {
    // private key is 256 bits shown as 64 hexadecimal digits, each 4 bits
    let private_key_hex = "3ac5dc9a32f4db6501f7fc01f61961e4c30efbf46f01ad73c09c113bb678e60b";

    let ethereum_address: Result<EthereumAddress, anyhow::Error> = private_key_hex.parse();
    match ethereum_address {
        Ok(ethereum_address) => {
            let address = format!("0x{}", ethereum_address.hex_encode_address());
            assert_eq!(address, "0x18a5113f7fbc31e73c2bb38a895fd6683803e7f8");
            println!("Address: {address}")
        },
        Err(e) => println!("Failed to generate Ethereum address: {e}"),
    }
}
