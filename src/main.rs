use bitcoin::{Address, Network, PublicKey as BitcoinPublicKey, PrivateKey};
use bitcoin::secp256k1::{rand, Secp256k1, SecretKey, PublicKey};
use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use bitcoin::key::CompressedPublicKey;
use reqwest::blocking::Client;
use serde_json::Value;

fn get_balance_info(addresses: &[String]) -> Result<Value, Box<dyn std::error::Error>> {
    let client = Client::new();
    let url = format!("https://blockchain.info/balance?active={}&base=BTC&cors=true", addresses.join("|"));
    let response = client.get(&url).send()?.json()?;
    Ok(response)
}

fn random_bigint(min: &BigUint, max: &BigUint) -> BigUint {
    let mut rng = thread_rng();
    rng.gen_biguint_range(min, max)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Define the range for private keys
    let min_key = BigUint::parse_bytes(b"0000000000000000000000000000000000000000000000040000000000000000", 16).unwrap();
    let max_key = BigUint::parse_bytes(b"000000000000000000000000000000000000000000000007ffffffffffffffff", 16).unwrap();

    // Generate a random number within the range
    let random_value = random_bigint(&min_key, &max_key);

    // Convert the random value to a fixed 32-byte array
    let mut private_key_bytes = [0u8; 32];
    let random_bytes = random_value.to_bytes_be();
    private_key_bytes[32 - random_bytes.len()..].copy_from_slice(&random_bytes);

    let s = Secp256k1::new();

    // Set secret key
    let secret_key = SecretKey::from_slice(&private_key_bytes)
        .expect("32 bytes, within curve order");

    let public_key = PublicKey::from_secret_key(&s, &secret_key);

    // Convert to BitcoinPublicKey
    let bitcoin_public_key = BitcoinPublicKey::new(public_key);

    // Generate uncompressed public key
    let uncompressed_public_key = PublicKey::from_secret_key(&s, &secret_key).serialize_uncompressed();
    let bitcoin_uncompressed_public_key = BitcoinPublicKey::from_slice(&uncompressed_public_key)
        .expect("Valid uncompressed public key");

    // Generate P2PKH address
    let p2pkh_compressed_address = Address::p2pkh(&bitcoin_public_key, Network::Bitcoin);
    // Generate P2PKH(u) address (uncompressed)
    let p2pkh_uncompressed_address = Address::p2pkh(&bitcoin_uncompressed_public_key, Network::Bitcoin);

    let private_key = PrivateKey::new(secret_key, Network::Bitcoin);

    // Create CompressedPublicKey
    let compressed_public_key = CompressedPublicKey(public_key);
    let bech32_address = Address::p2wpkh(&compressed_public_key, Network::Bitcoin);
    let p2sh_address = Address::p2shwpkh(&compressed_public_key, Network::Bitcoin);

    // Collect addresses
    let addresses = vec![
        ("P2PKH(c)", p2pkh_compressed_address.to_string()),
        ("P2SH(c)", p2sh_address.to_string()),
        ("BECH32(c)", bech32_address.to_string()),
        ("P2PKH(u)", p2pkh_uncompressed_address.to_string()),
    ];
    
    // Get balance information
    let balance_info = get_balance_info(&addresses.iter().map(|(_, addr)| addr.clone()).collect::<Vec<_>>())?;
    
    // Print conclusion
    println!("HEX: {}", hex::encode(private_key_bytes));
    println!("WIF(c): {}", private_key.to_wif());
    
    for (label, address) in addresses {
        if let Some(info) = balance_info.get(&address) {
            let balance = info["final_balance"].as_f64().unwrap();
            let tx_count = info["n_tx"].as_u64().unwrap();
            println!("{}: {} | Balance: {} | Tx: {}", label, address, balance, tx_count);
        } else {
            println!("{}: {} | Balance: N/A | Tx: N/A", label, address);
        }
    }
    
    Ok(())
    
}