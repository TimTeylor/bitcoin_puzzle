use bitcoin::{Address, Network, PublicKey as BitcoinPublicKey, PrivateKey};
use bitcoin::secp256k1::{rand, Secp256k1, SecretKey, PublicKey};
use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use bitcoin::key::CompressedPublicKey;

fn random_bigint(min: &BigUint, max: &BigUint) -> BigUint {
    let mut rng = thread_rng();
    rng.gen_biguint_range(min, max)
}

fn main() {
    // Define the range for private keys
    let min_key = BigUint::parse_bytes(b"0000000000000000000000000000000000000000000000020000000000000000", 16).unwrap();
    let max_key = BigUint::parse_bytes(b"000000000000000000000000000000000000000000000003ffffffffffffffff", 16).unwrap();

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
    let address = Address::p2pkh(&bitcoin_public_key, Network::Bitcoin);
    // Generate P2PKH(u) address (uncompressed)
    let p2pkh_uncompressed_address = Address::p2pkh(&bitcoin_uncompressed_public_key, Network::Bitcoin);

    let private_key = PrivateKey::new(secret_key, Network::Bitcoin);

    // Create CompressedPublicKey
    let compressed_public_key = CompressedPublicKey(public_key);
    let beh_address = Address::p2wpkh(&compressed_public_key, Network::Bitcoin);
    let p2sh_address = Address::p2shwpkh(&compressed_public_key, Network::Bitcoin);

    println!("HEX: {}", hex::encode(private_key_bytes));
    println!("WIF(c): {}", private_key.to_wif());
    println!("P2PKH(c): {}", address);
    println!("P2SH(c): {}", p2sh_address);
    println!("BECH32(c): {}", beh_address);
    println!("P2PKH(u): {}", p2pkh_uncompressed_address);
}