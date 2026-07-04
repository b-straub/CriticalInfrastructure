use ed25519_dalek::{SigningKey, SecretKey};
use rand::rngs::OsRng;
fn main() {
    let mut csprng = OsRng;
    for role in ["Guest", "User", "Admin"] {
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        println!("{} Role:", role);
        println!("  Secret Key: {:?}", signing_key.to_bytes());
        println!("  Public Key: {:?}", verifying_key.to_bytes());
    }
}
