use ed25519_dalek::{SigningKey, Signer, VerifyingKey};
use rand_core::OsRng;
use shared::{CommandPayload, Role, SignedMessage};
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() {
    println!("Master CLI starting...");

    // 1. Generate a keypair for the Master (In real life, this is loaded from a file/HSM)
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    
    println!("Master Public Key: {:?}", verifying_key.as_bytes());

    // 2. Create a payload
    let payload = CommandPayload {
        role: Role::Admin,
        target_led: 2, // Green
        turn_on: true,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
    };

    // 3. Serialize payload to bytes so we can sign it
    let payload_bytes = postcard::to_stdvec(&payload).unwrap();
    
    // 4. Sign the serialized payload
    let signature = signing_key.sign(&payload_bytes);

    // 5. Create the final message containing the signature and the payload
    let message = SignedMessage {
        public_key: verifying_key.as_bytes(),
        signature: &signature.to_bytes(),
        payload,
    };

    // Serialize the final message to send over the network
    let network_packet = postcard::to_stdvec(&message).unwrap();
    println!("Generated Network Packet ({} bytes): {:?}", network_packet.len(), network_packet);
    
    // TODO: Connect via TCP to target and send `network_packet`
}
