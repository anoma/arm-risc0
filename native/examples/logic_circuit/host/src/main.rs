use aarm_core::encryption::{random_keypair, Ciphertext};
use k256::Scalar;
use methods::{LOGIC_GUEST_ELF, LOGIC_GUEST_ID};
use rand::rngs::OsRng;
use risc0_zkvm::{default_prover, ExecutorEnv};
use std::time::Instant;

pub fn main() {
    let prove_start_timer = Instant::now();

    // Generate a random sender's private key
    let sender_sk = Scalar::generate_vartime(&mut OsRng);
    // Generate a keypair for the receiver
    let (receiver_sk, receiver_pk) = random_keypair();

    // Example message as Vec<u8> and nonce
    let message = b"Hello, AES-256-GCM encryption!".to_vec();
    let nonce: [u8; 12] = rand::random();

    let env = ExecutorEnv::builder()
        .write(&(&message, &receiver_pk, &sender_sk, &nonce))
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover.prove(env, LOGIC_GUEST_ELF).unwrap().receipt;

    let prove_duration = prove_start_timer.elapsed();
    println!("Prove duration time: {:?}", prove_duration);

    let extract_journal_start_timer = Instant::now();
    // Extract journal of receipt
    let cipher: Ciphertext = receipt.journal.decode().unwrap();

    let extract_journal_duration = extract_journal_start_timer.elapsed();
    println!(
        "Extract Journal duration time: {:?}",
        extract_journal_duration
    );

    let verify_start_timer = Instant::now();

    receipt.verify(LOGIC_GUEST_ID).unwrap();
    let verify_duration = verify_start_timer.elapsed();
    println!("Verify duration time: {:?}", verify_duration);

    // Decryption
    let decryption = cipher.decrypt(&receiver_sk).unwrap();

    assert_eq!(message, decryption);
}
