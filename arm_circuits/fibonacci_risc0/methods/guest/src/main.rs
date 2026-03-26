use risc0_zkvm::guest::env;

fn main() {
    let n: u32 = env::read();
    let mut a: u128 = 0;
    let mut b: u128 = 1;
    for _ in 1..n {
        let sum = a + b;
        a = b;
        b = sum;
    }
    env::commit(&b);
}
