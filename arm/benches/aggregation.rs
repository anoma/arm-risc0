use std::{env, time::Instant, vec};

use arm::{
    aggregation::{batch::BatchProof, pcd::PcdProof, AggregationProof, AggregationStrategy},
    transaction::{generate_test_transaction, Transaction},
};

use risc0_zkvm::InnerReceipt;

// For the test transaction will aggregate up to 3*MAX_ACTIONS proofs.
const MAX_ACTIONS_DEFAULT: usize = 5;

fn main() {
    // Print info running the bench with environment variables:
    // RISC0_DEV_MODE=1 RUST_LOG=info RISC0_INFO=1
    env_logger::init();

    let (max_actions, strategies, exact) = parse_args();
    benchmark_test_transaction(max_actions, &strategies, exact);
}

fn parse_args() -> (usize, Vec<AggregationStrategy>, bool) {
    let args: Vec<String> = env::args().collect();

    let strategies = if args.len() == 6 {
        match args[2].as_str() {
            "batch" => vec![AggregationStrategy::Batch],
            "sequential" => vec![AggregationStrategy::Sequential],
            "all" => vec![AggregationStrategy::Batch, AggregationStrategy::Sequential],
            _ => {
                println!("Ignoring passed arguments");
                vec![AggregationStrategy::Batch, AggregationStrategy::Sequential]
            }
        }
    } else {
        vec![AggregationStrategy::Batch, AggregationStrategy::Sequential]
    };

    let max_actions = if args.len() == 6 {
        match args[3].parse() {
            Ok(n) => n,
            _ => {
                println!("Ignoring passed arguments");
                MAX_ACTIONS_DEFAULT
            }
        }
    } else {
        MAX_ACTIONS_DEFAULT
    };

    let exact = if args.len() == 6 {
        match args[4].as_str() {
            "exact" => true,
            "upto" => false,
            _ => {
                println!("Ignoring passed arguments");
                false
            }
        }
    } else {
        false
    };

    (max_actions, strategies, exact)
}

fn benchmark_test_transaction(max_actions: usize, strategies: &[AggregationStrategy], exact: bool) {
    println!("TEST TRANSACTION BENCHMARKS");

    println!("Generating test transaction...");
    let tx = generate_test_transaction(1);

    let mut num_actions = Vec::new();
    for i in 0..max_actions {
        let next_po2: usize = (i as u64).next_power_of_two().try_into().unwrap();
        if next_po2 <= max_actions {
            num_actions.push(next_po2);
        }
    }
    if num_actions.last().unwrap() != &max_actions {
        num_actions.push(max_actions);
    }
    num_actions.dedup();

    if exact {
        num_actions = vec![max_actions];
        println!(
            "Benchmarking exactly {:?} aggregations ({:?} actions)",
            3 * num_actions.last().unwrap(),
            num_actions.last().unwrap()
        );
    } else {
        println!(
            "Benchmarking for up to {:?} aggregations ({:?} actions)",
            3 * num_actions.last().unwrap(),
            num_actions.last().unwrap()
        );
    }

    for n in num_actions {
        let dummy_tx = expand_tx_with_actions(&tx, n.try_into().unwrap());
        benchmark_aggregation(&dummy_tx, &strategies);
    }
}

fn benchmark_aggregation(tx: &Transaction, strategies: &[AggregationStrategy]) {
    println!(
        "\nNumber of aggregated proofs: {:?}",
        number_aggregations(&tx)
    );
    println!("Base proofs size (bytes): {:?}", base_proofs_size(&tx));
    for strategy in strategies.to_vec() {
        println!("\n\tStrategy: {:?}", strategy);
        let mut tx_str = tx.clone();

        let aggregation_timer = Instant::now();
        tx_str.aggregate_with_strategy(strategy).unwrap();
        let prove_duration = aggregation_timer.elapsed();

        println!("\tAggregation time {:?}", prove_duration);

        let verification_timer = Instant::now();
        let verify_res = tx_str.verify_aggregation();
        let verify_time = verification_timer.elapsed();

        assert_eq!(true, verify_res.is_some());

        println!("\tVerification time {:?}", verify_time);

        let agg_proof = bincode::deserialize(&tx_str.aggregation_proof.clone().unwrap()).unwrap();

        let inner_receipt = match agg_proof {
            AggregationProof::Sequential(PcdProof(inner_receipt)) => inner_receipt,
            AggregationProof::Batch(BatchProof(inner_receipt)) => inner_receipt,
        };
        println!(
            "\tAggregation proof size (bytes): {:?}",
            inner_receipt.seal_size()
        );
        match inner_receipt {
            InnerReceipt::Composite(cmp) => println!(
                "\tAggregation proof type: Composite. Number of segments: {:?}",
                cmp.segments.len()
            ),
            InnerReceipt::Succinct(_) => println!("\tAggregation proof type: Succinct."),
            InnerReceipt::Groth16(_) => println!("\tAggregation proof type: Groth16."),
            InnerReceipt::Fake(_) => println!("\tAggregation proof type: Fake."),
            _ => {}
        }
    }
}

fn number_aggregations(tx: &Transaction) -> usize {
    let mut i: usize = 0;

    for a in tx.actions.iter() {
        i += a.get_compliance_units().len();
        i += a.get_logic_verifier_inputs().len();
    }

    i
}

/// Returns a dummy transaction with `num_actions` actions in it.
fn expand_tx_with_actions(tx: &Transaction, num_actions: usize) -> Transaction {
    let mut actions = Vec::new();
    //let mut actions = tx.actions.clone();

    for _ in 0..num_actions {
        let a = tx.actions[0].clone();
        actions.push(a);
    }

    Transaction {
        actions: actions,
        delta_proof: tx.delta_proof.clone(),
        expected_balance: None,
        aggregation_proof: None,
    }
}

/// Returns the total size of all proofs in the tx.
fn base_proofs_size(tx: &Transaction) -> usize {
    let mut proof_size = 0;
    for action in tx.actions.iter() {
        for cu in action.compliance_units.iter() {
            proof_size += cu.proof.clone().unwrap().len();
        }
        for lp in action.logic_verifier_inputs.iter() {
            proof_size += lp.proof.clone().unwrap().len();
        }
    }

    proof_size
}
