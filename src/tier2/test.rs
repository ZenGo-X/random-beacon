use std::convert::TryInto;
use std::time::Duration;

use curv::elliptic::curves::*;
use round_based::dev::Simulation;
use sha2::Sha256;

use crate::keygen::tests::KeygenSimulation;
use crate::tier2::state_machine::{LocalKey, NextRand, Tier2Seed};
use crate::utils::IteratorExt;

fn keygen(t: u16, n: u16) -> Vec<LocalKey> {
    let keygen = KeygenSimulation::<Bls12_381_2, Sha256>::setup(t, n);
    let phase0 = keygen.phase0_generate_parties_local_secrets();
    let phase1 = keygen.phase1_share_and_commit_shares(&phase0);
    let phase2 = keygen.phase2_decrypt_shares(&phase1);
    keygen.phase3_skipped(&phase2);
    keygen.phase4_skipped(&phase2, None);
    let phase5 = keygen.phase5_deduce_set_Q(&phase1, &phase2, None, None);
    let phase6 = keygen.phase6_construct_and_commit_local_secret(&phase5);
    let phase7 = keygen.phase7_validate_shares_commitments(&phase5, &phase6);

    let vk_vec: Vec<_> = phase6
        .committed_parties_secrets
        .iter()
        .map(|com| com.S.clone())
        .collect();

    let mut local_keys = vec![];
    for i in 0..n {
        local_keys.push(
            LocalKey::new(
                t,
                n,
                phase6.parties_secrets[usize::from(i)].σ.clone(),
                vk_vec.clone(),
                phase7.tpk[usize::from(i)].clone(),
            )
            .unwrap(),
        )
    }

    local_keys
}

fn next_rand(seed: Tier2Seed, local_keys: &[LocalKey]) -> (Vec<u8>, Tier2Seed) {
    let mut next_rand_simulation = Simulation::new();
    next_rand_simulation.enable_benchmarks(true);
    for (i, local_key) in local_keys.iter().enumerate_u16() {
        next_rand_simulation.add_party(
            NextRand::new(
                seed.clone(),
                i + 1,
                local_keys.len().try_into().unwrap(),
                local_key.clone(),
            )
            .unwrap(),
        );
    }
    let mut results = next_rand_simulation.run().unwrap();
    println!("{:?}", next_rand_simulation.benchmark_results());
    let total_duration: Duration = next_rand_simulation
        .benchmark_results()
        .unwrap()
        .values()
        .map(|v| v.total_time / u32::from(v.n))
        .sum();
    println!("Took: {:?}", total_duration);
    results.iter().all(|r| *r == results[0]);
    results.pop().unwrap()
}

#[test]
fn generate_next_random_t3_n10() {
    let local_keys = keygen(1, 3);
    let seed = Tier2Seed::initial(b"initial seed".to_vec());
    let (_rnd, _next_seed) = next_rand(seed, &local_keys);
}

#[test]
fn algorithm_is_deterministic() {
    let local_keys = keygen(1, 3);

    let seed = Tier2Seed::initial(b"initial seed".to_vec());
    let (rnd1, next_seed1) = next_rand(seed.clone(), &local_keys);
    let (rnd2, next_seed2) = next_rand(seed.clone(), &local_keys);

    assert_eq!(rnd1, rnd2);
    assert_eq!(next_seed1, next_seed2);
}

#[test]
fn any_set_of_parties_produces_the_same_randomness() {
    let local_keys = keygen(1, 3);

    let seed = Tier2Seed::initial(b"initial seed".to_vec());
    let (rnd1, next_seed1) = next_rand(seed.clone(), &local_keys[..2]);
    let (rnd2, next_seed2) = next_rand(seed.clone(), &local_keys[1..]);

    assert_eq!(rnd1, rnd2);
    assert_eq!(next_seed1, next_seed2);
}

// #[test]
// fn tier2_protocol_performance() {
//     if std::env::var_os("HEAVY_TESTS").is_none() {
//         println!("Env variable isn't set — test skipped");
//         return;
//     }
//
//     let mut results = vec![];
//     for n in (5..15).step_by(5) {
//         let mut keygen_simulation = Simulation::new();
//         keygen_simulation.enable_benchmarks(true);
//         for i in 1..=n {
//             keygen_simulation.add_party(Keygen::new(i, n / 3, n).unwrap());
//         }
//         let _ = keygen_simulation.run().unwrap();
//         results.push((
//             n,
//             format!("{:?}", keygen_simulation.benchmark_results().unwrap()),
//         ))
//     }
//
//     println!("# Keygen benchmarks");
//     println!();
//
//     for (n, b) in results {
//         println!("## n={}", n);
//         println!();
//         println!("{}", b);
//         println!();
//     }
// }
