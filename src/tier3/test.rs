use std::iter;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha512};
use typenum::U64;

use crate::tier3::core::*;
use crate::vrf::*;

pub type Randomness = [u8; 64];

pub struct ProtocolSimulation<H: Digest<OutputSize = U64> + Clone> {
    pub parties: Vec<ProtocolSetup<H>>,
}

impl<H: Digest<OutputSize = U64> + Clone> ProtocolSimulation<H> {
    pub fn keygen(n: u16, rounds_limit: u16) -> Self {
        let sk: Vec<_> = iter::repeat_with(SecretKey::generate)
            .take(usize::from(n))
            .collect();
        let pk: Vec<_> = sk.iter().map(|sk_i| sk_i.public_key()).collect();

        Self {
            parties: sk
                .into_iter()
                .map(|sk_i| ProtocolSetup::new(sk_i, pk.clone(), rounds_limit).unwrap())
                .collect(),
        }
    }

    pub fn phase1_broadcast_local_randomness(
        &self,
        seed: &Tier3Seed,
    ) -> Result<Phase1BroadcastLocalRandomness<H>, RoundsLimitExceeded> {
        let mut randomness = vec![];
        let mut took = vec![];

        for party_i in &self.parties {
            let start = Instant::now();
            match proceed_locally(party_i, seed) {
                Ok(r) => {
                    randomness.push(r);
                    took.push(start.elapsed());
                }
                Err(ProceedError::RoundsLimitExceeded { .. }) => return Err(RoundsLimitExceeded),
            }
        }
        let board = randomness.iter().cloned().map(Some).collect();

        Ok(Phase1BroadcastLocalRandomness {
            randomness,
            board,
            took,
        })
    }

    pub fn phase2_combine_published_randomness(
        &self,
        seed: Tier3Seed,
        phase1: &Phase1BroadcastLocalRandomness<H>,
    ) -> Phase2CompletedRound {
        let (mut randomness, mut next_seed) = (None::<[u8; 64]>, None::<Tier3Seed>);
        let mut took = vec![];

        for party_i in &self.parties {
            let start = Instant::now();
            let (randomness_i, next_seed_i) =
                combine(&party_i, seed.clone(), &phase1.board).unwrap();
            took.push(start.elapsed());

            if let Some(randomness) = &randomness {
                assert_eq!(*randomness, randomness_i);
            }
            if let Some(next_seed) = &next_seed {
                assert_eq!(*next_seed, next_seed_i);
            }
            randomness = Some(randomness_i);
            next_seed = Some(next_seed_i);
        }
        Phase2CompletedRound {
            randomness: randomness.unwrap(),
            next_seed: next_seed.unwrap(),
            took,
        }
    }
}

pub struct Phase1BroadcastLocalRandomness<H: Digest + Clone> {
    /// $\text{randomness}_i$ is a randomness generated by $\ith$ party by evaluating VDF
    pub randomness: Vec<VerifiableRandomness<H>>,

    /// Published randomness on board
    ///
    /// $\text{board}_i$ is a randomness published by $\ith$ party
    pub board: Msgs<VerifiableRandomness<H>>,

    /// $took_i$ shows how much time it took for $\ith$ party to complete this phase
    pub took: Vec<Duration>,
}

pub struct Phase2CompletedRound {
    /// The round output ??? random element
    pub randomness: Randomness,
    /// Updated seed that should be used to run next round
    pub next_seed: Tier3Seed,
    /// $took_i$ shows how much time it took for $\ith$ party to complete this phase
    pub took: Vec<Duration>,
}

#[derive(Debug, Clone)]
pub struct RoundsLimitExceeded;

#[test]
fn protocol_outputs_once() {
    let seed = Tier3Seed::initial([6; 64]);
    let tier3 = ProtocolSimulation::<Sha512>::keygen(5, 2);
    let phase1 = tier3.phase1_broadcast_local_randomness(&seed).unwrap();
    let _phase2 = tier3.phase2_combine_published_randomness(seed, &phase1);
}

#[test]
fn protocol_outputs_twice() {
    let seed = Tier3Seed::initial([6; 64]);
    let tier3 = ProtocolSimulation::<Sha512>::keygen(5, 2);
    let round1_phase1 = tier3.phase1_broadcast_local_randomness(&seed).unwrap();
    let round1_phase2 = tier3.phase2_combine_published_randomness(seed, &round1_phase1);
    let round2_phase1 = tier3
        .phase1_broadcast_local_randomness(&round1_phase2.next_seed)
        .unwrap();
    let round2_phase2 =
        tier3.phase2_combine_published_randomness(round1_phase2.next_seed, &round2_phase1);
    assert_ne!(round1_phase2.randomness, round2_phase2.randomness);
}

#[test]
fn protocol_terminates_once_it_reached_rounds_limit() {
    let seed = Tier3Seed::initial([6; 64]);
    let tier3 = ProtocolSimulation::<Sha512>::keygen(5, 2);

    let round1_phase1 = tier3.phase1_broadcast_local_randomness(&seed).unwrap();
    let round1_phase2 = tier3.phase2_combine_published_randomness(seed, &round1_phase1);

    let round2_phase1 = tier3
        .phase1_broadcast_local_randomness(&round1_phase2.next_seed)
        .unwrap();
    let round2_phase2 =
        tier3.phase2_combine_published_randomness(round1_phase2.next_seed, &round2_phase1);

    assert!(tier3
        .phase1_broadcast_local_randomness(&round2_phase2.next_seed)
        .is_err());
}

fn analyse_tier3_measurements<H: Digest + Clone>(
    name: String,
    phase1: &Phase1BroadcastLocalRandomness<H>,
    phase2: &Phase2CompletedRound,
) {
    use crate::utils::performance_analysis::*;

    analyse_measurements(
        name,
        &[
            PhaseMeasurement::Available(&phase1.took),
            PhaseMeasurement::Available(&phase2.took),
        ],
    )
}

#[test]
fn tier3_protocol_performance() {
    if std::env::var_os("HEAVY_TESTS").is_none() {
        println!("Env variable isn't set ??? test skipped");
        return;
    }

    for n in (5..=45).step_by(10) {
        let seed = Tier3Seed::initial([6; 64]);
        let tier3 = ProtocolSimulation::<Sha512>::keygen(n, 2);
        let phase1 = tier3.phase1_broadcast_local_randomness(&seed).unwrap();
        let phase2 = tier3.phase2_combine_published_randomness(seed, &phase1);

        analyse_tier3_measurements(format!("Tier3 n={}", n), &phase1, &phase2)
    }
}

#[test]
fn tier3_protocol_communication() {
    if std::env::var_os("HEAVY_TESTS").is_none() {
        println!("Env variable isn't set ??? test skipped");
        return;
    }

    let seed = Tier3Seed::initial([6; 64]);
    let tier3 = ProtocolSimulation::<Sha512>::keygen(5, 2);
    let phase1 = tier3.phase1_broadcast_local_randomness(&seed).unwrap();
    let _phase2 = tier3.phase2_combine_published_randomness(seed, &phase1);

    println!("# Communication size");
    println!();
    println!("## Tier3");
    println!();
    println!(
        "Phase1: {} bytes",
        bincode::serialize(&phase1.board[0].as_ref().unwrap())
            .unwrap()
            .len()
    );
}
