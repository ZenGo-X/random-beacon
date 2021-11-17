use bls::threshold_bls::state_machine::sign::{Error, Sign};
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use round_based::{Msg, StateMachine};

pub use bls::threshold_bls::state_machine::keygen::{Keygen, LocalKey};
use sha2::Sha256;
use std::time::Duration;

type Result<T, E = Error> = std::result::Result<T, E>;

/// Protocol that outputs a next random value
#[derive(Debug)]
pub struct NextRand {
    r: u16,
    state: Sign,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Tier2Seed {
    r: u16,
    seed: Vec<u8>,
}

impl NextRand {
    pub fn new(seed: Tier2Seed, i: u16, n: u16, local_key: LocalKey) -> Result<Self> {
        let mut message = vec![0; 2 + seed.seed.len()];
        message[..2].copy_from_slice(&seed.r.to_be_bytes());
        message[2..].copy_from_slice(&seed.seed);

        Ok(Self {
            r: seed.r,
            state: Sign::new(message, i, n, local_key)?,
        })
    }
}

impl StateMachine for NextRand {
    type MessageBody = <Sign as StateMachine>::MessageBody;
    type Err = <Sign as StateMachine>::Err;
    type Output = (Vec<u8>, Tier2Seed);

    fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<(), Self::Err> {
        self.state.handle_incoming(msg)
    }

    fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
        self.state.message_queue()
    }

    fn wants_to_proceed(&self) -> bool {
        self.state.wants_to_proceed()
    }

    fn proceed(&mut self) -> Result<(), Self::Err> {
        self.state.proceed()
    }

    fn round_timeout(&self) -> Option<Duration> {
        self.state.round_timeout()
    }

    fn round_timeout_reached(&mut self) -> Self::Err {
        self.state.round_timeout_reached()
    }

    fn is_finished(&self) -> bool {
        self.state.is_finished()
    }

    fn pick_output(&mut self) -> Option<Result<Self::Output, Self::Err>> {
        let sig = match self.state.pick_output()? {
            Ok(sig) => sig.1,
            Err(e) => return Some(Err(e)),
        };
        let rnd = Sha256::new().chain_point(&sig.sigma).finalize();
        let next_seed = Tier2Seed {
            r: self.r + 1,
            seed: sig.sigma.to_bytes(true).to_vec(),
        };
        Some(Ok((rnd.to_vec(), next_seed)))
    }

    fn current_round(&self) -> u16 {
        self.state.current_round()
    }

    fn total_rounds(&self) -> Option<u16> {
        self.state.total_rounds()
    }

    fn party_ind(&self) -> u16 {
        self.state.party_ind()
    }

    fn parties(&self) -> u16 {
        self.state.parties()
    }
}

impl Tier2Seed {
    pub fn initial(seed: Vec<u8>) -> Self {
        Self { r: 0, seed }
    }
}
