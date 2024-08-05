use alloc::boxed::Box;
use std::sync::Mutex;

use libcrux::digest::{sha2_256, Sha2_256};
use rustls::crypto::hash;

pub struct Sha256;

impl hash::Hash for Sha256 {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(Mutex::new(Sha2_256::new())))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&sha2_256(data)[..])
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }

    fn output_len(&self) -> usize {
        32
    }
}

struct Sha256Context(Mutex<Sha2_256>);

impl hash::Context for Sha256Context {
    fn fork_finish(&self) -> hash::Output {
        let mut hasher: Sha2_256 = {
            self.0
                .lock()
                .expect("couldn't take hasher lock during fork_finish")
                .clone()
        };

        hash::Output::new(&hasher.finish()[..])
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        let hasher: Sha2_256 = {
            self.0
                .lock()
                .expect("couldn't take hasher lock during fork_finish")
                .clone()
        };

        Box::new(Self(Mutex::new(hasher)))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(
            &self
                .0
                .lock()
                .expect("couldn't take hasher lock during finish")
                .finish()[..],
        )
    }

    fn update(&mut self, data: &[u8]) {
        self.0
            .lock()
            .expect("couldn't take hasher lock during update")
            .update(data);
    }
}
