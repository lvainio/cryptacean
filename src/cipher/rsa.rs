use num::{
    integer::{gcd, lcm},
    FromPrimitive, One,
};
use num_bigint::BigUint;

struct PrivateKey {
    n: BigUint,
    key: BigUint,
}

impl PrivateKey {
    fn new(n: BigUint, key: BigUint) -> Self {
        Self { n, key }
    }
}

struct PublicKey {
    n: BigUint,
    key: BigUint,
}

impl PublicKey {
    fn new(n: BigUint, key: BigUint) -> Self {
        Self { n, key }
    }
}

struct RSA {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl RSA {
    fn from_keys(private_key: PrivateKey, public_key: PublicKey) -> Result<Self, String>  {
        let inv: Option<BigUint> = public_key.key.modinv(&public_key.n);
        match inv {
            Some(inv) => {
                if inv == private_key.key {
                    Ok(Self {
                        private_key,
                        public_key
                    })
                } else {
                    Err(format!(
                        "Invalid key pair: the private key ({}) is not a modular multiplicative inverse of the public key ({}) modulo n ({}).",
                        private_key.key, public_key.key, public_key.n
                    ))
                }
            },
            None => Err(format!(
                "Invalid key pair: the public key ({}) does not have a modular multiplicative inverse modulo n ({})",
                public_key.key, public_key.n
            )),
        }
    }

    fn new() -> Self {
        let p: BigUint = BigUint::from_u64(61).unwrap();
        let q: BigUint = BigUint::from_u64(53).unwrap();

        let n: BigUint = p.clone() * q.clone();
        let lambda: BigUint = lcm(p - BigUint::one(), q - BigUint::one());

        let e: BigUint = BigUint::from_u64(17).unwrap();
        let d: BigUint = BigUint::from_u64(413).unwrap();

        let private_key = PrivateKey::new(n.clone(), d);
        let public_key = PublicKey::new(n.clone(), e);

        Self {
            private_key,
            public_key,
        }
    }

    fn encrypt(&self, message: &BigUint) -> BigUint {
        if *message < self.public_key.n {
            message.modpow(&self.public_key.public_key, &self.public_key.n)
        } else {
            panic!("Message need to be smaller than N.");
        }
    }

    fn decrypt(&self, cipher: &BigUint) -> BigUint {
        cipher.modpow(&self.private_key.private_key, &self.private_key.n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_works() {
        let rsa = RSA::new(None, None);

        assert!(false);

        let c = rsa.encrypt(&BigUint::from_u64(65).unwrap());
        let m = rsa.decrypt(&c);

        println!("C: {}", c);
        println!("M: {}", m);

        assert!(c == BigUint::from_u64(2790).unwrap());
        assert!(m == BigUint::from_u64(65).unwrap());
    }
}
