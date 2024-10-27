use num::{
    integer::{gcd, lcm},
    FromPrimitive, One,
};
use num_bigint::BigUint;

struct PrivateKey {
    p: BigUint,
    q: BigUint,
    lambda: BigUint,
    n: BigUint,
    key: BigUint,
}

impl PrivateKey {
    fn new(n: BigUint, key: BigUint, p: BigUint, q: BigUint, lambda: BigUint) -> Self {
        Self {
            p,
            q,
            lambda,
            n,
            key,
        }
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

pub struct RSA {
    private_key: Option<PrivateKey>,
    public_key: Option<PublicKey>,
}

impl RSA {
    pub fn new() -> Self {
        Self {
            private_key: None,
            public_key: None,
        }
    }

    pub fn with_private_key(mut self, private_key: PrivateKey) -> Self {
        self.private_key = Some(private_key);
        self
    }

    pub fn with_public_key(mut self, public_key: PublicKey) -> Self {
        self.public_key = Some(public_key);
        self
    }

    pub fn validate(self) -> Result<Self, String> {
        // Allow both keys to be None or either key to be None.
        if self.public_key.is_none() || self.private_key.is_none() {
            return Ok(self);
        }

        let private_key = self.private_key.unwrap();
        let public_key = self.public_key.unwrap();

        let inv: Option<BigUint> = public_key.key.modinv(&private_key.lambda);
        match inv {
            Some(inv) => {
                if inv == private_key.key {
                    Ok(Self {
                        private_key: Some(private_key),
                        public_key: Some(public_key),
                    })
                } else {
                    Err(format!(
                        "Invalid key pair: the private key ({}) is not a modular multiplicative inverse of the public key ({}) modulo λ(n) ({}).",
                        private_key.key, public_key.key, public_key.n
                    ))
                }
            },
            None => Err(format!(
                "Invalid key pair: the public key ({}) does not have a modular multiplicative inverse modulo λ(n) ({})",
                public_key.key, private_key.lambda
            )),
        }
    }

    pub fn encrypt(&self, message: &BigUint) -> Result<BigUint, String> {
        match &self.public_key {
            Some(public_key) => {
                if *message < public_key.n {
                    Ok(message.modpow(&public_key.key, &public_key.n))
                } else {
                    Err(String::from(
                        "Error: can not encrypt a message that is larger than n.",
                    ))
                }
            }
            None => Err(String::from("Can not encrypt when public key is None.")),
        }
    }

    pub fn decrypt(&self, cipher: &BigUint) -> Result<BigUint, String> {
        match &self.private_key {
            Some(private_key) => {
                if *cipher < private_key.n {
                    Ok(cipher.modpow(&private_key.key, &private_key.n))
                } else {
                    Err(String::from(
                        "Error: can not decrypt a message that is larger than n.",
                    ))
                }
            }
            None => Err(String::from("Can not decrypt when private key is None.")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_works() {
        let p = BigUint::from_u64(61).unwrap();
        let q = BigUint::from_u64(53).unwrap();
        let n = p.clone() * q.clone();
        let lambda = lcm(p.clone() - BigUint::one(), q.clone() - BigUint::one());
        let e = BigUint::from_u64(17).unwrap();
        let d = BigUint::from_u64(413).unwrap();

        let private_key = PrivateKey::new(n.clone(), d, p, q, lambda);
        let public_key = PublicKey::new(n.clone(), e);

        let rsa = match RSA::new()
            .with_private_key(private_key)
            .with_public_key(public_key)
            .validate()
        {
            Ok(rsa) => rsa,
            Err(e) => {
                println!("Error creating RSA instance: {}", e);
                return;
            }
        };

        let c = rsa.encrypt(&BigUint::from_u64(65).unwrap()).unwrap();
        let m = rsa.decrypt(&c).unwrap();

        println!("C: {}", c);
        println!("M: {}", m);

        assert!(c == BigUint::from_u64(2790).unwrap());
        assert!(m == BigUint::from_u64(65).unwrap());
    }
}
