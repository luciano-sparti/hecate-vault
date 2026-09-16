use crate::buffer::SecretBuffer;
use anyhow::{anyhow, Result};
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Galois Field GF(256) arithmetic with primitive polynomial 0x11D (x^8 + x^4 + x^3 + x^2 + 1)
/// Generator alpha = 2.
struct Gf256;

impl Gf256 {
    const EXP_TABLE: [u8; 512] = {
        let mut table = [0u8; 512];
        let mut x = 1u16;
        let mut i = 0;
        while i < 255 {
            table[i] = x as u8;
            table[i + 255] = x as u8;
            let mut next = x << 1;
            if (next & 0x100) != 0 {
                next ^= 0x11d;
            }
            x = next;
            i += 1;
        }
        table
    };

    const LOG_TABLE: [u8; 256] = {
        let mut table = [0u8; 256];
        let mut x = 1u16;
        let mut i = 0;
        while i < 255 {
            table[x as usize] = i as u8;
            let mut next = x << 1;
            if (next & 0x100) != 0 {
                next ^= 0x11d;
            }
            x = next;
            i += 1;
        }
        table
    };

    #[inline(always)]
    fn add(a: u8, b: u8) -> u8 {
        a ^ b
    }

    #[inline(always)]
    fn mul(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let log_a = Self::LOG_TABLE[a as usize] as usize;
            let log_b = Self::LOG_TABLE[b as usize] as usize;
            Self::EXP_TABLE[log_a + log_b]
        }
    }

    #[inline(always)]
    fn div(a: u8, b: u8) -> Result<u8> {
        if b == 0 {
            return Err(anyhow!("Division by zero in GF(256)"));
        }
        if a == 0 {
            return Ok(0);
        }
        let log_a = Self::LOG_TABLE[a as usize] as usize;
        let log_b = Self::LOG_TABLE[b as usize] as usize;
        let diff = (log_a + 255 - log_b) % 255;
        Ok(Self::EXP_TABLE[diff])
    }
}

/// A single share of a split secret in Shamir's Secret Sharing scheme.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ShamirShare {
    pub id: u8,
    pub threshold: u8,
    pub total: u8,
    pub data: Vec<u8>,
}

impl ShamirShare {
    /// Formats the share as a human-readable recovery string (e.g. "HCT-SHR-3-5-01-a1b2c3...")
    pub fn to_formatted_string(&self) -> String {
        format!(
            "HCT-SHR-{}-{}-{:02x}-{}",
            self.threshold,
            self.total,
            self.id,
            hex::encode(&self.data)
        )
    }

    /// Parses a formatted recovery string back into a ShamirShare.
    pub fn from_formatted_string(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.trim().split('-').collect();
        if parts.len() != 6 || parts[0] != "HCT" || parts[1] != "SHR" {
            return Err(anyhow!("Invalid Shamir share format. Expected 'HCT-SHR-k-n-id-hex'"));
        }

        let threshold: u8 = parts[2].parse().map_err(|_| anyhow!("Invalid threshold"))?;
        let total: u8 = parts[3].parse().map_err(|_| anyhow!("Invalid total count"))?;
        let id = u8::from_str_radix(parts[4], 16).map_err(|_| anyhow!("Invalid share id"))?;
        let data = hex::decode(parts[5]).map_err(|_| anyhow!("Invalid hex payload in share"))?;

        Ok(Self {
            id,
            threshold,
            total,
            data,
        })
    }
}

/// Split a secret into `total` shares such that any `threshold` shares can reconstruct it.
pub fn split_secret(
    secret: &SecretBuffer,
    threshold: u8,
    total: u8,
) -> Result<Vec<ShamirShare>> {
    if threshold < 2 {
        return Err(anyhow!("Threshold must be at least 2"));
    }
    if threshold > total {
        return Err(anyhow!("Threshold cannot exceed total shares"));
    }
    if total > 254 {
        return Err(anyhow!("Total shares cannot exceed 254"));
    }
    if secret.is_empty() {
        return Err(anyhow!("Secret cannot be empty"));
    }

    let secret_bytes = secret.as_bytes();
    let mut shares_data: Vec<Vec<u8>> = (0..total).map(|_| Vec::with_capacity(secret_bytes.len())).collect();
    let mut rng = thread_rng();

    for &secret_byte in secret_bytes {
        // Polynomial: f(x) = secret_byte + a_1*x + a_2*x^2 + ... + a_{k-1}*x^{k-1}
        let mut coefficients = vec![secret_byte];
        for _ in 1..threshold {
            let mut coeff = [0u8; 1];
            rng.fill_bytes(&mut coeff);
            while coeff[0] == 0 {
                rng.fill_bytes(&mut coeff);
            }
            coefficients.push(coeff[0]);
        }

        // Evaluate f(x) for x = 1 .. total
        for x in 1..=total {
            let mut y = 0u8;
            for (power, &coeff) in coefficients.iter().enumerate() {
                let mut x_pow = 1u8;
                for _ in 0..power {
                    x_pow = Gf256::mul(x_pow, x);
                }
                let term = Gf256::mul(coeff, x_pow);
                y = Gf256::add(y, term);
            }
            shares_data[(x - 1) as usize].push(y);
        }
    }

    let shares = shares_data
        .into_iter()
        .enumerate()
        .map(|(idx, data)| ShamirShare {
            id: (idx + 1) as u8,
            threshold,
            total,
            data,
        })
        .collect();

    Ok(shares)
}

/// Combine `threshold` or more shares to reconstruct the original secret using Lagrange interpolation.
pub fn combine_shares(shares: &[ShamirShare]) -> Result<SecretBuffer> {
    if shares.is_empty() {
        return Err(anyhow!("No shares provided"));
    }

    let threshold = shares[0].threshold as usize;
    if shares.len() < threshold {
        return Err(anyhow!(
            "Insufficient shares provided: need at least {}, got {}",
            threshold,
            shares.len()
        ));
    }

    let share_len = shares[0].data.len();
    for share in shares {
        if share.data.len() != share_len {
            return Err(anyhow!("Inconsistent share data lengths"));
        }
    }

    // Take the first `threshold` unique shares
    let mut used_shares: Vec<&ShamirShare> = Vec::with_capacity(threshold);
    for share in shares {
        if !used_shares.iter().any(|s| s.id == share.id) {
            used_shares.push(share);
            if used_shares.len() == threshold {
                break;
            }
        }
    }

    if used_shares.len() < threshold {
        return Err(anyhow!("Duplicate shares detected; insufficient unique shares"));
    }

    let mut secret_bytes = Vec::with_capacity(share_len);

    for byte_idx in 0..share_len {
        let mut secret_byte = 0u8;

        for (i, share_i) in used_shares.iter().enumerate() {
            let xi = share_i.id;
            let yi = share_i.data[byte_idx];

            let mut numerator = 1u8;
            let mut denominator = 1u8;

            for (j, share_j) in used_shares.iter().enumerate() {
                if i != j {
                    let xj = share_j.id;
                    numerator = Gf256::mul(numerator, xj);
                    denominator = Gf256::mul(denominator, Gf256::add(xi, xj));
                }
            }

            let basis = Gf256::div(numerator, denominator)?;
            let term = Gf256::mul(yi, basis);
            secret_byte = Gf256::add(secret_byte, term);
        }

        secret_bytes.push(secret_byte);
    }

    Ok(SecretBuffer::new(secret_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_3_of_5_threshold() -> Result<()> {
        let original_secret = SecretBuffer::from_str("MasterKey-256bit-EnterpriseHSM-Secret!");
        let threshold = 3;
        let total = 5;

        let shares = split_secret(&original_secret, threshold, total)?;
        assert_eq!(shares.len(), 5);

        // Any 3 shares should reconstruct
        let subset1 = vec![shares[0].clone(), shares[1].clone(), shares[2].clone()];
        let recovered1 = combine_shares(&subset1)?;
        assert_eq!(original_secret.as_bytes(), recovered1.as_bytes());

        let subset2 = vec![shares[1].clone(), shares[3].clone(), shares[4].clone()];
        let recovered2 = combine_shares(&subset2)?;
        assert_eq!(original_secret.as_bytes(), recovered2.as_bytes());

        // 2 shares should fail to provide the threshold count
        let subset_insufficient = vec![shares[0].clone(), shares[1].clone()];
        assert!(combine_shares(&subset_insufficient).is_err());

        Ok(())
    }

    #[test]
    fn test_share_formatting_roundtrip() -> Result<()> {
        let original_secret = SecretBuffer::from_str("TestPayloadKey123");
        let shares = split_secret(&original_secret, 2, 3)?;
        
        let formatted = shares[0].to_formatted_string();
        let parsed = ShamirShare::from_formatted_string(&formatted)?;
        assert_eq!(shares[0].id, parsed.id);
        assert_eq!(shares[0].data, parsed.data);
        Ok(())
    }
}
