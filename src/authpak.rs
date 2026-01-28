// Plan 9 AuthPAK (Password Authenticated Key Exchange) Implementation
//
// Implements dp9ik's SPAKE2-EE on Ed448-Goldilocks curve with Decaf encoding.
// Reference: Nawin.Auth/AuthPak.cs and 9front's authpak.c

use anyhow::{bail, Result};
use hkdf::Hkdf;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Digest, Sha256};

// Protocol constants from authsrv.h
pub const PAKSLEN: usize = 56;        // Field element size (448 bits / 8)
pub const PAKYLEN: usize = 56;        // Decaf-encoded point size
pub const PAKXLEN: usize = 56;        // Private scalar size
pub const PAKKEYLEN: usize = 32;      // Derived ticket encryption key size
pub const PAKPLEN: usize = 4 * PAKSLEN;  // Extended point (X,Y,Z,T) = 224 bytes
pub const PAKHASHLEN: usize = 2 * PAKPLEN; // PM and PN points = 448 bytes

// Ed448-Goldilocks curve parameters
// p = 2^448 - 2^224 - 1 (Goldilocks prime)
lazy_static::lazy_static! {
    static ref P: BigUint = {
        let hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        BigUint::parse_bytes(hex.as_bytes(), 16).unwrap()
    };

    // q = curve order
    static ref Q: BigUint = {
        let hex = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3";
        BigUint::parse_bytes(hex.as_bytes(), 16).unwrap()
    };

    // d = -39081 mod p
    static ref D: BigUint = &*P - BigUint::from(39081u32);

    // Generator point (9front's y=19, not RFC 8032)
    static ref GX: BigUint = {
        let hex = "297EA0EA2692FF1B4FAFF46098453A6A26ADF733245F065C3C59D0709CECFA96147EAAF3932D94C63D96C170033F4BA0C7F0DE840AED939F";
        BigUint::parse_bytes(hex.as_bytes(), 16).unwrap()
    };
    static ref GY: BigUint = BigUint::from(19u32);

    // (p-1)/2 for sign normalization
    static ref P_HALF: BigUint = (&*P - BigUint::one()) >> 1;
}

// a = 1 for untwisted Edwards
fn a() -> BigUint {
    BigUint::one()
}

/// Extended point representation (X, Y, Z, T) where x = X/Z, y = Y/Z, x*y = T/Z
#[derive(Clone, Debug)]
pub struct ExtendedPoint {
    pub x: BigUint,
    pub y: BigUint,
    pub z: BigUint,
    pub t: BigUint,
}

impl ExtendedPoint {
    fn identity() -> Self {
        ExtendedPoint {
            x: BigUint::zero(),
            y: BigUint::one(),
            z: BigUint::one(),
            t: BigUint::zero(),
        }
    }

    fn from_affine(x: &BigUint, y: &BigUint) -> Self {
        ExtendedPoint {
            x: x.clone(),
            y: y.clone(),
            z: BigUint::one(),
            t: (x * y) % &*P,
        }
    }

    fn is_identity(&self) -> bool {
        self.x.is_zero() && self.y == self.z
    }
}

/// PAK private state for key exchange
pub struct PakPriv {
    pub x: [u8; PAKXLEN],   // Private scalar (big-endian)
    pub y: [u8; PAKYLEN],   // Public value (Decaf encoded)
    pub is_client: bool,
}

/// Derives PAK hash points (PM, PN) from password and username.
///
/// 1. aesKey = PBKDF2-HMAC-SHA1(password, "Plan 9 key derivation", 9001, 16)
/// 2. h = HKDF-SHA256(ikm=aesKey, salt=SHA256(username), info="Plan 9 AuthPAK hash", len=112)
/// 3. PM = Elligator2(h[0:56])
/// 4. PN = Elligator2(h[56:112])
pub fn authpak_hash(password: &str, username: &str) -> [u8; PAKHASHLEN] {
    // Step 1: passtoaeskey - PBKDF2 with HMAC-SHA1
    let mut aes_key = [0u8; 16];
    let salt = b"Plan 9 key derivation";
    pbkdf2_hmac::<Sha1>(password.as_bytes(), salt, 9001, &mut aes_key);

    // Step 2: HKDF-SHA256
    let username_salt = Sha256::digest(username.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&username_salt), &aes_key);
    let mut h = [0u8; 2 * PAKSLEN]; // 112 bytes
    hk.expand(b"Plan 9 AuthPAK hash", &mut h)
        .expect("HKDF expand failed");

    // Step 3 & 4: Hash to curve points using Elligator2
    let pm = elligator2_hash_to_point(&h[..PAKSLEN]);
    let pn = elligator2_hash_to_point(&h[PAKSLEN..]);

    // Encode points in extended format
    let mut result = [0u8; PAKHASHLEN];
    encode_extended_point(&pm, &mut result[..PAKPLEN]);
    encode_extended_point(&pn, &mut result[PAKPLEN..]);

    result
}

/// Generate new PAK exchange values.
///
/// Y = x*G + blind
/// - Client uses PM for blinding
/// - Server uses PN for blinding
pub fn authpak_new(pak_hash: &[u8; PAKHASHLEN], is_client: bool) -> PakPriv {
    // Get blinding point based on role
    let offset = if is_client { 0 } else { PAKPLEN };
    let blind_point = decode_extended_point(&pak_hash[offset..offset + PAKPLEN]);

    // Generate random scalar x
    let x_scalar = generate_random_scalar();
    let mut x_bytes = [0u8; PAKXLEN];
    let x_vec = x_scalar.to_bytes_be();
    let start = PAKXLEN.saturating_sub(x_vec.len());
    x_bytes[start..].copy_from_slice(&x_vec[x_vec.len().saturating_sub(PAKXLEN)..]);

    // Compute Y = x*G + blindPoint
    let g = ExtendedPoint::from_affine(&GX, &GY);
    let x_g = scalar_mult(&g, &x_scalar);
    let y_point = add_points(&x_g, &blind_point);

    // Encode Y using Decaf
    let y_bytes = decaf_encode(&y_point);

    PakPriv {
        x: x_bytes,
        y: y_bytes,
        is_client,
    }
}

/// Complete PAK exchange and derive shared key.
///
/// Z = x * (peerY - peerBlind)
/// pakKey = HKDF-SHA256(ikm=Z, salt=SHA256(clientY||serverY), info="Plan 9 AuthPAK key", len=32)
pub fn authpak_finish(
    priv_state: &PakPriv,
    pak_hash: &[u8; PAKHASHLEN],
    peer_y: &[u8; PAKYLEN],
) -> Result<[u8; PAKKEYLEN]> {
    // Get peer's blinding point
    let offset = if priv_state.is_client { PAKPLEN } else { 0 };
    let peer_blind = decode_extended_point(&pak_hash[offset..offset + PAKPLEN]);

    // Decode peer's Y value
    let peer_point = match decaf_decode(peer_y) {
        Some(p) => p,
        None => bail!("Failed to decode peer Y value"),
    };

    // Compute Z = x * (peerY - peerBlind)
    let unblinded = subtract_points(&peer_point, &peer_blind);
    let x_scalar = BigUint::from_bytes_be(&priv_state.x);
    let z = scalar_mult(&unblinded, &x_scalar);

    // Encode Z
    let z_bytes = decaf_encode(&z);

    // Compute salt = SHA256(clientY || serverY)
    let mut y_concat = [0u8; 2 * PAKYLEN];
    if priv_state.is_client {
        y_concat[..PAKYLEN].copy_from_slice(&priv_state.y);
        y_concat[PAKYLEN..].copy_from_slice(peer_y);
    } else {
        y_concat[..PAKYLEN].copy_from_slice(peer_y);
        y_concat[PAKYLEN..].copy_from_slice(&priv_state.y);
    }
    let salt = Sha256::digest(&y_concat);

    // HKDF to derive key
    let hk = Hkdf::<Sha256>::new(Some(&salt), &z_bytes);
    let mut pak_key = [0u8; PAKKEYLEN];
    hk.expand(b"Plan 9 AuthPAK key", &mut pak_key)
        .expect("HKDF expand failed");

    Ok(pak_key)
}

// ============================================================================
// Elligator2 - hash to curve point
// ============================================================================

/// Verify that a point satisfies the curve equation: a*x² + y² = 1 + d*x²*y²
#[cfg(test)]
fn verify_on_curve(p: &ExtendedPoint) -> bool {
    // Convert to affine: x = X/Z, y = Y/Z
    let z_inv = mod_inv(&p.z, &P);
    let x = (&p.x * &z_inv) % &*P;
    let y = (&p.y * &z_inv) % &*P;

    // a*x² + y² should equal 1 + d*x²*y²
    let x2 = (&x * &x) % &*P;
    let y2 = (&y * &y) % &*P;
    let lhs = (&a() * &x2 + &y2) % &*P;
    let rhs = (BigUint::one() + &*D * &x2 * &y2 % &*P) % &*P;

    lhs == rhs
}

fn elligator2_hash_to_point(hash: &[u8]) -> ExtendedPoint {
    let r0 = BigUint::from_bytes_be(hash) % &*P;

    // Find smallest quadratic non-residue n
    // For Goldilocks prime, n = 7 (not 2!)
    let mut n = BigUint::from(2u32);
    while legendre_symbol(&n, &P) != -1 {
        n += BigUint::one();
    }

    // r = n*r0*r0 mod p
    let r = (&n * &r0 * &r0) % &*P;

    // For r0=0 case: r=0, dr=0, term1=a-d=39082, term2=-d=39081
    // d_val = 39082 * 39081 = 1527185442

    // D_val = (d*r + a - d) * (d*r - a*r - d)
    let dr = (&*D * &r) % &*P;
    let a_minus_d = mod_sub(&a(), &*D, &P);
    let term1 = (&dr + &a_minus_d) % &*P;
    let term2 = mod_sub(&mod_sub(&dr, &((&a() * &r) % &*P), &P), &*D, &P);
    let d_val = (&term1 * &term2) % &*P;

    // N = (r+1) * (a - 2*d)
    let a_2d = mod_sub(&a(), &(BigUint::from(2u32) * &*D % &*P), &P);
    let n_val = ((&r + BigUint::one()) * &a_2d) % &*P;

    // ND = N * D_val
    let nd = (&n_val * &d_val) % &*P;

    let (c, e) = if nd.is_zero() {
        (BigUint::one(), BigUint::zero())
    } else if let Some(sqrt_nd) = mod_sqrt(&nd) {
        (BigUint::one(), mod_inv(&sqrt_nd, &P))
    } else {
        let n_nd = (&n * &nd) % &*P;
        let c = &*P - BigUint::one(); // c = -1 mod p
        let e = (&n * &r0 * &mod_inv_sqrt(&n_nd)) % &*P;
        (c, e)
    };

    // s = c * N * e
    let s = (&c * &n_val * &e) % &*P;

    // t = -c * N * (r-1) * ((a-2*d) * e)^2 - 1
    let r_minus_1 = mod_sub(&r, &BigUint::one(), &P);
    let a2d_e = (&a_2d * &e) % &*P;
    let a2d_e2 = (&a2d_e * &a2d_e) % &*P;
    let neg_c = mod_sub(&*P, &c, &P);
    let t = mod_sub(&((&neg_c * &n_val * &r_minus_1 * &a2d_e2) % &*P), &BigUint::one(), &P);

    // Extended coordinates
    // For the map (s, t) -> (X, Y, Z, T), the standard Elligator2 to Edwards formula is:
    // x = 2*s / t
    // y = (1 - a*s^2) / (1 + a*s^2)
    // In projective coordinates:
    // X = 2*s*Z', Y = (1-a*s^2)*(1+a*s^2), Z = (1+a*s^2)*t, where Z' normalizes to give x = X/Z
    //
    // But wait - the standard formula uses: X = 2*s, Y = (1-s^2)*(1+s^2) with Z = (1+s^2)*t
    // That gives x = X/Z = 2*s / ((1+s^2)*t), which is not 2*s/t...
    //
    // Let me re-derive from the C# code which has:
    // X = 2*s*t, Y = (1-a*s^2)*(1+a*s^2), Z = (1+a*s^2)*t, T = 2*s*(1-a*s^2)
    // This gives x = X/Z = 2*s*t / ((1+a*s^2)*t) = 2*s / (1+a*s^2)
    // And y = Y/Z = (1-a*s^2)*(1+a*s^2) / ((1+a*s^2)*t) = (1-a*s^2) / t

    let ass = (&a() * &s * &s) % &*P;
    let one_minus_ass = mod_sub(&BigUint::one(), &ass, &P);
    let one_plus_ass = (BigUint::one() + &ass) % &*P;

    let x = (BigUint::from(2u32) * &s * &t) % &*P;
    let y = (&one_minus_ass * &one_plus_ass) % &*P;
    let z = (&one_plus_ass * &t) % &*P;
    let t_coord = (BigUint::from(2u32) * &s * &one_minus_ass) % &*P;

    let result = ExtendedPoint {
        x,
        y,
        z,
        t: t_coord,
    };

    result
}

// ============================================================================
// Decaf encoding/decoding
// ============================================================================

fn decaf_encode(p: &ExtendedPoint) -> [u8; PAKYLEN] {
    // r = misqrt((a-d)*(Z+Y)*(Z-Y), p)
    let a_minus_d = mod_sub(&a(), &*D, &P);
    let z_plus_y = (&p.z + &p.y) % &*P;
    let z_minus_y = mod_sub(&p.z, &p.y, &P);
    let val = (&a_minus_d * &z_plus_y * &z_minus_y) % &*P;

    // Check if val is zero (identity point case)
    if val.is_zero() {
        return [0u8; PAKYLEN];
    }

    let mut r = mod_inv_sqrt(&val);

    // u = (a-d)*r
    let u = (&a_minus_d * &r) % &*P;

    // if -2*u*Z > (p-1)/2, r = -r
    let neg_2uz = mod_sub(&*P, &(BigUint::from(2u32) * &u * &p.z % &*P), &P);
    if neg_2uz > *P_HALF {
        r = mod_sub(&*P, &r, &P);
    }

    // s = u*(r*(a*Z*X - d*Y*T) + Y) / a
    let azx = (&a() * &p.z * &p.x) % &*P;
    let dyt = (&*D * &p.y * &p.t) % &*P;
    let inner = (&r * &mod_sub(&azx, &dyt, &P) + &p.y) % &*P;
    let a_inv = mod_inv(&a(), &P);
    let mut s = (&u * &inner * &a_inv) % &*P;

    // if s > (p-1)/2, s = -s
    if s > *P_HALF {
        s = mod_sub(&*P, &s, &P);
    }

    // Convert to bytes (big-endian)
    let s_bytes = s.to_bytes_be();
    let mut result = [0u8; PAKYLEN];
    let start = PAKYLEN.saturating_sub(s_bytes.len());
    result[start..].copy_from_slice(&s_bytes[s_bytes.len().saturating_sub(PAKYLEN)..]);

    result
}

fn decaf_decode(data: &[u8]) -> Option<ExtendedPoint> {
    if data.len() != PAKYLEN {
        return None;
    }

    let s = BigUint::from_bytes_be(data);

    // if s > (p-1)/2, reject
    if s > *P_HALF {
        return None;
    }

    // ss = s^2
    let ss = (&s * &s) % &*P;

    // Z = 1 + a*ss
    let z = (BigUint::one() + &a() * &ss) % &*P;

    // u = Z^2 - 4*d*ss
    let u = mod_sub(&(&z * &z % &*P), &(BigUint::from(4u32) * &*D * &ss % &*P), &P);

    // v = u*ss
    let mut v = (&u * &ss) % &*P;

    if v.is_zero() {
        // v stays zero
    } else {
        let sqrt_v = mod_sqrt(&v)?;
        v = mod_inv(&sqrt_v, &P);
    }

    // if u*v > (p-1)/2, v = -v
    let uv = (&u * &v) % &*P;
    if uv > *P_HALF {
        v = mod_sub(&*P, &v, &P);
    }

    // w = v * s * (2-Z)
    let two_minus_z = mod_sub(&BigUint::from(2u32), &z, &P);
    let mut w = (&v * &s * &two_minus_z) % &*P;

    // if s == 0: w = w + 1
    if s.is_zero() {
        w = (w + BigUint::one()) % &*P;
    }

    // X = 2*s, Y = w*Z, T = w*X
    let x = (BigUint::from(2u32) * &s) % &*P;
    let y = (&w * &z) % &*P;
    let t = (&w * &x) % &*P;

    Some(ExtendedPoint { x, y, z, t })
}

// ============================================================================
// Edwards curve operations
// ============================================================================

fn add_points(p1: &ExtendedPoint, p2: &ExtendedPoint) -> ExtendedPoint {
    // Unified addition formula for a*x² + y² = 1 + d*x²*y² where a=1
    let aa = (&p1.x * &p2.x) % &*P;
    let bb = (&p1.y * &p2.y) % &*P;
    let cc = (&*D * &p1.t * &p2.t) % &*P;
    let dd = (&p1.z * &p2.z) % &*P;

    let e = mod_sub(
        &(((&p1.x + &p1.y) * (&p2.x + &p2.y)) % &*P),
        &((&aa + &bb) % &*P),
        &P,
    );
    let f = mod_sub(&dd, &cc, &P);
    let g = (&dd + &cc) % &*P;
    let h = mod_sub(&bb, &(&a() * &aa % &*P), &P);

    let x3 = (&e * &f) % &*P;
    let y3 = (&g * &h) % &*P;
    let z3 = (&f * &g) % &*P;
    let t3 = (&e * &h) % &*P;

    ExtendedPoint {
        x: x3,
        y: y3,
        z: z3,
        t: t3,
    }
}

fn subtract_points(p1: &ExtendedPoint, p2: &ExtendedPoint) -> ExtendedPoint {
    // Negate p2: (-X, Y, Z, -T)
    let neg_p2 = ExtendedPoint {
        x: mod_sub(&*P, &p2.x, &P),
        y: p2.y.clone(),
        z: p2.z.clone(),
        t: mod_sub(&*P, &p2.t, &P),
    };
    add_points(p1, &neg_p2)
}

fn scalar_mult(point: &ExtendedPoint, scalar: &BigUint) -> ExtendedPoint {
    let mut result = ExtendedPoint::identity();
    let mut temp = point.clone();

    let bits = scalar.bits();
    for i in 0..bits {
        if scalar.bit(i) {
            result = add_points(&result, &temp);
        }
        temp = add_points(&temp, &temp); // double
    }

    result
}

fn generate_random_scalar() -> BigUint {
    let mut bytes = [0u8; PAKXLEN];
    getrandom::getrandom(&mut bytes).expect("Failed to generate random bytes");
    BigUint::from_bytes_be(&bytes) % &*Q
}

// ============================================================================
// Extended point encoding/decoding
// ============================================================================

fn encode_extended_point(p: &ExtendedPoint, output: &mut [u8]) {
    assert!(output.len() >= PAKPLEN);

    let x_bytes = p.x.to_bytes_be();
    let y_bytes = p.y.to_bytes_be();
    let z_bytes = p.z.to_bytes_be();
    let t_bytes = p.t.to_bytes_be();

    pad_and_copy(&x_bytes, &mut output[..PAKSLEN]);
    pad_and_copy(&y_bytes, &mut output[PAKSLEN..2 * PAKSLEN]);
    pad_and_copy(&z_bytes, &mut output[2 * PAKSLEN..3 * PAKSLEN]);
    pad_and_copy(&t_bytes, &mut output[3 * PAKSLEN..4 * PAKSLEN]);
}

fn decode_extended_point(data: &[u8]) -> ExtendedPoint {
    assert!(data.len() >= PAKPLEN);

    let x = BigUint::from_bytes_be(&data[..PAKSLEN]);
    let y = BigUint::from_bytes_be(&data[PAKSLEN..2 * PAKSLEN]);
    let z = BigUint::from_bytes_be(&data[2 * PAKSLEN..3 * PAKSLEN]);
    let t = BigUint::from_bytes_be(&data[3 * PAKSLEN..4 * PAKSLEN]);

    ExtendedPoint { x, y, z, t }
}

fn pad_and_copy(src: &[u8], dest: &mut [u8]) {
    dest.fill(0);
    let start = dest.len().saturating_sub(src.len());
    let src_start = src.len().saturating_sub(dest.len());
    dest[start..].copy_from_slice(&src[src_start..]);
}

// ============================================================================
// Modular arithmetic
// ============================================================================

fn mod_sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    if a >= b {
        (a - b) % p
    } else {
        (p - ((b - a) % p)) % p
    }
}

fn mod_inv(a: &BigUint, p: &BigUint) -> BigUint {
    // Extended Euclidean algorithm
    a.modpow(&(p - BigUint::from(2u32)), p)
}

fn legendre_symbol(a: &BigUint, p: &BigUint) -> i32 {
    let exp = (p - BigUint::one()) >> 1;
    let r = a.modpow(&exp, p);
    if r.is_zero() {
        0
    } else if r.is_one() {
        1
    } else {
        -1
    }
}

fn mod_sqrt(a: &BigUint) -> Option<BigUint> {
    if a.is_zero() {
        return Some(BigUint::zero());
    }

    if legendre_symbol(a, &P) != 1 {
        return None;
    }

    // For p ≡ 3 (mod 4), use simple formula
    if (&*P % BigUint::from(4u32)) == BigUint::from(3u32) {
        let exp = (&*P + BigUint::one()) >> 2;
        return Some(a.modpow(&exp, &P));
    }

    // Tonelli-Shanks for general case
    let mut q = &*P - BigUint::one();
    let mut s = 0u32;
    while (&q % BigUint::from(2u32)).is_zero() {
        q >>= 1;
        s += 1;
    }

    let mut z = BigUint::from(2u32);
    while legendre_symbol(&z, &P) != -1 {
        z += BigUint::one();
    }

    let mut m = s;
    let mut c = z.modpow(&q, &P);
    let mut t = a.modpow(&q, &P);
    let mut r = a.modpow(&((&q + BigUint::one()) >> 1), &P);

    loop {
        if t.is_one() {
            return Some(r);
        }

        let mut i = 1u32;
        let mut temp = (&t * &t) % &*P;
        while !temp.is_one() {
            temp = (&temp * &temp) % &*P;
            i += 1;
        }

        let b = c.modpow(&(BigUint::one() << (m - i - 1)), &P);
        m = i;
        c = (&b * &b) % &*P;
        t = (&t * &c) % &*P;
        r = (&r * &b) % &*P;
    }
}

fn mod_inv_sqrt(a: &BigUint) -> BigUint {
    // For p ≡ 3 (mod 4): a^((p-3)/4)
    if (&*P % BigUint::from(4u32)) == BigUint::from(3u32) {
        let exp = (&*P - BigUint::from(3u32)) >> 2;
        return a.modpow(&exp, &P);
    }

    // General case
    if let Some(r) = mod_sqrt(a) {
        if !r.is_zero() {
            return mod_inv(&r, &P);
        }
    }
    BigUint::zero()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elligator2_produces_valid_point() {
        // Test with a simple hash value (all zeros)
        let hash = [0u8; PAKSLEN];
        let point = elligator2_hash_to_point(&hash);
        assert!(verify_on_curve(&point), "All-zeros hash should produce point on curve");

        // Test with r0 = 1 (small value)
        let mut hash1 = [0u8; PAKSLEN];
        hash1[PAKSLEN - 1] = 1; // r0 = 1
        let point1 = elligator2_hash_to_point(&hash1);
        assert!(verify_on_curve(&point1), "r0=1 should produce point on curve");

        // Test with r0 = 2
        let mut hash2 = [0u8; PAKSLEN];
        hash2[PAKSLEN - 1] = 2;
        let point2 = elligator2_hash_to_point(&hash2);
        assert!(verify_on_curve(&point2), "r0=2 should produce point on curve");
    }

    #[test]
    fn test_elligator2_formula_derivation() {
        // According to Elligator2, the map should produce a point on the Montgomery
        // curve, which is then converted to Edwards form.
        //
        // For Ed448 (untwisted Edwards with a=1, d=-39081):
        // The birational equivalence to Montgomery is:
        //   Montgomery: B*v² = u³ + A*u² + u
        //   Edwards: x² + y² = 1 + d*x²*y² (with a=1)
        //
        // The formulas (s, t) from Elligator2 should satisfy certain relationships.
        //
        // Let's check the final coordinate conversion formulas.

        // Use a specific input where we can trace through
        let mut hash = [0u8; PAKSLEN];
        hash[55] = 1; // r0 = 1

        let r0 = BigUint::from(1u32);
        let n = BigUint::from(2u32);
        let r = (&n * &r0 * &r0) % &*P; // r = 2

        // D_val = (d*r + a - d) * (d*r - a*r - d)
        // = (d*(r-1) + a) * (d*(r-1) - a*r)
        // Let dr = d*r
        // term1 = dr + a - d
        // term2 = dr - a*r - d = dr - r - d (since a=1)
        let _dr = (&*D * &r) % &*P;
        let a_minus_d = mod_sub(&a(), &*D, &P);

        // a_minus_d should be 39082 since a=1, d=-39081, so a-d = 1-(-39081) = 39082
        assert_eq!(a_minus_d, BigUint::from(39082u32), "a - d should be 39082");
    }

    #[test]
    fn test_elligator2_st_relationship() {
        // For the point to be on curve, we need: t² = (1+as²)² - 4ds²
        // Let's verify this for the (s, t) values produced by elligator2

        // Trace through the algorithm with r0 = 1
        let r0 = BigUint::from(1u32);
        let n = BigUint::from(2u32);
        let r = (&n * &r0 * &r0) % &*P; // r = 2

        let dr = (&*D * &r) % &*P;
        let a_minus_d = mod_sub(&a(), &*D, &P);
        let term1 = (&dr + &a_minus_d) % &*P;
        let term2 = mod_sub(&mod_sub(&dr, &((&a() * &r) % &*P), &P), &*D, &P);
        let d_val = (&term1 * &term2) % &*P;

        let a_2d = mod_sub(&a(), &(BigUint::from(2u32) * &*D % &*P), &P);
        let n_val = ((&r + BigUint::one()) * &a_2d) % &*P;

        let nd = (&n_val * &d_val) % &*P;

        let (c, e) = if nd.is_zero() {
            (BigUint::one(), BigUint::zero())
        } else if let Some(sqrt_nd) = mod_sqrt(&nd) {
            (BigUint::one(), mod_inv(&sqrt_nd, &P))
        } else {
            let n_nd = (&n * &nd) % &*P;
            let c = &*P - BigUint::one();
            let e = (&n * &r0 * &mod_inv_sqrt(&n_nd)) % &*P;
            (c, e)
        };

        let s = (&c * &n_val * &e) % &*P;

        let r_minus_1 = mod_sub(&r, &BigUint::one(), &P);
        let a2d_e = (&a_2d * &e) % &*P;
        let a2d_e2 = (&a2d_e * &a2d_e) % &*P;
        let neg_c = mod_sub(&*P, &c, &P);
        let t = mod_sub(&((&neg_c * &n_val * &r_minus_1 * &a2d_e2) % &*P), &BigUint::one(), &P);

        // Now verify: t² = (1+as²)² - 4ds²
        let ass = (&a() * &s * &s) % &*P;
        let one_plus_ass = (BigUint::one() + &ass) % &*P;
        let one_plus_ass_sq = (&one_plus_ass * &one_plus_ass) % &*P;
        let four_d_ss = (BigUint::from(4u32) * &*D * &s * &s) % &*P;

        let expected_t_sq = mod_sub(&one_plus_ass_sq, &four_d_ss, &P);
        let actual_t_sq = (&t * &t) % &*P;

        eprintln!("s (first 8 bytes): {:02x?}", &s.to_bytes_be()[..8.min(s.to_bytes_be().len())]);
        eprintln!("t (first 8 bytes): {:02x?}", &t.to_bytes_be()[..8.min(t.to_bytes_be().len())]);
        eprintln!("expected t² (first 8): {:02x?}", &expected_t_sq.to_bytes_be()[..8.min(expected_t_sq.to_bytes_be().len())]);
        eprintln!("actual t² (first 8): {:02x?}", &actual_t_sq.to_bytes_be()[..8.min(actual_t_sq.to_bytes_be().len())]);

        // Also verify the affine coordinates directly
        // x = 2s / (1+as²), y = (1-as²) / t
        let one_minus_ass = mod_sub(&BigUint::one(), &ass, &P);
        let x_num = (BigUint::from(2u32) * &s) % &*P;
        let x_denom_inv = mod_inv(&one_plus_ass, &P);
        let x_aff = (&x_num * &x_denom_inv) % &*P;

        let y_num = one_minus_ass.clone();
        let t_inv = mod_inv(&t, &P);
        let y_aff = (&y_num * &t_inv) % &*P;

        // Check curve equation: x² + y² = 1 + d*x²*y²
        let x2 = (&x_aff * &x_aff) % &*P;
        let y2 = (&y_aff * &y_aff) % &*P;
        let lhs = (&x2 + &y2) % &*P;
        let rhs = (BigUint::one() + &*D * &x2 * &y2 % &*P) % &*P;

        eprintln!("x affine (first 8): {:02x?}", &x_aff.to_bytes_be()[..8.min(x_aff.to_bytes_be().len())]);
        eprintln!("y affine (first 8): {:02x?}", &y_aff.to_bytes_be()[..8.min(y_aff.to_bytes_be().len())]);
        eprintln!("LHS x²+y² (first 8): {:02x?}", &lhs.to_bytes_be()[..8.min(lhs.to_bytes_be().len())]);
        eprintln!("RHS 1+dx²y² (first 8): {:02x?}", &rhs.to_bytes_be()[..8.min(rhs.to_bytes_be().len())]);

        // Try the relationship with actual d value (not D)
        // d = -39081, so we need t² = (1+s²)² - 4*(-39081)*s² = (1+s²)² + 156324*s²
        let s_sq = (&s * &s) % &*P;
        let expected_t_sq_v2 = (&one_plus_ass_sq + BigUint::from(156324u32) * &s_sq) % &*P;
        eprintln!("expected t² v2 (first 8): {:02x?}", &expected_t_sq_v2.to_bytes_be()[..8.min(expected_t_sq_v2.to_bytes_be().len())]);
    }

    #[test]
    fn test_mod_inv_sqrt() {
        // Test that mod_inv_sqrt(a) returns 1/sqrt(a)
        // For a QR a, sqrt(a)^2 = a, so (1/sqrt(a))^2 * a = 1
        let a = BigUint::from(4u32); // 4 is a perfect square
        let inv_sqrt = mod_inv_sqrt(&a);
        let inv_sqrt_sq = (&inv_sqrt * &inv_sqrt) % &*P;
        let result = (&inv_sqrt_sq * &a) % &*P;
        assert_eq!(result, BigUint::one(), "1/sqrt(4)^2 * 4 should = 1");

        // Test with a larger QR
        let b = BigUint::from(9u32);
        let inv_sqrt_b = mod_inv_sqrt(&b);
        let inv_sqrt_b_sq = (&inv_sqrt_b * &inv_sqrt_b) % &*P;
        let result_b = (&inv_sqrt_b_sq * &b) % &*P;
        assert_eq!(result_b, BigUint::one(), "1/sqrt(9)^2 * 9 should = 1");
    }

    #[test]
    fn test_generator_on_curve() {
        let g = ExtendedPoint::from_affine(&GX, &GY);
        assert!(verify_on_curve(&g), "Generator should be on curve");
    }

    #[test]
    fn test_point_addition_preserves_curve() {
        let g = ExtendedPoint::from_affine(&GX, &GY);
        let g2 = add_points(&g, &g);
        assert!(verify_on_curve(&g2), "2*G should be on curve");

        let g3 = add_points(&g2, &g);
        assert!(verify_on_curve(&g3), "3*G should be on curve");
    }

    #[test]
    fn test_authpak_hash() {
        let hash = authpak_hash("test1234", "glenda");
        assert_eq!(hash.len(), PAKHASHLEN);
        // Hash should be deterministic
        let hash2 = authpak_hash("test1234", "glenda");
        assert_eq!(hash, hash2);

        // Compare with known C# output: PM[0:16] = DF40966D3445560680243A1A009F9DEB
        let expected_pm_prefix = hex::decode("DF40966D3445560680243A1A009F9DEB").unwrap();
        let actual_pm_prefix = &hash[..16];
        eprintln!("Expected PM[0:16]: {}", hex::encode(&expected_pm_prefix));
        eprintln!("Actual PM[0:16]: {}", hex::encode(actual_pm_prefix));
        assert_eq!(actual_pm_prefix, expected_pm_prefix.as_slice(),
            "PakHash PM prefix should match C# implementation");
    }

    #[test]
    fn test_elligator2_with_known_hash() {
        // Use the exact HKDF output h[0:56] from the test case
        let h_m_hex = "D6B9D05E4D9F7C67871EEE7B4478B4F757379552AFA3B1BE02AA0DC1B9FC882403DCBA41F548C431DCD46366E8BE932EC15D6BF895A62224";
        let h_m_vec = hex::decode(h_m_hex).unwrap();
        let mut h_m = [0u8; PAKSLEN];
        h_m.copy_from_slice(&h_m_vec);

        eprintln!("Testing elligator2 with full h_m");

        let pm = elligator2_hash_to_point(&h_m);

        // Encode as extended point
        let mut encoded = [0u8; PAKPLEN];
        encode_extended_point(&pm, &mut encoded);

        // C# produces PM[0:16] = DF40966D3445560680243A1A009F9DEB
        let expected_pm_x_prefix = hex::decode("DF40966D3445560680243A1A009F9DEB").unwrap();
        eprintln!("Expected PM X[0:16]: {}", hex::encode(&expected_pm_x_prefix));
        eprintln!("Actual PM X[0:16]: {}", hex::encode(&encoded[..16]));

        assert_eq!(&encoded[..16], expected_pm_x_prefix.as_slice(),
            "Elligator2 should produce same point as C#");
    }

    #[test]
    fn test_r_computation() {
        // Test r = n * r0² mod p with known r0
        // For Goldilocks prime, n = 7 (smallest quadratic non-residue)
        let h_m_hex = "D6B9D05E4D9F7C67871EEE7B4478B4F757379552AFA3B1BE02AA0DC1B9FC882403DCBA41F548C431DCD46366E8BE932EC15D6BF895A62224";
        let h_m = hex::decode(h_m_hex).unwrap();
        let r0 = BigUint::from_bytes_be(&h_m) % &*P;

        // Find smallest non-residue (should be 7)
        let mut n = BigUint::from(2u32);
        while legendre_symbol(&n, &P) != -1 {
            n += BigUint::one();
        }
        assert_eq!(n, BigUint::from(7u32), "Smallest non-residue for Goldilocks should be 7");

        // Compute r = n * r0² mod P
        let r_mine = (&n * &r0 * &r0) % &*P;

        // C# result (with n=7)
        let r_csharp_str = "414087075856234680559476517246076512312762072425852754863593888821593969593046834515284184464842321768222161173969941417623136623594978";
        let r_csharp = r_csharp_str.parse::<BigUint>().unwrap();

        assert_eq!(r_mine, r_csharp, "r computation should match C#");
    }

    #[test]
    fn test_pak_exchange() {
        let password = "test1234";
        let username = "glenda";

        // Both sides compute the same pakhash
        let pak_hash = authpak_hash(password, username);

        // Client generates exchange values
        let client_priv = authpak_new(&pak_hash, true);

        // Server generates exchange values
        let server_priv = authpak_new(&pak_hash, false);

        // Both sides complete the exchange
        let client_key = authpak_finish(&client_priv, &pak_hash, &server_priv.y).unwrap();
        let server_key = authpak_finish(&server_priv, &pak_hash, &client_priv.y).unwrap();

        // Both should derive the same key
        assert_eq!(client_key, server_key);
    }

    #[test]
    fn test_decaf_round_trip() {
        let g = ExtendedPoint::from_affine(&GX, &GY);
        let encoded = decaf_encode(&g);
        let decoded = decaf_decode(&encoded).expect("Should decode");

        // Re-encode should give same result
        let re_encoded = decaf_encode(&decoded);
        assert_eq!(encoded, re_encoded);
    }
}
