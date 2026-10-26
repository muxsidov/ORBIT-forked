
// use log::*;

use ark_ec::{AdditiveGroup, PrimeGroup};
use ark_ff::{PrimeField, Field};
// This group has a prime order `r`, and is associated with a prime field `Fr`.
use ark_bn254::{g2, Bn254, Fq12 as TargetField, Fr as ScalarField, G1Projective as G, G2Projective as G2};
use ark_std::{Zero, UniformRand, ops::Mul};

use ark_ec::{pairing, pairing::Pairing, AffineRepr,  CurveGroup, models::short_weierstrass::{Affine, Projective}};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

use ark_secp256r1::{Config as Secp256r1Config, Fq as PBase, Fr as Secp256r1Scalar}; // Curve config, Base Field (Fq), Scalar Field (Fr)
type Secp256r1Projective = Projective<Secp256r1Config>;
type Secp256r1Affine = Affine<Secp256r1Config>;

use serde::{Serialize,Deserialize};
use serde_json;
use hex;

use aes::{cipher, Aes128};
use ctr::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use sha2::{Sha256, Digest};
use sha3::{Sha3_256, Digest as Sha3_Digest};

fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
      let mut bytes = vec![];
      a.serialize_with_mode(&mut bytes, Compress::Yes).map_err(serde::ser::Error::custom)?;
      s.serialize_bytes(&bytes)
}

fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error> where D: serde::de::Deserializer<'de> {
      let s: Vec<u8> = serde::de::Deserialize::deserialize(data)?;
      let a = A::deserialize_with_mode(s.as_slice(), Compress::Yes, Validate::Yes);
      a.map_err(serde::de::Error::custom)
}


#[derive(Serialize,Deserialize)]
struct ParamWaters {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    beta_secret: ScalarField,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    g: G,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    g_alpha: G,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    g2: G2,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    g2_beta: G2,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    h_vec: Vec<G>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    h_0: G,
}
#[derive(Serialize,Deserialize)]
struct ParamECDSA {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    secretkey: Secp256r1Scalar,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    publickey: Secp256r1Affine,
    param_water:ParamWaters
}


pub fn pairing() {
    // debug!("Pairing.");

    let mut rng = ark_std::test_rng();
    // Let's sample uniformly random group elements:
    let a = G::rand(&mut rng);
    let b = G::rand(&mut rng);

    // We can add elements, ...
    let c = a + b;
    // ... subtract them, ...
    let d = a - b;
    // ... and double them.
    assert_eq!(c + d, a.double());
    // We can also negate elements, ...
    let e = -a;
    // ... and check that negation satisfies the basic group law
    assert_eq!(e + a, G::zero());

    // We can also multiply group elements by elements of the corresponding scalar field
    // (an act known as *scalar multiplication*)
    let scalar = ScalarField::rand(&mut rng);
    let e = c.mul(scalar);
    let f = e.mul(scalar.inverse().unwrap());

    // debug!("{}", e);

    assert_eq!(f, c);
}

// TODO: remove cycle 
// fn decrypt(message: &[u8], key: &[u8]) -> Vec<u8>{
//     message
//     .iter()
//     .zip(key.iter().cycle()) 
//     .map(|(m, k)| m ^ k)    
//     .collect()              // Collect the results into a Vec<u8>
// }
fn decrypt(message: &[u8], key: &[u8], counter_iv: u8) -> Vec<u8>{
    let mut iv = [0x0; 16];
    iv[0] = counter_iv;
    let mut cipher = ctr::Ctr128BE::<Aes128>::new_from_slices(&key[..16], iv.as_slice()).expect("Key or IV length incorrect");
    let mut buffer =  message.to_vec();
    // Encrypt the message
    cipher.apply_keystream(&mut buffer);
    buffer
}
fn derive_key(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut combined = Vec::new();
    combined.extend_from_slice(a);
    combined.extend_from_slice(b);

    let mut hasher = Sha256::new();
    hasher.update(&combined);
    let hash_result = hasher.finalize();

    let mut hash_array = [0u8; 32]; // SHA-256 produces a 32-byte hash
    hash_array.copy_from_slice(&hash_result);
    hash_array
}

fn h_of_id(param: &ParamWaters, id: &str) -> G {
    id.bytes()
        .enumerate()
        .flat_map(|(byte_idx, byte)| {
            (0u8..8)
                .filter(move |bit| (byte >> bit) & 1 == 1)
                .map(move |bit| byte_idx * 8 + bit as usize)
        })
        .fold(param.h_0, |acc, i| acc + param.h_vec[i])
}

fn water_decrypt(param: &ParamWaters, id: &str, message: Vec<Vec<u8>>) -> pairing::PairingOutput<ark_ec::bn::Bn<ark_bn254::Config>>{
    let mut rng = ark_std::test_rng();

    let c1: pairing::PairingOutput<ark_ec::bn::Bn<ark_bn254::Config>> = pairing::PairingOutput::<ark_ec::bn::Bn<ark_bn254::Config>>::deserialize_compressed(&message[0][..]).unwrap();
    let c2 = G2::deserialize_compressed(&message[1][..]).unwrap();
    let c3 = G::deserialize_compressed(&message[2][..]).unwrap();

    // Derive decryption key from MSK (beta_secret is the master secret scalar in params).
    let rand_r = ScalarField::rand(&mut rng);
    let sk1 = (param.g_alpha * param.beta_secret) + (h_of_id(param, id) * rand_r);
    let sk3 = param.g2 * rand_r;
    let decrypt_m = c1 + Bn254::pairing(c3, sk3) - Bn254::pairing(sk1, c2);

    decrypt_m
}

pub fn evaluate_paymentbox(params:String, key_mat_enc:Vec<Vec<u8>>, enc_sig1_1:Vec<u8>, enc_sig2 :Vec<u8>, enc_sig3 :Vec<u8>, enc_sig1_vec:Vec<Vec<u8>>, shared_key:Vec<u8>, message_pattern:Vec<u8>, garble_message_size :usize, MAX_ITEM :usize, tag: String) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let par: ParamWaters = serde_json::from_str(&params).unwrap();
    let g = par.g;
    let g2 = par.g2;
    let g1_alpha = par.g_alpha;
    let g2_beta = par.g2_beta;
    let u_prime = par.h_0;
    let u_vec = &par.h_vec;

    let ITEM_SIZE = 32; // shared_key byte size

    assert!(MAX_ITEM ==256 || MAX_ITEM==2 || MAX_ITEM ==16);
    // let MAX_ITEM = 2; //Byte Variant MAX_ITEM=256
    let max_message_size = 40; //max_garble message size [<= max_message_size used in param_gen]
    assert_eq!(garble_message_size, message_pattern.len(), "Message size not equal!");

    // debug!("Evaluating AON box");
    // debug!("message_pattern len: {}", message_pattern.len());
    // debug!("key_mat_enc len: {}", key_mat_enc.len());
    // debug!("Shared_key len: {}", shared_key.len());

    let mut aon_key = [0 as u8;32];
    let mut counter = 0;
    let mut local_share_b = Vec::new();
    for message_val in message_pattern.clone(){
        let cur_key_ptr = (counter*ITEM_SIZE);

        // debug!("len of message key_mat_enc: {}", key_mat_enc[counter].len());

        let key_mat = decrypt(&key_mat_enc[(counter*MAX_ITEM)+ (message_val as usize)], &shared_key[cur_key_ptr..cur_key_ptr+ITEM_SIZE],0);
        // debug!("local_key/share_key {}, val: {} : {:?}", counter, message_val, shared_key[cur_key_ptr..cur_key_ptr+ITEM_SIZE].to_vec());
        // debug!("local_mat {}, val: {} : {:?}", counter, message_val, key_mat_enc[(counter*MAX_ITEM)+ (message_val as usize)].to_vec());
        // debug!("local_mat_dec {}, val: {} : {:?}", counter, message_val, key_mat);

        // debug!("decrypted key_mat: {}", cur_key_ptr);
        // debug!("len of message key_mat: {}", key_mat.len());

        // let aon_i: Vec<u8> = key_mat[..32].to_vec();
        for i in 0..32{
            aon_key[i] ^= key_mat[i]
        }
        // debug!("{}",counter);

        let local_share: Vec<u8> = key_mat[32..].to_vec();
        local_share_b.push(local_share);

        counter+=1;
    }

    let sig1_firstpart_dec = decrypt(&enc_sig1_1[..], &aon_key,1);
    let sig_1_hprime_masked = G::deserialize_compressed(&sig1_firstpart_dec[..]).unwrap();

    let sig2_dec = decrypt(&enc_sig2[..], &aon_key,2);
    let sig_2 = G::deserialize_compressed(&sig2_dec[..]).unwrap();

    let sig3_dec = decrypt(&enc_sig3[..], &aon_key,3);
    let sig_3 = G2::deserialize_compressed(&sig3_dec[..]).unwrap();

    let mut sig1_vec_masked = Vec::new();
    let mut counter=0;
    let mut final_sum = G::zero();
    for message_val in message_pattern.clone() {
        let dec_sign1_select = &mut decrypt(&enc_sig1_vec[(counter*MAX_ITEM)+ (message_val as usize)], &derive_key(&aon_key, &local_share_b[counter])[..],0);
            let sign1_select = G::deserialize_compressed(&dec_sign1_select[..]).unwrap();
        sig1_vec_masked.push(sign1_select);
        final_sum = final_sum + sign1_select;
        counter+=1;
    }
    //Finalizing Siganture
    let sig_1 = sig_1_hprime_masked + final_sum;

    {
        // debug!("Verifying Signature");
        fn bytes_to_bit_vec(bytes: Vec<u8>, max : u32) -> Vec<u8> {
            let mut bit_vec = Vec::with_capacity(bytes.len() * 8);
            
            for byte in bytes {
                for i in (0..max) { // Extract bits from MSB to LSB
                    bit_vec.push((byte >> i) & 1);
                }
            }
            bit_vec
        }

        let message_pattern_bit_decomposed = bytes_to_bit_vec(message_pattern, MAX_ITEM.ilog2());
        
        // Verify siganture
        let msg_hash = u_vec[..max_message_size].iter().enumerate().filter(|(i, x)| message_pattern_bit_decomposed[*i] == 1 ).fold(u_prime, |sum, (index, val)| sum + val); 
        // message_pattern[*i]
        // let msg_hash = u_vec[..garble_message_size].iter().enumerate().filter(|(i, x)| ((identity>>i) &0x1) == 1 ).fold(u_prime, |sum, (index, val)| sum + val); //TODO: enable correct bit setting

        let lhs = Bn254::pairing(g1_alpha, g2_beta) + Bn254::pairing(msg_hash, sig_3);
        let rhs = Bn254::pairing(sig_1, g2);

        // debug!("Asserting Waters Signature/IBE Key");
        assert_eq!(Bn254::pairing(g, sig_3),Bn254::pairing(sig_2, g2), "Random factor in dk2,dk3 does not match");
        assert_eq!(lhs,rhs);
        
    }

    let mut sk1_bytes = Vec::new();
    sig_1.serialize_compressed(&mut sk1_bytes).unwrap();
    let mut sk2_bytes = Vec::new();
    sig_2.serialize_compressed(&mut sk2_bytes).unwrap();
    let mut sk3_bytes = Vec::new();
    sig_3.serialize_compressed(&mut sk3_bytes).unwrap();
    (sk1_bytes, sk2_bytes, sk3_bytes)
}

pub fn evaluate_ecdsa(params:String, key_mat_enc:Vec<Vec<u8>>, rtag:Vec<Vec<u8>>,enc_r:Vec<u8>, enc_s0 :Vec<u8>, enc_svec:Vec<Vec<u8>>, shared_key:Vec<u8>, message_pattern:Vec<u8>, garble_message_size :usize, MAX_ITEM :usize){
    let par: ParamECDSA = serde_json::from_str(&params).unwrap();
    let pk = par.publickey;
    let generator: Secp256r1Projective = Projective::<Secp256r1Config>::generator();

    let ITEM_SIZE = 32; // shared_key byte size

    assert!(MAX_ITEM ==256 || MAX_ITEM==2 || MAX_ITEM ==16);
    // let MAX_ITEM = 2; //Byte Variant MAX_ITEM=256
    let max_message_size = 256; //max_garble message size [<= max_message_size used in param_gen]
    assert_eq!(garble_message_size, message_pattern.len());

    // debug!("Evaluating AON box");
    // debug!("message_pattern len: {}", message_pattern.len());
    // debug!("key_mat_enc len: {}", key_mat_enc.len());
    // debug!("Shared_key len: {}", shared_key.len());

    let mut aon_key = [0 as u8;32];
    let mut counter = 0;
    let mut local_share_b = Vec::new();
    for message_val in message_pattern.clone(){
        let cur_key_ptr = (counter*ITEM_SIZE);

        // debug!("len of message key_mat_enc: {}", key_mat_enc[counter].len());

        let key_mat = decrypt(&key_mat_enc[(counter*MAX_ITEM)+ (message_val as usize)], &shared_key[cur_key_ptr..cur_key_ptr+ITEM_SIZE],0);
        // debug!("local_key/share_key {}, val: {} : {:?}", counter, message_val, shared_key[cur_key_ptr..cur_key_ptr+ITEM_SIZE].to_vec());
        // debug!("local_mat {}, val: {} : {:?}", counter, message_val, key_mat_enc[(counter*MAX_ITEM)+ (message_val as usize)].to_vec());
        // debug!("local_mat_dec {}, val: {} : {:?}", counter, message_val, key_mat);

        // debug!("decrypted key_mat: {}", cur_key_ptr);
        // debug!("len of message key_mat: {}", key_mat.len());

        // let aon_i: Vec<u8> = key_mat[..32].to_vec();
        for i in 0..32{
            aon_key[i] ^= key_mat[i]
        }
        // debug!("{}",counter);

        let local_share: Vec<u8> = key_mat[32..].to_vec();
        local_share_b.push(local_share);

        counter+=1;
    }

    let tag = "001_000".to_string(); // ECDSA variant placeholder tag
    let rtag_dec = water_decrypt(&par.param_water, &tag, rtag);
    let mut hasher = Sha3_256::new();
    hasher.update(rtag_dec.to_string()); //Better to use serialzed byte instead. String for convenient.
    let hashed = hasher.finalize().to_vec();
    for j in 0..32{
        aon_key[j] ^= hashed[j];
    }

    // debug!("aon_key: {:?}", aon_key);
    let s0_dec = decrypt(&enc_s0[..], &aon_key,1);
    let s0_masked = Secp256r1Scalar::deserialize_compressed(&s0_dec[..]).unwrap();

    let r_dec = decrypt(&enc_r[..], &aon_key,2);
    let r_right = Secp256r1Scalar::deserialize_compressed(&r_dec[..]).unwrap();

    let mut sig1_vec_masked = Vec::new();
    let mut counter=0;
    let mut final_sum = Secp256r1Scalar::zero();
    for message_val in message_pattern.clone() {
        let dec_sign1_select = &mut decrypt(&enc_svec[(counter*MAX_ITEM)+ (message_val as usize)], &derive_key(&aon_key, &local_share_b[counter])[..],0);
            let sign1_select = Secp256r1Scalar::deserialize_compressed(&dec_sign1_select[..]).unwrap();
        sig1_vec_masked.push(sign1_select);
        final_sum = final_sum + sign1_select;
        counter+=1;
    }
    //Finalizing Siganture
    let s = s0_masked + final_sum;

    {
        // debug!("Verifying Signature");
        fn bytes_to_bit_vec(bytes: Vec<u8>, max : u32) -> Vec<u8> {
            let mut bit_vec = Vec::with_capacity(bytes.len() * 8);
            
            for byte in bytes {
                for i in (0..max) { // Extract bits from MSB to LSB
                    bit_vec.push((byte >> i) & 1);
                }
            }
            bit_vec
        }

        let message_pattern_bit_decomposed = bytes_to_bit_vec(message_pattern, MAX_ITEM.ilog2());
        
        // Verify siganture
        let mut poweroftwo = Secp256r1Scalar::ONE;
        let two = Secp256r1Scalar::ONE + Secp256r1Scalar::ONE;

        let msg_hash = (0..max_message_size).map(
            |index| {
                let ret = (index, poweroftwo);
                poweroftwo = poweroftwo * two;
                ret
            }
        ).filter(|(index, _val)| message_pattern_bit_decomposed[*index] == 1 ).fold(Secp256r1Scalar::ZERO, |sum, (_index,val)| sum + val); 
        // message_pattern[*i]
        // let msg_hash = u_vec[..garble_message_size].iter().enumerate().filter(|(i, x)| ((identity>>i) &0x1) == 1 ).fold(u_prime, |sum, (index, val)| sum + val); //TODO: enable correct bit setting

        let sinv = s.inverse().unwrap();
        let k_prime = ((generator * msg_hash) + (pk*r_right)) * sinv;
        let r_prime = (k_prime).into_affine().x().unwrap();
        let r_prime_right = Secp256r1Scalar::from_bigint(r_prime.into_bigint()).unwrap();

        // Printing garbled ECDSA key
        // debug!("r  = {:?}", r_right.into_bigint().to_string());
        // debug!("s  = {:?}", s.into_bigint().to_string());

        // debug!("Asserting ECDSA Signature");
        assert_eq!(r_right,r_prime_right,"Signature does not checkout");
    }

    // debug!("{}", "Siganture OK");

}

// Must match gs_link() in the server's lib.rs.
fn gs_link(sk2_bytes: &[u8], sk3_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ORBIT-GS-LINK");
    hasher.update(sk2_bytes);
    hasher.update(sk3_bytes);
    hasher.finalize().into()
}

#[derive(Deserialize)]
struct GsCircuit {
    base_key_mat: String,
    base_enc: String,
    key_mat0: Vec<String>,
    key_mat1: Vec<String>,
    slots_c0: Vec<String>,
    slots_c1: Vec<String>,
}

const GS_CHECK_LEN: usize = 16;

// Evaluate the GS circuit at bob_tag (see generate_gs_core in the server's lib.rs for the layout).
//
// shared_keys: flat byte array of (1 + numBits) × 32 bytes of AndroidKeyStore ECDH results:
//   [0..32]                 = branch key → decrypts base_key_mat → a_0
//   [(1+i)*32..(2+i)*32]    = key for bit i, against the epk selected by bob_tag bit i
//                             → decrypts key_mat{bit}[i] → (a_i || b_i)
// gwat_sk2, gwat_sk3: this coin's own activation key components from GWat; they form the link
// that the AoN key a = H(link) ⊕ a_0 ⊕ … ⊕ a_l depends on.
//
// Returns (sk1_bytes, sk2_bytes, sk3_bytes) — Bob's Waters activation key.
pub fn evaluate_gs(gs_circuit_json: &str, bob_tag: &str, shared_keys: &[u8], gwat_sk2: &[u8], gwat_sk3: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let gs: GsCircuit = serde_json::from_str(gs_circuit_json).map_err(|e| format!("invalid gs_circuit: {e}"))?;
    let unhex = |h: &str| hex::decode(h).map_err(|e| format!("invalid hex in gs_circuit: {e}"));

    let tag_bytes = bob_tag.as_bytes();
    let num_bits = tag_bytes.len() * 8;
    if num_bits != gs.slots_c0.len() {
        return Err(format!("tag has {} bits, circuit has {} (re-mint the coin)", num_bits, gs.slots_c0.len()));
    }
    if shared_keys.len() != (1 + num_bits) * 32 {
        return Err(format!("expected {} shared keys, got {} bytes", 1 + num_bits, shared_keys.len()));
    }
    let key_at = |idx: usize| &shared_keys[idx * 32..(idx + 1) * 32];
    let bit_of = |i: usize| (tag_bytes[i / 8] >> (i % 8)) & 1;

    // Recover the AoN key from the link, the branch share and one share per tag bit.
    let mut aon_key = derive_key(b"ORBIT-GS-AON", &gs_link(gwat_sk2, gwat_sk3));
    let a_0 = decrypt(&unhex(&gs.base_key_mat)?, key_at(0), 0);
    for j in 0..32 { aon_key[j] ^= a_0[j]; }
    let mut b_vals: Vec<Vec<u8>> = Vec::with_capacity(num_bits);
    for i in 0..num_bits {
        let key_mat = if bit_of(i) == 0 { &gs.key_mat0[i] } else { &gs.key_mat1[i] };
        if key_mat.is_empty() {
            return Err(format!("tag bit {} (byte {}) is fixed by the coin to {}: no slot for {} (denomination mismatch?)", i, i / 8, 1 - bit_of(i), bit_of(i)));
        }
        let a_b = decrypt(&unhex(key_mat)?, key_at(1 + i), 0);
        for j in 0..32 { aon_key[j] ^= a_b[j]; }
        b_vals.push(a_b[32..64].to_vec());
    }

    let base_plain = decrypt(&unhex(&gs.base_enc)?, &aon_key, 1);
    if base_plain[..GS_CHECK_LEN].iter().any(|&b| b != 0) {
        return Err("GS all-or-nothing key mismatch (wrong ECDH keys, or GWat key not from this coin)".into());
    }
    let base = &base_plain[GS_CHECK_LEN..];
    let g1 = |b: &[u8]| G::deserialize_with_mode(b, Compress::Yes, Validate::Yes).map_err(|e| format!("invalid G1: {e}"));
    let mut dk1 = g1(&base[0..32])?;
    let dk2 = g1(&base[32..64])?;
    let dk3 = G2::deserialize_with_mode(&base[64..128], Compress::Yes, Validate::Yes).map_err(|e| format!("invalid G2: {e}"))?;

    // Add the masked per-bit shares; the masks cancel only over one full selection.
    for i in 0..num_bits {
        let slot = if bit_of(i) == 0 { &gs.slots_c0[i] } else { &gs.slots_c1[i] };
        dk1 += g1(&decrypt(&unhex(slot)?, &derive_key(&aon_key, &b_vals[i]), 0))?;
    }

    let mut sk1_bytes = Vec::new();
    dk1.serialize_compressed(&mut sk1_bytes).unwrap();
    let mut sk2_bytes = Vec::new();
    dk2.serialize_compressed(&mut sk2_bytes).unwrap();
    let mut sk3_bytes = Vec::new();
    dk3.serialize_compressed(&mut sk3_bytes).unwrap();

    Ok((sk1_bytes, sk2_bytes, sk3_bytes))
}
