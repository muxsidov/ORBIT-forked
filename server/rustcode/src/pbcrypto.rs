
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
    // #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    // alpha_secret: ScalarField,
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

// Currently only support tag = 1
fn water_decrypt(param: &ParamWaters, id: u8, message: Vec<Vec<u8>>) -> pairing::PairingOutput<ark_ec::bn::Bn<ark_bn254::Config>>{
    assert_eq!(id, 1);
    let mut rng = ark_std::test_rng();

    let c1: pairing::PairingOutput<ark_ec::bn::Bn<ark_bn254::Config>> = pairing::PairingOutput::<ark_ec::bn::Bn<ark_bn254::Config>>::deserialize_compressed(&message[0][..]).unwrap();
    let c2 = G2::deserialize_compressed(&message[1][..]).unwrap();
    let c3 = G::deserialize_compressed(&message[2][..]).unwrap();

    // We assume key is given. Here we emulate the given key by computing it directly.
    let rand_r = ScalarField::rand(&mut rng);
    let sk1= (param.g_alpha*param.beta_secret) + ((param.h_0 + param.h_vec[0]) * rand_r);
    let sk3 = param.g2 * rand_r;
    let decrypt_m = c1 + Bn254::pairing(c3, sk3) - Bn254::pairing(sk1, c2);
    
    decrypt_m
}

pub fn evaluate_paymentbox(params:String, key_mat_enc:Vec<Vec<u8>>, rtag:Vec<Vec<u8>>, enc_sig1_1:Vec<u8>, enc_sig2 :Vec<u8>, enc_sig3 :Vec<u8>, enc_sig1_vec:Vec<Vec<u8>>, shared_key:Vec<u8>, message_pattern:Vec<u8>, garble_message_size :usize, MAX_ITEM :usize){
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

    let tag = 1; // NOTE: tag should be incrementally sampled/ randomly sampled instead, we hardcoded to 1
    let rtag_dec = water_decrypt(&par, tag, rtag);
    let mut hasher = Sha3_256::new();
    hasher.update(rtag_dec.to_string()); //Better to use serialzed byte instead. String for convenient.
    let hashed = hasher.finalize().to_vec();
    for j in 0..32{
        aon_key[j] ^= hashed[j];
    }

    // debug!("aon_key: {:?}", aon_key);
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

    // println!("Signature OK");
    // debug!("{}", "Siganture OK");

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

    let tag = 1; // NOTE: tag should be incrementally sampled/ randomly sampled instead, we hardcoded to 1
    let rtag_dec = water_decrypt(&par.param_water, tag, rtag);
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
        debug!("r  = {:?}", r_right.into_bigint().to_string());
        debug!("s  = {:?}", s.into_bigint().to_string());

        // debug!("Asserting ECDSA Signature");
        assert_eq!(r_right,r_prime_right,"Signature does not checkout");
    }

    // debug!("{}", "Siganture OK");

}
