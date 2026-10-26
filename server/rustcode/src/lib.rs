// mod bbgwild;
// mod waters;
mod pbcrypto;

use core::hash;
use std::convert::identity;
use std::io::Read;
use std::ptr::hash;
use std::str::FromStr;
use std::string;

use aes::cipher::typenum::Integer;
use pyo3::{exceptions::PyOSError, types::PyByteArray};
use pyo3::prelude::*;
use pyo3::types::{PyInt, PyString};
use pyo3::types::PyBytes;
use pyo3::types::PyList;
use pyo3::wrap_pyfunction;
use pyo3_log;

use sha3::{Sha3_256, Digest as Sha3_Digest};

use ark_ec::{bls12::G1Projective, pairing, AdditiveGroup, PrimeGroup,  CurveGroup, models::short_weierstrass::{Affine, Projective}};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_bn254::{g2, Bn254, Fq12 as TargetField, Fr as ScalarField, G1Projective as G, G2Projective as G2};
// use ark_secp256r1::{G_GENERATOR_X, G_GENERATOR_Y};
use ark_secp256r1::{Config as Secp256r1Config, Fq as PBase, Fr as Secp256r1Scalar}; // Curve config, Base Field (Fq), Scalar Field (Fr)
use ark_std::{ops::Mul, rand::Rng, UniformRand, Zero};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{BigInt};

type Secp256r1Projective = Projective<Secp256r1Config>;
type Secp256r1Affine = Affine<Secp256r1Config>;

use aes::{cipher, Aes128};
use ctr::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use sha2::{Sha256, Digest};

// use p256::{
//     elliptic_curve::sec1::ToEncodedPoint,
//     SecretKey, PublicKey,
// ;

// use aes::cipher::{
//     BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
//     generic_array::GenericArray,
// };

use serde::{Serialize,Deserialize};
use serde_json;
use serde_json::json;
use hex;
use base64::{engine::general_purpose, Engine as _};

// use rand_core::OsRng;


use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
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


#[derive(Serialize,Deserialize)]
struct PaymentBox {
    tag: String,
    sig3: Vec<u8>,
    sig2: Vec<u8>,
    sig1_firstpart: Vec<u8>,
    sig1_vec: Vec<Vec<u8>>,
    key_mat_enc: Vec<Vec<u8>>
}

#[derive(Serialize,Deserialize)]
struct ECDSABox {
    tag: String,
    rtag: Vec<Vec<u8>>,
    r: Vec<u8>,
    s0: Vec<u8>,
    s_vec: Vec<Vec<u8>>,
    key_mat_enc: Vec<Vec<u8>>
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
fn concat_two(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut combined = Vec::new();
    combined.extend_from_slice(a);
    combined.extend_from_slice(b);
    combined
}

// #[pyfunction]
// fn compute_signature() -> PyResult<isize>{
//     Ok(1)
// }



// Default Message Size is 256
#[pyfunction]
fn generate_params_waters() -> PyResult<String> {
    let mut rng = ark_std::test_rng();
    let alpha_secret = ScalarField::rand(&mut rng);
    // let beta_secret = ScalarField::rand(&mut rng);
    let beta_secret = alpha_secret;

    let g = G::rand(&mut rng);
    let g_alpha = g * alpha_secret; //g^alpha
        
    let g2 = G2::rand(&mut rng); //g2
    let g2_beta = g2 * beta_secret; //g2^beta

    let max_message_size = 256;

    let u_prime = G::rand(&mut rng);
    let u_vec = (0..max_message_size).map(|_: i32| G::rand(&mut rng)).collect::<Vec<_>>();

    //Mapping to Original Water syntax
    // g_alpha -> g2
    // beta_secret -> alpha
    // g2 -> g
    // g2_beta -> g1 or g^alpha
    let params = ParamWaters {
        // alpha_secret: alpha_secret,
        beta_secret: beta_secret,
        g: g,
        g_alpha: g_alpha, //msk
        g2: g2,
        g2_beta: g2_beta,
        h_vec: u_vec,
        h_0: u_prime,
    };

    let json_string = serde_json::to_string(&params).unwrap();

    Ok(json_string)
} 


#[pyfunction]
fn generate_params_ecdsa(param_water_string :String) -> PyResult<String> {
    let mut rng = ark_std::test_rng();

    let water_param: ParamWaters = serde_json::from_str(&param_water_string).unwrap();

    let generator_proj: Secp256r1Projective = Projective::<Secp256r1Config>::generator();
    let generator_affine: Secp256r1Affine = generator_proj.into_affine();
  
    // Generate a secret key
    let private_key_scalar = Secp256r1Scalar::rand(&mut rng);
    let public_key_proj: Secp256r1Projective = generator_proj * private_key_scalar;
    let public_key_affine = public_key_proj.into_affine();

    let params = ParamECDSA {
        secretkey: private_key_scalar,
        publickey: public_key_affine,
        param_water:water_param
    };

    let json_string = serde_json::to_string(&params).unwrap();

    Ok(json_string)
} 

// OTP
// fn encrypt(message: &[u8], key: &[u8]) -> Vec<u8>{
//     message
//     .iter()
//     .zip(key.iter().cycle()) 
//     .map(|(m, k)| m ^ k)    
//     .collect()              // Collect the results into a Vec<u8>
// }
fn encrypt(message: &[u8], key: &[u8], counter_iv: u8) -> Vec<u8>{
    let mut iv = [0x0; 16];
    iv[0] = counter_iv;
    let mut cipher = ctr::Ctr128BE::<Aes128>::new_from_slices(&key[..16], iv.as_slice()).expect("Key or IV length incorrect");
    let mut buffer =  message.to_vec();
    // Encrypt the message
    cipher.apply_keystream(&mut buffer);
    buffer
}
#[pyfunction]
fn test_encrypt(message: String, key: String){
    let ciphertext = encrypt(message.as_bytes(), key.as_bytes(),0);
    println!("Ciphertext: {:?}, len: {:?}", ciphertext, ciphertext.len());

    let plaintext = encrypt(&ciphertext, key.as_bytes(),0);
    println!("Plaintext: {:?}, len: {:?}", plaintext, plaintext.len());
    assert_eq!(message.as_bytes(), plaintext.as_slice());
    println!("Message {:?}, Recovered: {:?}", message, String::from_utf8(plaintext).unwrap());
}

fn usize_to_fixed_bit_array_8(value: usize) -> [bool; 8] {
    let mut bits = [false; 8];
    for i in 0..8 {
        bits[i] = (value & (1 << i)) != 0;
    }
    bits
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

fn water_encrypt(param: &ParamWaters, id: &str, message: pairing::PairingOutput<ark_ec::bn::Bn<ark_bn254::Config>>) -> Vec<Vec<u8>>{
    let mut rng = ark_std::test_rng();
    let rand_t = ScalarField::rand(&mut rng);
    let c1 = Bn254::pairing(param.g_alpha, param.g2_beta)*rand_t + message;
    let c2 = param.g2 * rand_t;
    let c3 = h_of_id(param, id) * rand_t;

    let mut c1_byte = Vec::new();
    c1.serialize_compressed(&mut c1_byte).unwrap();
    let mut c2_byte = Vec::new();
    c2.serialize_compressed(&mut c2_byte).unwrap();
    let mut c3_byte = Vec::new();
    c3.serialize_compressed(&mut c3_byte).unwrap();

    let mut c = Vec::new();
    c.push(c1_byte);
    c.push(c2_byte);
    c.push(c3_byte);
    c
}

// NOTE: Important to first trim h_vec to 40 else overflow into h_vec will capture not intended identity.
#[pyfunction]
fn water_unlock_solidity(param_str: String, id: usize) -> PyResult<String>{
    let param: ParamWaters = serde_json::from_str(&param_str).unwrap();
    let mut rng = ark_std::test_rng();

    let rand_r = ScalarField::rand(&mut rng);
    let sum_u_ = param.h_vec[0..40].iter().enumerate().filter(|(i, x)| ((id>>i) &0x1) == 1 ).fold(G::ZERO, |sum, (index, val)| sum + val); //NOTE: Endianness
    // for i in 0..40{
    //     println!("(id>>{}) &0x1) == 1, {},",i, (id>>i) &0x1);
    // }
    // let collect = param.h_vec[0..40].iter().enumerate().filter(|(i, x)| ((id>>i) &0x1) == 1 ).count();
    // println!("collec leng: {}", collect);

    // let sum_u_ = param.h_vec[0];

    let sk1= (param.g_alpha*param.beta_secret) + ((param.h_0 + sum_u_) * rand_r);
    let sk2= param.g * rand_r;
    let sk3 = param.g2 * rand_r;

    // sanity check signature
    let lhs = Bn254::pairing(param.g_alpha, param.g2_beta) + Bn254::pairing((param.h_0 + sum_u_), sk3);
    let rhs = Bn254::pairing(sk1, param.g2);
    assert_eq!(lhs,rhs);
    assert_eq!(Bn254::pairing(sk2,param.g2),Bn254::pairing(param.g, sk3));

    let mut ret = g1_to_uncompressed_json(&sk1, "sk1");
    merge_json(&mut ret, &g1_to_uncompressed_json(&sk2, "sk2"));
    merge_json(&mut ret, &g2_to_uncompressed_json(&sk3, "sk3"));
    merge_json(&mut ret, &g1_to_uncompressed_json(&param.g_alpha, "g1a"));
    merge_json(&mut ret, &g2_to_uncompressed_json(&param.g2_beta, "g2b"));
    merge_json(&mut ret, &g2_to_uncompressed_json(&param.g2, "g2"));
    merge_json(&mut ret, &g1_to_uncompressed_json(&param.g, "g"));
    merge_json(&mut ret, &g1_to_uncompressed_json(&param.h_0, "u0"));
    merge_json(&mut ret, &g1_to_uncompressed_json(&(param.h_0 + sum_u_), "u_vec_sum"));
    merge_json(&mut ret, &g1_vec_to_uncompressed_json(param.h_vec[..40].to_vec(), "u_vec"));

    Ok(ret.to_string())
}

// Derive a fresh Waters activation key (ak2) for a string tag using the master secret.
// Returns {"sk1":"<hex>","sk2":"<hex>","sk3":"<hex>"} in compressed form (same format
// as evaluate_paymentbox output so the Android app can store it directly as a card).
#[pyfunction]
fn water_derive_ak(param_str: String, tag: String) -> PyResult<String> {
    let param: ParamWaters = serde_json::from_str(&param_str).unwrap();
    let mut rng = ark_std::test_rng();

    let rand_r = ScalarField::rand(&mut rng);
    let h_tag = h_of_id(&param, &tag);

    let sk1 = (param.g_alpha * param.beta_secret) + (h_tag * rand_r);
    let sk2 = param.g * rand_r;
    let sk3 = param.g2 * rand_r;

    let lhs = Bn254::pairing(param.g_alpha, param.g2_beta) + Bn254::pairing(h_tag, sk3);
    let rhs = Bn254::pairing(sk1, param.g2);
    assert_eq!(lhs, rhs, "water_derive_ak: pairing check 1 failed");
    assert_eq!(Bn254::pairing(sk2, param.g2), Bn254::pairing(param.g, sk3), "water_derive_ak: pairing check 2 failed");

    let mut sk1_bytes = Vec::new();
    sk1.serialize_compressed(&mut sk1_bytes).unwrap();
    let mut sk2_bytes = Vec::new();
    sk2.serialize_compressed(&mut sk2_bytes).unwrap();
    let mut sk3_bytes = Vec::new();
    sk3.serialize_compressed(&mut sk3_bytes).unwrap();

    let sk1_hex: String = sk1_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let sk2_hex: String = sk2_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let sk3_hex: String = sk3_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    Ok(format!("{{\"sk1\":\"{}\",\"sk2\":\"{}\",\"sk3\":\"{}\"}}", sk1_hex, sk2_hex, sk3_hex))
}

fn pylist_to_bytes(list: &'_ Bound<'_, PyList>) -> Vec<Vec<u8>> {
    list.iter()
        .map(|item| item.downcast::<PyBytes>().unwrap().as_bytes().to_vec())
        .collect()
}

// Secret that ties a coin's GS circuit to its GWat circuit: only a device that evaluated GWat
// (spending its 5 ECDH uses) learns sk2 = g^r, sk3 = g2^r and can derive the GS all-or-nothing
// key. Plays the role of the paper's rtag from Activate. Must match gs_link() in the Android
// pbcrypto.rs.
fn gs_link(sk2_bytes: &[u8], sk3_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ORBIT-GS-LINK");
    hasher.update(sk2_bytes);
    hasher.update(sk3_bytes);
    hasher.finalize().into()
}

#[pyfunction]
fn garble_waters(param: String, shared_key_list:  &'_ Bound<'_, PyList>, garble_message_size: usize, MAX_ITEM: usize, tag: String) -> PyResult<String> {
    let (paybox_json, _) = garble_waters_core(&param, pylist_to_bytes(shared_key_list), garble_message_size, MAX_ITEM, tag);
    Ok(paybox_json)
}

// Mint one coin: GWat (activation) and GS (re-delegation) circuits, linked so that GS can only be
// opened after GWat. Returns (gwat_json, gs_json).
#[pyfunction]
fn garble_waters_with_gs(
    param: String,
    shared_key_list: &'_ Bound<'_, PyList>,
    garble_message_size: usize,
    MAX_ITEM: usize,
    tag: String,
    gs_shared_key_list: &'_ Bound<'_, PyList>,
    tag_bits: usize,
    denomination: u32,
) -> PyResult<(String, String)> {
    if denomination > 999 {
        return Err(PyOSError::new_err(format!("denomination {denomination} does not fit the 3-digit DDD field")));
    }
    let (paybox_json, link) = garble_waters_core(&param, pylist_to_bytes(shared_key_list), garble_message_size, MAX_ITEM, tag);
    let gs_json = generate_gs_core(&param, pylist_to_bytes(gs_shared_key_list), tag_bits, denomination, &link);
    Ok((paybox_json, gs_json))
}

// Returns (PaymentBox JSON, gs_link of its sk2/sk3).
fn garble_waters_core(param: &str, shared_key_byte: Vec<Vec<u8>>, garble_message_size: usize, MAX_ITEM: usize, tag: String) -> (String, [u8; 32]) {
    let test = false;
    let param: ParamWaters = serde_json::from_str(param).unwrap();
    // Per-coin secrets (r, masks, AoN shares): must be fresh. test_rng() is a fixed seed and
    // would give every coin the same r and masks.
    let mut rng = rand::thread_rng();
    let g = param.g;
    let g_alpha = param.g_alpha;
    let g2 = param.g2;
    let g2_beta = param.g2_beta;

    let msk = param.g_alpha * param.beta_secret;

    let max_message_size = 40; //max_garble message size [<= max_message_size used in param_gen]
    assert_eq!(max_message_size, (MAX_ITEM.ilog2() as usize) * garble_message_size);
    // let garble_message_size = 40; //max_garble message size [<= max_message_size used in param_gen]
    let u_prime = param.h_0;
    let u_vec = &param.h_vec;

    let rand_r = ScalarField::rand(&mut rng);

    let mut running_rand_ss = G::zero();

    let mut sig1_vec_masked = vec![];
    
    for i in 0..garble_message_size {     
        let new_share = G::rand(&mut rng);
        running_rand_ss += new_share;
        sig1_vec_masked.push(new_share);

        let start_ptr = i*MAX_ITEM;

        if MAX_ITEM==2{
            sig1_vec_masked.push( u_vec[i]*(rand_r) + new_share);
        }
        else{
            let step = MAX_ITEM.ilog2() as usize;
            let subset_uvec = &u_vec[i*step..(i+1)*step];
            for j in 1..MAX_ITEM {
                let mut array  = usize_to_fixed_bit_array_8(j);
                // println!(" {}:,{:?}", j, array);
                let summed = subset_uvec.into_iter().enumerate().filter(|(index, val)| array[*index]== true).fold(G::zero(), |sum, (index, val)| sum+((*val)*rand_r));
                sig1_vec_masked.push( summed+ new_share);
            }
        }
    }

    let mask_ss =  - running_rand_ss; 
    let sig_1_hprime_masked = msk + (u_prime*rand_r) + mask_ss; //(msk * u'^r) + rand_mask
    let sig_2 = g * rand_r;
    let sig_3 = g2 * rand_r;
    if test
    {
        if MAX_ITEM==2{
            //TODO: ((identity>>(i/step)) &0x1) might be wrong because we will >> more than 64 and leads to some error.

            // Signing Message
            let identity = 10; //1010
            let step = 2;
            let final_sum: ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config> = sig1_vec_masked.iter().enumerate().filter(|(i, x)| ((identity>>(i/step)) &0x1) == i%step ).fold(G::zero(), |sum, (index, val)| sum + val); 

            let sig_1 = sig_1_hprime_masked + final_sum;
    
            // Verify siganture
            let msg_hash = u_vec[..garble_message_size].iter().enumerate().filter(|(i, x)| ((identity>>i) &0x1) == 1 ).fold(u_prime, |sum, (index, val)| sum + val);
            let lhs = Bn254::pairing(g_alpha, g2_beta) + Bn254::pairing(msg_hash, sig_3);
            let rhs = Bn254::pairing(sig_1, g2);
            assert_eq!(lhs,rhs,"Siganture cannot be verified");
        }
        else{
            //Test for 10000000,10000000,...
            let final_sum: ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config> = sig1_vec_masked.iter().enumerate().filter(|(i, x)| i%256==1 ).fold(G::zero(), |sum, (index, val)| sum + val); 
            let sig_1 = sig_1_hprime_masked + final_sum;            
    
            // Verify siganture
            let msg_hash = u_vec[..max_message_size].iter().enumerate().filter(|(i, x)| i%8==0).fold(u_prime, |sum, (index, val)| sum + val);
            let lhs = Bn254::pairing(g_alpha, g2_beta) + Bn254::pairing(msg_hash, sig_3);
            let rhs = Bn254::pairing(sig_1, g2);
            assert_eq!(lhs,rhs,"Siganture cannot be verified");
        }
    }

    // TODO: enable one-use key benchmark need to make the aon_key_bytes come from chosen_key_bytes, then encrypt correctly.
    // All keys are derived using method of AoN at server.py
    let mut aon_key_share_bytes: Vec<Vec<u8>> = Vec::new();
    let mut aon_key_bytes: [u8;32] = [0 as u8;32];
    for i in 0..garble_message_size{
        let mut random_bytes = [0u8; 32];  //Sample local randomness secret
        rng.fill(&mut random_bytes);
        aon_key_share_bytes.push(random_bytes.to_vec());

        for j in 0..32{
            aon_key_bytes[j] ^= random_bytes[j];
        }
    }

    
    // encrypt sig1_vecs with chosen_keys.
    let mut enc_sig1_vec = Vec::new();
    let mut key_mat_vec: Vec<Vec<u8>> = Vec::new();
    for i in 0..garble_message_size{
        for j in 0..MAX_ITEM{
            let mut sig_1_item = Vec::new();
            sig1_vec_masked[(i*MAX_ITEM)+j].serialize_compressed(&mut sig_1_item).unwrap();
            let localkey = (shared_key_byte[(i*MAX_ITEM) + j].clone());
            let mut random_bytes = [0u8; 32];  //Sample local randomness secret
            rng.fill(&mut random_bytes);
            // println!("local_key, {}, {}, {:?}", i,j,localkey);

            key_mat_vec.push(encrypt(&concat_two(&aon_key_share_bytes[i], &random_bytes), localkey.as_slice(),0)); // enc_localkey (a_i || b_i,{value_index})

            // println!("local_key_mat, {}, {}, {:?}", i,j,&concat_two(&aon_key_share_bytes[i], &random_bytes));

            let final_localkeymat = derive_key(&aon_key_bytes, &random_bytes);
            enc_sig1_vec.push(encrypt(&sig_1_item[..], &final_localkeymat,0)); 
            // println!("enc_sig1_vec: i:{:?}, j:{:?}, len: {:?}", i,j,enc_sig1_vec.len());
        }
    }

    // println!("aon_key {:?}", aon_key_bytes);


    // encrypt sig2, sig_1_hprime_masked with aon key.
    let mut sig_1_firstpart = Vec::new();
    sig_1_hprime_masked.serialize_compressed(&mut sig_1_firstpart).unwrap();
    let enc_sig1_firstpart = encrypt(&sig_1_firstpart[..], &aon_key_bytes,1);

    let mut sig_2_byte = Vec::new();
    sig_2.serialize_compressed(&mut sig_2_byte).unwrap();
    let enc_sig2 = encrypt(&sig_2_byte[..], &aon_key_bytes,2);

    let mut sig_3_byte = Vec::new();
    sig_3.serialize_compressed(&mut sig_3_byte).unwrap();
    let enc_sig3 = encrypt(&sig_3_byte[..], &aon_key_bytes,3);

    let pay_box = PaymentBox {
        tag: tag,
        sig3: enc_sig3,
        sig2: enc_sig2,
        sig1_firstpart: enc_sig1_firstpart,
        sig1_vec: enc_sig1_vec,
        key_mat_enc: key_mat_vec
    };

    let json_string = serde_json::to_string(&pay_box).unwrap();
    // let encoded = general_purpose::URL_SAFE_NO_PAD.encode(&json_string);
    // let _test_deserialize: PaymentBox = serde_json::from_str(&json_string).unwrap();
  
    (json_string, gs_link(&sig_2_byte, &sig_3_byte))
}

// Generate a GS circuit: a linear garbled binary circuit that evaluates to the Waters
// activation key for one tag chosen at re-delegation time (paper Fig. 4, Waters branch).
// Called via garble_waters_with_gs so the circuit is linked to the coin's GWat circuit.
//
// shared_keys: 1 branch key + tag_bits*2 bit-slot keys (bit=0 key, bit=1 key per bit).
// link: gs_link(sk2, sk3) of the coin's GWat key.
//
// Two layers, as in the paper:
//   - Masking: random G1 shares s_1..s_l with s_0 = -Σ s_i. Slot (i,0) holds s_i, slot (i,1)
//     holds u_i·r + s_i, the base holds msk + u'·r + s_0. A single slot reveals nothing about
//     u_i·r; only one full selection of slots sums to a valid dk1.
//   - All-or-nothing: AoN key a = H(link) ⊕ a_0 ⊕ a_1 ⊕ … ⊕ a_l. The branch slot carries a_0,
//     each bit slot (i,β) carries (a_i || b_iβ) under its ECDH key; the share in slot (i,β) is
//     encrypted under H(a || b_iβ) and the base under a. Nothing decrypts unless the GWat
//     link, the branch and one slot per bit were all opened. With nusecount = 5 (GWat) + 1 + l,
//     opening both slots of any bit leaves some other bit unopened, so no key can be derived.
//
// Fixed tag bits: the tag is "UUU_DDD_CCC" (11 ASCII bytes, bit i = byte i/8, bit i%8 LSB-first
// ↦ h_vec[i]). Bytes 3..8 ("_DDD_") are fixed by the coin and get only the slot matching the coin's
// real bit; the other slot is "" so indices and shapes stay the same. UUU and CCC keep both slots
// because Alice picks the recipient's tag offline.
//   Why it's secure: forging a fixed bit 0→1 needs the slot u_i·r + s_i, i.e. h_i·r from g^r
//   (CDH); forging 1→0 needs the mask s_i alone, which is never given out. The garbled key
//   material for the missing slot doesn't exist, so the evaluator cannot even open it.
//
// Output JSON (Alice's device adds the epk separately):
//   {base_key_mat, base_enc, key_mat0[i], key_mat1[i], slots_c0[i], slots_c1[i]}  (hex)
//
// Evaluation (Android JNI evaluate_gs):
//   a = H(link) ⊕ Dec_kbranch(base_key_mat) ⊕ Σ_i a_i,   (a_i, b_i) = Dec_ki(key_mat{btag_i}[i])
//   dk1 = Dec_a(base_enc).dk1 + Σ_i Dec_{H(a||b_i)}(slots_c{btag_i}[i])   (G1 addition)
//   dk2, dk3 = from Dec_a(base_enc)
const GS_CHECK_LEN: usize = 16;
const GS_FIXED_BYTES: std::ops::Range<usize> = 3..8; // "_DDD_" in "UUU_DDD_CCC"

fn generate_gs_core(param_str: &str, shared_keys: Vec<Vec<u8>>, tag_bits: usize, denomination: u32, link: &[u8; 32]) -> String {
    let param: ParamWaters = serde_json::from_str(param_str).unwrap();
    let mut rng = rand::thread_rng();
    assert_eq!(shared_keys.len(), 1 + tag_bits * 2, "GS shared_keys count mismatch");
    assert_eq!(tag_bits, 88, "GS tag layout \"UUU_DDD_CCC\" needs 88 bits");
    let fixed_bytes = format!("_{:03}_", denomination).into_bytes();
    // Some(real bit) for a fixed position, None for a free (UUU / CCC) one.
    let fixed_bit = |i: usize| -> Option<usize> {
        GS_FIXED_BYTES.contains(&(i / 8)).then(|| ((fixed_bytes[i / 8 - GS_FIXED_BYTES.start] >> (i % 8)) & 1) as usize)
    };

    let rand_r = ScalarField::rand(&mut rng);
    let msk = param.g_alpha * param.beta_secret;
    let dk2 = param.g * rand_r;
    let dk3 = param.g2 * rand_r;

    // Masking shares, summing to zero with s_0 folded into the base.
    let shares: Vec<G> = (0..tag_bits).map(|_| G::rand(&mut rng)).collect();
    let s_0 = -shares.iter().fold(G::zero(), |acc, s| acc + s);
    let base_dk1 = msk + (param.h_0 * rand_r) + s_0;

    // AoN shares a_0 (branch), a_1..a_l (bits); a = H(link) ⊕ all shares.
    let mut aon_key = derive_key(b"ORBIT-GS-AON", link);
    let mut aon_shares: Vec<[u8; 32]> = Vec::new();
    for _ in 0..(1 + tag_bits) {
        let mut a_i = [0u8; 32];
        rng.fill(&mut a_i);
        for j in 0..32 { aon_key[j] ^= a_i[j]; }
        aon_shares.push(a_i);
    }

    // base_plaintext = zero check value (16B) || base_dk1 (32B) || dk2 (32B) || dk3 (64B) = 144 bytes.
    // The check value lets the evaluator detect a wrong AoN key instead of returning a garbage key.
    let mut base_plaintext = vec![0u8; GS_CHECK_LEN];
    base_dk1.serialize_compressed(&mut base_plaintext).unwrap();
    dk2.serialize_compressed(&mut base_plaintext).unwrap();
    dk3.serialize_compressed(&mut base_plaintext).unwrap();
    let base_key_mat = encrypt(&aon_shares[0], &shared_keys[0], 0);
    let base_enc = encrypt(&base_plaintext, &aon_key, 1);

    let mut key_mat: [Vec<String>; 2] = [Vec::new(), Vec::new()];
    let mut slots: [Vec<String>; 2] = [Vec::new(), Vec::new()];
    for i in 0..tag_bits {
        let a_i = &aon_shares[1 + i];
        let bit1_share = param.h_vec[i] * rand_r + shares[i];
        for (bit, share) in [shares[i], bit1_share].iter().enumerate() {
            if fixed_bit(i).is_some_and(|real| real != bit) {
                key_mat[bit].push(String::new());
                slots[bit].push(String::new());
                continue;
            }
            let mut b_ib = [0u8; 32];
            rng.fill(&mut b_ib);
            let k_ib = &shared_keys[1 + 2 * i + bit];
            key_mat[bit].push(hex::encode(encrypt(&concat_two(a_i, &b_ib), k_ib, 0)));

            let mut share_bytes = Vec::new();
            share.serialize_compressed(&mut share_bytes).unwrap();
            slots[bit].push(hex::encode(encrypt(&share_bytes, &derive_key(&aon_key, &b_ib), 0)));
        }
    }
    let [key_mat0, key_mat1] = key_mat;
    let [slots_c0, slots_c1] = slots;

    json!({
        "base_key_mat": hex::encode(base_key_mat),
        "base_enc": hex::encode(base_enc),
        "key_mat0": key_mat0,
        "key_mat1": key_mat1,
        "slots_c0": slots_c0,
        "slots_c1": slots_c1,
    }).to_string()
}

// Test-only: evaluate a GS circuit with the server-side copy of evaluate_gs (identical to the
// Android JNI one), so the full mint → activate → re-delegate pipeline can be tested in Python.
// shared_keys: flat bytes, branch key followed by one key per tag bit (chosen by the caller).
#[pyfunction]
fn test_evaluate_gs(gs_circuit_json: String, bob_tag: String, shared_keys: Vec<u8>, gwat_sk2: Vec<u8>, gwat_sk3: Vec<u8>) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    pbcrypto::evaluate_gs(&gs_circuit_json, &bob_tag, &shared_keys, &gwat_sk2, &gwat_sk3)
        .map_err(|e| PyOSError::new_err(e))
}

// Test-only: verify a Waters key against a tag in the GS string encoding (ASCII bytes,
// LSB-first within each byte, bit i ↦ h_vec[i]). Checks both Waters equations.
#[pyfunction]
fn test_verify_gs_key(param_str: String, tag: String, sk1: Vec<u8>, sk2: Vec<u8>, sk3: Vec<u8>) -> PyResult<bool> {
    let param: ParamWaters = serde_json::from_str(&param_str).unwrap();
    let (Ok(sk1), Ok(sk2), Ok(sk3)) = (
        G::deserialize_compressed(&sk1[..]),
        G::deserialize_compressed(&sk2[..]),
        G2::deserialize_compressed(&sk3[..]),
    ) else { return Ok(false) };
    let mut h = param.h_0;
    for (byte_idx, byte) in tag.as_bytes().iter().enumerate() {
        for bit in 0..8 {
            if (byte >> bit) & 1 == 1 { h += param.h_vec[byte_idx * 8 + bit]; }
        }
    }
    let check1 = Bn254::pairing(param.g, sk3) == Bn254::pairing(sk2, param.g2);
    let check2 = Bn254::pairing(param.g_alpha, param.g2_beta) + Bn254::pairing(h, sk3) == Bn254::pairing(sk1, param.g2);
    Ok(check1 && check2)
}

// Alice runs this on her device to garble a Waters activation key for Bob without the server.
// osk_sk1/sk2/sk3 are Alice's recovered key bytes (proof of delegation authority).
// tag2 is the identity for Bob's new key — must differ from Alice's tag to prevent reuse.
#[pyfunction]
fn garble_redelegate(param_str: String, osk_sk1: Vec<u8>, osk_sk2: Vec<u8>, osk_sk3: Vec<u8>, shared_key_list: &'_ Bound<'_, PyList>, garble_message_size: usize, MAX_ITEM: usize, tag2: String) -> PyResult<String> {
    let param: ParamWaters = serde_json::from_str(&param_str).unwrap();
    let mut rng = ark_std::test_rng();
    let g = param.g;
    let g_alpha = param.g_alpha;
    let g2 = param.g2;
    let g2_beta = param.g2_beta;

    // Verify Alice holds a valid Waters key (proof of delegation authority).
    let osk_sk1_pt = G::deserialize_compressed(&osk_sk1[..]).expect("invalid sk1");
    let osk_sk2_pt = G::deserialize_compressed(&osk_sk2[..]).expect("invalid sk2");
    let osk_sk3_pt = G2::deserialize_compressed(&osk_sk3[..]).expect("invalid sk3");
    assert_eq!(Bn254::pairing(g, osk_sk3_pt), Bn254::pairing(osk_sk2_pt, g2), "osk: dk2/dk3 mismatch");

    let msk = param.g_alpha * param.beta_secret;
    let max_message_size = 40;
    assert_eq!(max_message_size, (MAX_ITEM.ilog2() as usize) * garble_message_size);
    let u_prime = param.h_0;
    let u_vec = &param.h_vec;

    let rand_r = ScalarField::rand(&mut rng);

    let mut running_rand_ss = G::zero();
    let mut sig1_vec_masked = vec![];

    for i in 0..garble_message_size {
        let new_share = G::rand(&mut rng);
        running_rand_ss += new_share;
        sig1_vec_masked.push(new_share);

        if MAX_ITEM == 2 {
            sig1_vec_masked.push(u_vec[i] * rand_r + new_share);
        } else {
            let step = MAX_ITEM.ilog2() as usize;
            let subset_uvec = &u_vec[i * step..(i + 1) * step];
            for j in 1..MAX_ITEM {
                let array = usize_to_fixed_bit_array_8(j);
                let summed = subset_uvec.iter().enumerate()
                    .filter(|(index, _)| array[*index])
                    .fold(G::zero(), |sum, (_, val)| sum + (*val * rand_r));
                sig1_vec_masked.push(summed + new_share);
            }
        }
    }

    let mask_ss = -running_rand_ss;
    let sig_1_hprime_masked = msk + (u_prime * rand_r) + mask_ss;
    let sig_2 = g * rand_r;
    let sig_3 = g2 * rand_r;

    let shared_key_byte: Vec<Vec<u8>> = shared_key_list
        .iter()
        .map(|item| item.downcast::<PyBytes>().unwrap().as_bytes().to_vec())
        .collect();
    let mut aon_key_share_bytes: Vec<Vec<u8>> = Vec::new();
    let mut aon_key_bytes: [u8; 32] = [0u8; 32];
    for _ in 0..garble_message_size {
        let mut random_bytes = [0u8; 32];
        rng.fill(&mut random_bytes);
        aon_key_share_bytes.push(random_bytes.to_vec());
        for j in 0..32 { aon_key_bytes[j] ^= random_bytes[j]; }
    }

    let mut enc_sig1_vec = Vec::new();
    let mut key_mat_vec: Vec<Vec<u8>> = Vec::new();
    for i in 0..garble_message_size {
        for j in 0..MAX_ITEM {
            let mut sig_1_item = Vec::new();
            sig1_vec_masked[i * MAX_ITEM + j].serialize_compressed(&mut sig_1_item).unwrap();
            let localkey = shared_key_byte[i * MAX_ITEM + j].clone();
            let mut random_bytes = [0u8; 32];
            rng.fill(&mut random_bytes);
            key_mat_vec.push(encrypt(&concat_two(&aon_key_share_bytes[i], &random_bytes), localkey.as_slice(), 0));
            let final_localkeymat = derive_key(&aon_key_bytes, &random_bytes);
            enc_sig1_vec.push(encrypt(&sig_1_item[..], &final_localkeymat, 0));
        }
    }

    let mut sig_1_firstpart = Vec::new();
    sig_1_hprime_masked.serialize_compressed(&mut sig_1_firstpart).unwrap();
    let enc_sig1_firstpart = encrypt(&sig_1_firstpart[..], &aon_key_bytes, 1);

    let mut sig_2_byte = Vec::new();
    sig_2.serialize_compressed(&mut sig_2_byte).unwrap();
    let enc_sig2 = encrypt(&sig_2_byte[..], &aon_key_bytes, 2);

    let mut sig_3_byte = Vec::new();
    sig_3.serialize_compressed(&mut sig_3_byte).unwrap();
    let enc_sig3 = encrypt(&sig_3_byte[..], &aon_key_bytes, 3);

    let pay_box = PaymentBox {
        tag: tag2.clone(),
        sig3: enc_sig3,
        sig2: enc_sig2,
        sig1_firstpart: enc_sig1_firstpart,
        sig1_vec: enc_sig1_vec,
        key_mat_enc: key_mat_vec,
    };

    Ok(serde_json::to_string(&pay_box).unwrap())
}

#[pyfunction]
fn test_rdelegate_local(params:String, garble_message : String, shared_key_list:  &'_ Bound<'_, PyList>,message_patern_list:  &'_ Bound<'_, PyList>,  max_selectable_elem: usize, max_item: usize) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let paybox: PaymentBox = serde_json::from_str(&garble_message).unwrap();

    let shared_key_bytes: Vec<Vec<u8>> = shared_key_list
    .iter()
    .map(|item| {
        let byte_arr = item.downcast::<PyBytes>().unwrap().as_bytes();
        byte_arr.to_vec()
    })
    .collect();
    let shared_key_bytes = shared_key_bytes.concat();

    let message_pattern: Vec<u8> = message_patern_list
    .iter()
    .map(|item| {
        let ret_int = item.downcast::<PyInt>().unwrap();
        (ret_int.extract::<u32>()).unwrap() as u8
    })
    .collect();

    let (sk1, sk2, sk3) = pbcrypto::evaluate_paymentbox(params, paybox.key_mat_enc, paybox.sig1_firstpart, paybox.sig2, paybox.sig3, paybox.sig1_vec, shared_key_bytes, message_pattern, max_selectable_elem, max_item, paybox.tag);
    Ok((sk1, sk2, sk3))
}

#[pyfunction]
fn garble_ecdsa(param: String, shared_key_list:  &'_ Bound<'_, PyList>, num_selectable_elem: usize, num_possible_item_per_ele: usize) -> PyResult<String> {
    let test = false;
    let param: ParamECDSA = serde_json::from_str(&param).unwrap();
    let mut rng = ark_std::test_rng();
    let sk = param.secretkey;
    let pk = param.publickey;
    let generator: Secp256r1Projective = Projective::<Secp256r1Config>::generator();

    let max_message_size = 256; //max_garble message size [<= max_message_size used in param_gen]
    assert_eq!(max_message_size, (num_possible_item_per_ele.ilog2() as usize) * num_selectable_elem);

    // // Signing
    let k = Secp256r1Scalar::rand(&mut rng);
    let r = (generator * k).into_affine().x().unwrap();

    let kinv = k.inverse().unwrap();
    let r_right = Secp256r1Scalar::from_bigint(r.into_bigint()).unwrap();

    // let s = kinv * (hashed_message + (sk * r_right));
    let s0 = kinv * sk * r_right;

    // Sign := (s0, s, r_right);
    let mut running_rand_ss = Secp256r1Scalar::zero();
    let mut sig1_vec_masked = vec![];
    
    //Goes through all bit/byte 
    let mut poweroftwo = Secp256r1Scalar::ONE;
    let two = Secp256r1Scalar::ONE + Secp256r1Scalar::ONE;
    let one = Secp256r1Scalar::ONE;

    for i in 0..num_selectable_elem {     
        let new_share = Secp256r1Scalar::rand(&mut rng);
        // let new_share = Secp256r1Scalar::ZERO;

        running_rand_ss += new_share;
        sig1_vec_masked.push(new_share);

        // let start_ptr = i*num_possible_item_per_ele;

        if num_possible_item_per_ele==2{
            sig1_vec_masked.push( (poweroftwo*kinv) + new_share);
            // println!("Power of two: {}", poweroftwo);
            poweroftwo = poweroftwo*two;
        }
        else{
            let step = num_possible_item_per_ele.ilog2() as usize;
            let mut counting = Secp256r1Scalar::ONE;
            for j in 1..num_possible_item_per_ele {
                // let mut array  = usize_to_fixed_bit_array_8(j);
                // println!(" {}:,{:?}", j, array);
                // let summed = subset_uvec.into_iter().enumerate().filter(|(index, val)| array[*index]== true).fold(G::zero(), |sum, (index, val)| sum+((*val)*rand_r));
                let summed = (poweroftwo *counting )*kinv; //TODO: fix this
                sig1_vec_masked.push( summed+ new_share);

                counting = counting + Secp256r1Scalar::ONE;
            }

            for i in 0..step{
                poweroftwo = poweroftwo*two;
            }
        }
    }

    let mask_ss =  - running_rand_ss; 
    let sig_0_masked = s0 + mask_ss; 

    //NOTE: very coarse testing...
    if test
    {
        if num_possible_item_per_ele==2{
            // signauter is r_right,s
            let hashed_message = (one * two *two *two) + (one*two) ; //1010
            let message_int: usize = 10;
            let message_bigint =  Secp256r1Scalar::from_bigint(BigInt::from_str("10").unwrap()).unwrap();
            assert_eq!(hashed_message,message_bigint);
            let step = 2;

            let final_sum = sig1_vec_masked.iter().enumerate().filter(|(i, _x)| 
            (
                {
                    let shift_step = (i/step);
                    let shifted_value = if shift_step >= 64 {0} else {(message_int>>(i/step)) &0x1};
                    let check = shifted_value == (i%step) as usize ; 
                    // println!("check i-{}: {}, {}, {}, \ti/step:{}",i, check,shifted_value ,(i%step), (i/step));
                    check
                } 
            ))
            .fold(Secp256r1Scalar::zero(), |sum, (_index, val)| sum + (*val)); 
            
            let s = sig_0_masked + final_sum;
    
            //Verify Signature
            let sinv = s.inverse().unwrap();
            let k_prime = ((generator * hashed_message) + (pk*r_right)) * sinv;
            let r_prime = (k_prime).into_affine().x().unwrap();
            let r_prime_right = Secp256r1Scalar::from_bigint(r_prime.into_bigint()).unwrap();

            assert_eq!(r_right,r_prime_right,"Signature does not checkout");
        }
        else{
            //Test for 10000000,10000000,...
                 // signauter is r_right,s
                 let hashed_message = (one * two *two *two*two* two *two *two*two) + (one) ; //1010
                 let message_int: usize = 257;
                 let message_bigint =  Secp256r1Scalar::from_bigint(BigInt::from_str("257").unwrap()).unwrap();
                 assert_eq!(hashed_message,message_bigint);
                 let step = num_possible_item_per_ele;

                 let final_sum = sig1_vec_masked.iter().enumerate().filter(|(i, _x)| 
                 (
                     {
                         let shift_step = (i/step) * 8;
                         let shifted_value = if shift_step >= 64 {0} else {(message_int>>shift_step) &0x1};
                         let check = shifted_value == (i%step) as usize;
                         if (check == true){
                            // println!("check i-{}: {}, {}, {}, \tshift_step:{}",i, check,shifted_value ,(i%step), shift_step);
                         } 
                         check
                     } 
                 ))
                 .fold(Secp256r1Scalar::zero(), |sum, (_index, val)| sum + (*val)); 
    
                 let s = sig_0_masked + final_sum;
         
                 //Verify Signature
                 let sinv = s.inverse().unwrap();
                 let k_prime = ((generator * hashed_message) + (pk*r_right)) * sinv;
                 let r_prime = (k_prime).into_affine().x().unwrap();
                 let r_prime_right = Secp256r1Scalar::from_bigint(r_prime.into_bigint()).unwrap();
     
                 assert_eq!(r_right,r_prime_right,"Signature does not checkout");
        }
    }

    // // TODO: enable one-use key benchmark need to make the aon_key_bytes come from chosen_key_bytes, then encrypt correctly.
    // All keys are derived using method of AoN at server.py
    let shared_key_byte: Vec<Vec<u8>> = shared_key_list
    .iter()
    .map(|item| {
        let byte_arr = item.downcast::<PyBytes>().unwrap().as_bytes();
        byte_arr.to_vec()
    })
    .collect();
    let mut aon_key_share_bytes: Vec<Vec<u8>> = Vec::new();
    let mut aon_key_bytes: [u8;32] = [0 as u8;32];
    for i in 0..num_selectable_elem{
        let mut random_bytes = [0u8; 32];  //Sample local randomness secret
        rng.fill(&mut random_bytes);
        aon_key_share_bytes.push(random_bytes.to_vec());

        for j in 0..32{
            aon_key_bytes[j] ^= random_bytes[j];
        }
    }

    let tag = "001_000".to_string(); // ECDSA variant placeholder tag
    let rand_m = ScalarField::rand(&mut rng);
    let rand_m_t = Bn254::pairing(param.param_water.g, param.param_water.g2)* rand_m; //some random message in the target group
    let mut hasher = Sha3_256::new();
    hasher.update(rand_m_t.to_string()); //Better to use serialzed byte instead. String for convenient.
    let hashed = hasher.finalize().to_vec();
    for j in 0..32{
        aon_key_bytes[j] ^= hashed[j];
    }
    let enc_rtag = water_encrypt(&param.param_water, &tag, rand_m_t);

    // encrypt sig1_vecs with chosen_keys. 
    let mut enc_sig1_vec = Vec::new();
    let mut key_mat_vec: Vec<Vec<u8>> = Vec::new();
    for i in 0..num_selectable_elem{
        for j in 0..num_possible_item_per_ele{
            let mut sig_1_item = Vec::new();
            sig1_vec_masked[(i*num_possible_item_per_ele)+j].serialize_compressed(&mut sig_1_item).unwrap();
            let localkey = (shared_key_byte[(i*num_possible_item_per_ele) + j].clone());
            let mut random_bytes = [0u8; 32];  //Sample local randomness secret
            rng.fill(&mut random_bytes);
            // println!("local_key, {}, {}, {:?}", i,j,localkey);

            key_mat_vec.push(encrypt(&concat_two(&aon_key_share_bytes[i], &random_bytes), localkey.as_slice(),0)); // enc_localkey (a_i || b_i,{value_index})

            // println!("local_key_mat, {}, {}, {:?}", i,j,&concat_two(&aon_key_share_bytes[i], &random_bytes));

            let final_localkeymat = derive_key(&aon_key_bytes, &random_bytes);
            enc_sig1_vec.push(encrypt(&sig_1_item[..], &final_localkeymat,0)); 
            // println!("enc_sig1_vec: i:{:?}, j:{:?}, len: {:?}", i,j,enc_sig1_vec.len());
        }
    }

    // println!("aon_key {:?}", aon_key_bytes);


    // encrypt sig2, sig_1_hprime_masked with aon key.
    let mut sig_0_serialized = Vec::new();
    sig_0_masked.serialize_compressed(&mut sig_0_serialized).unwrap();
    let enc_sig0 = encrypt(&sig_0_serialized[..], &aon_key_bytes,1);

    let mut r_byte = Vec::new();
    r_right.serialize_compressed(&mut r_byte).unwrap();
    let enc_r = encrypt(&r_byte[..], &aon_key_bytes,2);

    let ecdsa_box = ECDSABox {
        tag: tag.clone(),
        rtag: enc_rtag,
        r: enc_r,
        s0: enc_sig0,
        s_vec:enc_sig1_vec,
        key_mat_enc: key_mat_vec
    };

    let json_string = serde_json::to_string(&ecdsa_box).unwrap();
    // let encoded = general_purpose::URL_SAFE_NO_PAD.encode(&json_string);
    // let _test_deserialize: ECDSABox = serde_json::from_str(&json_string).unwrap();
  
    Ok(json_string)
    // let a = String::new();
    // Ok(a)
} 


#[pyfunction]
fn test_dsign_local(params:String, garble_message : String, shared_key_list:  &'_ Bound<'_, PyList>,message_patern_list:  &'_ Bound<'_, PyList>,  max_selectable_elem: usize, max_item: usize){
    let paybox: ECDSABox = serde_json::from_str(&garble_message).unwrap();

    let shared_key_bytes: Vec<Vec<u8>> = shared_key_list
    .iter()
    .map(|item| {
        let byte_arr = item.downcast::<PyBytes>().unwrap().as_bytes();
        byte_arr.to_vec()
    })
    .collect();
    let shared_key_bytes = shared_key_bytes.concat();

    let message_pattern: Vec<u8> = message_patern_list
    .iter()
    .map(|item| {
        let ret_int = item.downcast::<PyInt>().unwrap();
        (ret_int.extract::<u32>()).unwrap() as u8
    })
    .collect();

    pbcrypto::evaluate_ecdsa(params, paybox.key_mat_enc, paybox.rtag,paybox.r, paybox.s0, paybox.s_vec, shared_key_bytes, message_pattern, max_selectable_elem, max_item);
}

#[pyfunction]
fn test_water(id: isize) -> PyResult<isize> {
    let param: ParamWaters = serde_json::from_str(&generate_params_waters().unwrap()).unwrap();
    let mut rng = ark_std::test_rng();
    let g = param.g;
    let g1 = param.g;

    let msk = param.g_alpha * param.beta_secret; 

    let g1_alpha = param.g_alpha;

    let g2 = param.g2;
    let g2_beta = param.g2_beta;

    let u_prime = param.h_0;
    let u_vec = param.h_vec;
    let try_num_message = 10;

    //Here paper => code s.t. from water original paper syntax => g2_alpha -> g1_(alpha*beta), g^r -> g2^r, g1-> g^alpha, g2 -> g^beta
    for _ in 0..try_num_message{
        let identity: i32 = rng.gen();

        let rand_r = ScalarField::rand(&mut rng);
        let sum_u_ = u_vec.iter().enumerate().filter(|(i, x)| ((identity>>i) &0x1) == 1 ).fold(G::ZERO, |sum, (index, val)| sum + val); //NOTE: Endianness

        let sk1= msk + ((u_prime + sum_u_) * rand_r);
        let sk2 = g * rand_r;
        let sk3 = g2 * rand_r;
        assert_eq!(Bn254::pairing(g1, sk3),Bn254::pairing(sk2, g2), "Random factor in dk2,dk3 does not match");

        // Encryption
        let rand_m = ScalarField::rand(&mut rng);
        let message = Bn254::pairing(g1, g2)* rand_m; //some random message in the target group
        let rand_t = ScalarField::rand(&mut rng);
        let c1 = Bn254::pairing(g1_alpha, g2_beta)*rand_t + message;
        let c2 = g2 * rand_t;
        let c3 = (u_prime+sum_u_) * rand_t;


        let mut c1_vec = Vec::new();
        c1.serialize_compressed(&mut c1_vec).unwrap();

        let mut c2_vec = Vec::new();
        c2.serialize_compressed(&mut c2_vec).unwrap();

        let mut c3_vec = Vec::new();
        c3.serialize_compressed(&mut c3_vec).unwrap();

        println!("Size of C1:{}, C2:{}, C3:{}", c1_vec.len(),c2_vec.len(),c3_vec.len());

        // Decrypt
        //Swapped d2 and C3.
        let decrypt_m = c1 + Bn254::pairing(c3, sk3) - Bn254::pairing(sk1, c2);
        assert_eq!(decrypt_m, message);
        // println!("All Good : {}!", 1);
    }   

    Ok(1)
}

#[pyfunction]
fn test_ecdsa(m: isize) -> PyResult<isize> {
    let param: ParamECDSA = serde_json::from_str(&generate_params_ecdsa(generate_params_waters().unwrap()).unwrap()).unwrap();
    let mut rng = ark_std::test_rng();

    let sk = param.secretkey;
    let pk = param.publickey;
    let generator: Secp256r1Projective = Projective::<Secp256r1Config>::generator();

    let try_num_message = 10;

    for _ in 0..try_num_message{
        let hashed_message = Secp256r1Scalar::rand(&mut rng); //Message alread
        
        // // Signing
        let k = Secp256r1Scalar::rand(&mut rng);

        let r = (generator * k).into_affine().x().unwrap();

        let kinv = k.inverse().unwrap();
        let r_right = Secp256r1Scalar::from_bigint(r.into_bigint()).unwrap();
        // let s = kinv * (hashed_message + (sk * r_right));
        let s = kinv * hashed_message +(kinv * sk * r_right);
        // signauter is r_right,s

        //Verify Signature
        let sinv = s.inverse().unwrap();
        let k_prime = ((generator * hashed_message) + (pk*r_right)) * sinv;
        let r_prime = (k_prime).into_affine().x().unwrap();
        let r_prime_right = Secp256r1Scalar::from_bigint(r_prime.into_bigint()).unwrap();

        assert_eq!(r_right,r_prime_right,"Signature does not checkout");
    }   

    Ok(1)
}

#[pyfunction]
fn test_unlock(param_str: String) -> PyResult<Vec<u8>> {
    let param: ParamWaters = serde_json::from_str(&param_str).unwrap();
    let mut rng = ark_std::test_rng();
    let g = param.g;
    let g1 = param.g;

    let msk = param.g_alpha * param.beta_secret; 

    let g1_alpha = param.g_alpha;

    let g2 = param.g2;
    let g2_beta = param.g2_beta;

    let u_prime = param.h_0;
    let u_vec = param.h_vec;

    //Here paper => code s.t. from water original paper syntax => g2_alpha -> g1_(alpha*beta), g^r -> g2^r, g1-> g^alpha, g2 -> g^beta
    let identity: i32 = rng.gen();

    let rand_r = ScalarField::rand(&mut rng);
    let sum_u_ = u_vec.iter().enumerate().filter(|(i, x)| ((identity>>i) &0x1) == 1 ).fold(G::ZERO, |sum, (index, val)| sum + val); //NOTE: Endianness

    let sk1= msk + ((u_prime + sum_u_) * rand_r);
    let sk2 = g * rand_r;
    let sk3 = g2 * rand_r;

    let mut sk1_vec = Vec::new();
    sk1.serialize_compressed(&mut sk1_vec).unwrap();

    let mut sk2_vec = Vec::new();
    sk2.serialize_compressed(&mut sk2_vec).unwrap();

    let mut sk3_vec = Vec::new();
    sk3.serialize_compressed(&mut sk3_vec).unwrap();

    sk1_vec.extend_from_slice(&sk2_vec[..]);
    sk1_vec.extend_from_slice(&sk3_vec[..]);


    Ok(sk1_vec)
}



#[pyfunction]
fn test_activate(param_str: String) -> PyResult<Vec<u8>> {
    let param: ParamWaters = serde_json::from_str(&param_str).unwrap();
    let mut rng = ark_std::test_rng();
    let g = param.g;
    let g1 = param.g;

    let msk = param.g_alpha * param.beta_secret; 

    let g1_alpha = param.g_alpha;

    let g2 = param.g2;
    let g2_beta = param.g2_beta;

    let u_prime = param.h_0;
    let u_vec = param.h_vec;

    //Here paper => code s.t. from water original paper syntax => g2_alpha -> g1_(alpha*beta), g^r -> g2^r, g1-> g^alpha, g2 -> g^beta
    let identity: i32 = rng.gen();

    let rand_r = ScalarField::rand(&mut rng);
    let sum_u_ = u_vec.iter().enumerate().filter(|(i, x)| ((identity>>i) &0x1) == 1 ).fold(G::ZERO, |sum, (index, val)| sum + val); //NOTE: Endianness

    let sk1= msk + ((u_prime + sum_u_) * rand_r);
    let sk2 = g * rand_r;
    let sk3 = g2 * rand_r;

    let mut sk1_vec = Vec::new();
    sk1.serialize_compressed(&mut sk1_vec).unwrap();

    let mut sk2_vec = Vec::new();
    sk2.serialize_compressed(&mut sk2_vec).unwrap();

    let mut sk3_vec = Vec::new();
    sk3.serialize_compressed(&mut sk3_vec).unwrap();

    sk1_vec.extend_from_slice(&sk2_vec[..]);
    sk1_vec.extend_from_slice(&sk3_vec[..]);

    // Encryption
    let rand_m = ScalarField::rand(&mut rng);
    let message = Bn254::pairing(g1, g2)* rand_m; //some random message in the target group
    let rand_t = ScalarField::rand(&mut rng);
    let c1 = Bn254::pairing(g1_alpha, g2_beta)*rand_t + message;
    let c2 = g2 * rand_t;
    let c3 = (u_prime+sum_u_) * rand_t;

    let mut c1_vec = Vec::new();
    c1.serialize_compressed(&mut c1_vec).unwrap();

    let mut c2_vec = Vec::new();
    c2.serialize_compressed(&mut c2_vec).unwrap();

    let mut c3_vec = Vec::new();
    c3.serialize_compressed(&mut c3_vec).unwrap();

    // println!("Size of C1:{}, C2:{}, C3:{}", c1_vec.len(),c2_vec.len(),c3_vec.len());

    // Decrypt
    //Swapped d2 and C3.
    let decrypt_m = c1 + Bn254::pairing(c3, sk3) - Bn254::pairing(sk1, c2);
    assert_eq!(decrypt_m, message);



    Ok(sk1_vec)
}

fn g1_vec_to_uncompressed_json(p_vec: Vec<G>, name: &str) ->serde_json::Value {
    let mut ret_json_val= serde_json::Map::new();
    let mut array = vec![];
    for p in p_vec{
        let affine = p.into_affine();

        let x_big = affine.x.into_bigint();
        let y_big = affine.y.into_bigint();
    
        let x_hex = format!("{}", (x_big.to_string()));
        let y_hex = format!("{}", (y_big.to_string()));
    
        array.push(json!({ "x": x_hex, "y": y_hex }));
    }
    let json_arr = serde_json::Value::Array(array);
    ret_json_val.insert(name.to_string(), json_arr);
    let json_val = serde_json::Value::Object(ret_json_val);
    json_val
}
fn g1_to_uncompressed_json(p: &G, name: &str) -> serde_json::Value {
    let affine = p.into_affine();

    let x_big = affine.x.into_bigint();
    let y_big = affine.y.into_bigint();

    let x_hex = format!("{}", (x_big.to_string()));
    let y_hex = format!("{}", (y_big.to_string()));

    let mut obj = serde_json::Map::new();
    obj.insert(
        name.to_string(),
        json!({ "x": x_hex, "y": y_hex })
    );
    let json_val = serde_json::Value::Object(obj);
    json_val
}
fn g2_to_uncompressed_json(p: &G2, name:&str) -> serde_json::Value {
    let affine = p.into_affine();

    // Fq2 = c0 + c1 * u
    let x = affine.x;
    let y = affine.y;

    let x_c0 = x.c0.into_bigint();
    let x_c1 = x.c1.into_bigint();
    let y_c0 = y.c0.into_bigint();
    let y_c1 = y.c1.into_bigint();

    let x_c0_hex = format!("{}", (x_c0.to_string()));
    let x_c1_hex = format!("{}",(x_c1.to_string()));
    let y_c0_hex = format!("{}",(y_c0.to_string()));
    let y_c1_hex = format!("{}",(y_c1.to_string()));

    let mut obj = serde_json::Map::new();
    obj.insert(
        name.to_string(),
        json!({
            "x": [x_c0_hex, x_c1_hex],
            "y": [y_c0_hex, y_c1_hex]
        })
    );
    let json_val = serde_json::Value::Object(obj);
    json_val

}
fn merge_json(a: &mut serde_json::Value, b: &serde_json::Value) {
    if let (serde_json::Value::Object(a_map), serde_json::Value::Object(b_map)) = (a, b) {
        for (k, v) in b_map {
            a_map.insert(k.clone(), v.clone());
        }
    }
}

#[pyfunction]
fn test_pairing() -> PyResult<String> {
    let param_str = generate_params_waters().unwrap();
    let param: ParamWaters = serde_json::from_str(&param_str).unwrap();

    let mut rng = ark_std::test_rng();
    let g = param.g;
    let g1 = param.g;

    let msk = param.g_alpha * param.beta_secret; 

    let g1_alpha = param.g_alpha;

    let g2 = param.g2;
    let g2_beta = param.g2_beta;

    let u_prime = param.h_0;
    let u_vec = param.h_vec;

    let rand_r = ScalarField::rand(&mut rng);
    let g1r = g1 * rand_r;

    let mut g2r = g2*rand_r;
    assert_eq!(Bn254::pairing(g1r, g2),Bn254::pairing(g1, g2r));
    assert_eq!(Bn254::pairing(g1, g2),Bn254::pairing(g1, g2));

    let mut ret = g1_to_uncompressed_json(&g1r, "g1r");
    merge_json(&mut ret, &g1_to_uncompressed_json(&g1, "g1"));
    merge_json(&mut ret, &g2_to_uncompressed_json(&g2r, "g2r"));
    merge_json(&mut ret, &g2_to_uncompressed_json(&g2, "g2"));
    merge_json(&mut ret, &g1_to_uncompressed_json(&(g1r+g1), "g1rg1"));

    Ok(ret.to_string())    
}


// #[pyfunction]
// fn poseidon(x1: String, y1: String) -> PyResult<String> {
//     use poseidon_bfsecp256r1::Poseidon;
//     use secq256r1::scalarfield::Fr;

//     let ret_str = format!("{}", Poseidon::new().hash(vec![Fr::from_str(&x1).unwrap(),Fr::from_str(&y1).unwrap()]).unwrap());
//     Ok(ret_str)    
// }

#[pyfunction]
fn decompress_waters_key(sk1_hex: &str, sk2_hex: &str, sk3_hex: &str) -> PyResult<String> {
    use ark_bn254::{G1Affine, G2Affine};
    use ark_serialize::CanonicalDeserialize;

    let sk1_bytes = hex::decode(sk1_hex)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    let sk2_bytes = hex::decode(sk2_hex)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    let sk3_bytes = hex::decode(sk3_hex)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let sk1 = G1Affine::deserialize_compressed(&*sk1_bytes)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    let sk2 = G1Affine::deserialize_compressed(&*sk2_bytes)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    let sk3 = G2Affine::deserialize_compressed(&*sk3_bytes)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let sk1_x = sk1.x.into_bigint().to_string();
    let sk1_y = sk1.y.into_bigint().to_string();
    let sk2_x = sk2.x.into_bigint().to_string();
    let sk2_y = sk2.y.into_bigint().to_string();
    let sk3_x_c0 = sk3.x.c0.into_bigint().to_string();
    let sk3_x_c1 = sk3.x.c1.into_bigint().to_string();
    let sk3_y_c0 = sk3.y.c0.into_bigint().to_string();
    let sk3_y_c1 = sk3.y.c1.into_bigint().to_string();

    Ok(format!(
        r#"{{"sk1":{{"x":"{sk1_x}","y":"{sk1_y}"}},"sk2":{{"x":"{sk2_x}","y":"{sk2_y}"}},"sk3":{{"x":["{sk3_x_c0}","{sk3_x_c1}"],"y":["{sk3_y_c0}","{sk3_y_c1}"]}}}}"#
    ))
}

#[pymodule]
fn rustcode(m: &Bound<'_, PyModule>) -> PyResult<()> {
    pyo3_log::init();
    m.add_function(wrap_pyfunction!(test_water, m)?)?;
    m.add_function(wrap_pyfunction!(test_ecdsa, m)?)?;
    m.add_function(wrap_pyfunction!(test_activate, m)?)?;
    m.add_function(wrap_pyfunction!(test_unlock, m)?)?;
    m.add_function(wrap_pyfunction!(test_rdelegate_local, m)?)?;
    m.add_function(wrap_pyfunction!(test_dsign_local, m)?)?;
    m.add_function(wrap_pyfunction!(test_pairing, m)?)?;
    m.add_function(wrap_pyfunction!(test_encrypt, m)?)?;
    
    m.add_function(wrap_pyfunction!(generate_params_waters, m)?)?;
    m.add_function(wrap_pyfunction!(generate_params_ecdsa, m)?)?;
    m.add_function(wrap_pyfunction!(water_unlock_solidity, m)?)?;
    m.add_function(wrap_pyfunction!(water_derive_ak, m)?)?;
    m.add_function(wrap_pyfunction!(garble_waters_with_gs, m)?)?;
    m.add_function(wrap_pyfunction!(test_evaluate_gs, m)?)?;
    m.add_function(wrap_pyfunction!(test_verify_gs_key, m)?)?;
    m.add_function(wrap_pyfunction!(decompress_waters_key, m)?)?;
    m.add_function(wrap_pyfunction!(garble_waters, m)?)?;
    m.add_function(wrap_pyfunction!(garble_redelegate, m)?)?;
    m.add_function(wrap_pyfunction!(garble_ecdsa, m)?)?;
    // m.add_function(wrap_pyfunction!(poseidon, m)?)?;

    // m.add_class::<RustStruct>()?;

    Ok(())
}