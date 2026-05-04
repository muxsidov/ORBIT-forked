use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ark_ec::{bls12::G1Projective, pairing, AdditiveGroup, PrimeGroup,  CurveGroup, models::short_weierstrass::{Affine, Projective}};
use ark_secp256r1::{Config as Secp256r1Config, Fq as PBase, Fr as Secp256r1Scalar}; // Curve config, Base Field (Fq), Scalar Field (Fr)
use ark_std::{ops::Mul, rand::Rng, UniformRand, Zero};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{BigInt};
use std::str::FromStr;

use ark_serialize::CanonicalSerialize;
use ark_marlin::rng::FiatShamirRng;
use blake2::Blake2s;
use ark_std::rand::RngCore;

use ark_ff::Field;
use ark_ff::PrimeField;
type Secp256r1Projective = Projective<Secp256r1Config>;
type Secp256r1Affine = Affine<Secp256r1Config>;

use rayon::prelude::*;


use ark_bn254::{g2, Bn254, Fq12 as TargetField, Fr as ScalarField, G1Projective as G, G2Projective as G2};


// Pure key exchange
fn shared_keygen(pubkey: Secp256r1Projective)-> (Vec<Secp256r1Projective>, Vec<Secp256r1Scalar>, Vec<Secp256r1Projective> ) {
    let mut rng = ark_std::test_rng();
    let mut shared_key_vec = vec!();
    let mut secert_key_vec = vec!();
    let mut pubkey_e_vec = vec!();


    let generator_proj: Secp256r1Projective = Projective::<Secp256r1Config>::generator();
    for i in 0..80{
        // Generate a secret key
        let private_key_scalar = Secp256r1Scalar::rand(&mut rng);
        let public_key_proj: Secp256r1Projective = generator_proj * private_key_scalar;
    
        let shared_key = pubkey * private_key_scalar;
        shared_key_vec.push(shared_key);
        secert_key_vec.push(private_key_scalar);
        pubkey_e_vec.push(public_key_proj)
    }
    (shared_key_vec, secert_key_vec, pubkey_e_vec)
}

// Pure randomness commit
fn shared_key_commit_rand(g: Secp256r1Projective,h: Secp256r1Projective, shared_key_vec: Vec<Secp256r1Projective>, pubkey: Secp256r1Projective)-> ( Vec<Vec<Secp256r1Projective>>, Vec<Vec<Secp256r1Projective>>,Vec<Vec<Secp256r1Scalar>>, Vec<Vec<Secp256r1Scalar>>)  {
    let generator_proj: Secp256r1Projective = Projective::<Secp256r1Config>::generator();
    let num_of_circuits = 80;

    // let mut commit_vec =  vec![vec!();num_of_circuits];
    // let mut derived_key_vec =  vec![vec!();num_of_circuits];

    // let mut y_vec = vec![vec!();num_of_circuits];
    // let mut rho_vec =  vec![vec!();num_of_circuits];

    let (i_vec, commit_vec,derived_key_vec,y_vec,rho_vec) = (0..num_of_circuits).into_par_iter().map(|i| {
        let mut rng = ark_std::test_rng();
    // for i in 0..80{
        let mut y_row = vec!();
        let mut rho_row = vec!();
        let mut commit_row = vec!();
        let mut derived_key_row = vec!();

        // Number of keys per circuit
        for j in 0..80{
            let y = Secp256r1Scalar::rand(&mut rng);
            let rho = Secp256r1Scalar::rand(&mut rng);

            // Commit
            let commit = g*y + h*rho;
             
            //  Derive Key
            let derived_key = pubkey * y + shared_key_vec[j];

            commit_row.push(commit);
            y_row.push(y);
            rho_row.push(rho);
            derived_key_row.push(derived_key);
        }

        // commit_vec[i] = (commit_row);
        // derived_key_vec[i] = (derived_key_row);
        // y_vec[i] = (y_row);
        // rho_vec[i] = (rho_row);
        (vec![i], vec![commit_row],vec![derived_key_row],vec![y_row],vec![rho_row])
    }).reduce(|| (Vec::new(),Vec::new(), Vec::new(), Vec::new(), Vec::new()), |a,b| {
        (a.0.into_iter().chain(b.0.into_iter()).collect()
        ,a.1.into_iter().chain(b.1.into_iter()).collect()
        ,a.2.into_iter().chain(b.2.into_iter()).collect()
        ,a.3.into_iter().chain(b.3.into_iter()).collect()
        ,a.4.into_iter().chain(b.4.into_iter()).collect())
    });
    // }).reduce(|| (Vec::new(),Vec::new(), Vec::new(), Vec::new(), Vec::new()), |mut acc, (i, commit_row,derived_key_row,y_row,rho_row)| {
    //     acc.0.push(i);
    //     acc.1.push(commit_row);
    //     acc.2.push(derived_key_row);
    //     acc.3.push(y_row);
    //     acc.4.push(rho_row);
    // });

    // The order of derivation does not matter, we do not sort the circuit according to loop id.
    (derived_key_vec, commit_vec, y_vec, rho_vec)
}

fn proof_generation(g: Secp256r1Projective,h: Secp256r1Projective, shared_key_vec: Vec<Secp256r1Projective>, pubkey: Secp256r1Projective, secret_key_vec : Vec<Secp256r1Scalar>, derived_key_vec: Vec<Vec<Secp256r1Projective>>, commit_vec: Vec<Vec<Secp256r1Projective>>, y_vec : Vec<Vec<Secp256r1Scalar>>, rho_vec : Vec<Vec<Secp256r1Scalar>>, ephemeral_pubkey: Vec<Secp256r1Projective>)-> (Vec<Vec<Secp256r1Projective>>,Vec<Vec<Secp256r1Projective>>,Vec<Vec<Secp256r1Projective>>,Vec<Vec<Secp256r1Scalar>>,Vec<Vec<Secp256r1Scalar>>,Vec<Vec<Secp256r1Scalar>>,Vec<Vec<Secp256r1Scalar>>) {
    let generator_proj: Secp256r1Projective = Projective::<Secp256r1Config>::generator();
    let num_of_circuits_check = 40;

    let mut u1_vec = vec!();
    let mut u2_vec = vec!();
    let mut u3_vec = vec!();

    let mut c_vec = vec!();

    let mut z1_vec = vec!();
    let mut z2_vec = vec!();
    let mut z3_vec = vec!();
    
    let mut result_vec = (0..num_of_circuits_check).into_par_iter().map(|circuit| {
    // for circuit in 0..40{
        let mut rng = ark_std::test_rng();
        let mut u1_row = vec!();
        let mut u2_row = vec!();
        let mut u3_row = vec!();
        let mut c_row = vec!();
        let mut z1_row = vec!();
        let mut z2_row = vec!();
        let mut z3_row = vec!();
        for j in 0..80{
            let r1 = Secp256r1Scalar::rand(&mut rng);
            let r2 = Secp256r1Scalar::rand(&mut rng);
            let r3 = Secp256r1Scalar::rand(&mut rng);

            let u1 = g*r1 ;
            let u2 = g*r2 + h*r3;
            let u3 = pubkey* (r1+r2) ;

            // let c = Secp256r1Scalar::rand(&mut rng); 
            let mut fs = FiatShamirRng::<Blake2s>::from_seed(b"marlin-example");
            let mut buf = Vec::new();
            u1.serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            u2.serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            u3.serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            derived_key_vec[circuit][j].serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            commit_vec[circuit][j].serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            g.serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            h.serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            pubkey.serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            ephemeral_pubkey[j].serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            let mut bytes = [0u8; 64];
            fs.fill_bytes(&mut bytes);
            let c = Secp256r1Scalar::from_le_bytes_mod_order(&bytes);

            let z1 = r1+ c * secret_key_vec[j];
            let z2 = r2+ c* y_vec[circuit][j];
            let z3 = r3+ c* rho_vec[circuit][j];
             
            u1_row.push(u1);
            u2_row.push(u2);
            u3_row.push(u3);

            c_row.push(c);

            z1_row.push(z1);
            z2_row.push(z2);
            z3_row.push(z3);
        }

        // u1_vec.push(u1_row);
        // u2_vec.push(u2_row);
        // u3_vec.push(u3_row);
        // c_vec.push(c_row);
        // z1_vec.push(z1_row);
        // z2_vec.push(z2_row);
        // z3_vec.push(z3_row);
        vec![(circuit, u1_row,u2_row,u3_row,c_row,z1_row,z2_row,z3_row)]
    }).reduce(|| Vec::new(), |a,b| {
        a.into_iter().chain(b.into_iter()).collect()
    });
    result_vec.sort_by(|a,b|( a.0.cmp(&b.0)));

    for i in 0..num_of_circuits_check{
        u1_vec.push(result_vec[i].1.clone());
        u2_vec.push(result_vec[i].2.clone());
        u3_vec.push(result_vec[i].3.clone());
        c_vec.push(result_vec[i].4.clone());
        z1_vec.push(result_vec[i].5.clone());
        z2_vec.push(result_vec[i].6.clone());
        z3_vec.push(result_vec[i].7.clone());
    }

    // u1_vec, u2_vec, u3_vec, c_vec, z1_vec, z2_vec, z3_vec
    (u1_vec, u2_vec, u3_vec, c_vec, z1_vec, z2_vec, z3_vec)
}

fn proof_verification(g:Secp256r1Projective ,h: Secp256r1Projective, pubkey: Secp256r1Projective, ephemeral_pubkey: Vec<Secp256r1Projective>, com_vec: Vec<Vec<Secp256r1Projective>>, derived_key: Vec<Vec<Secp256r1Projective>>, u1_vec: Vec<Vec<Secp256r1Projective>>, u2_vec: Vec<Vec<Secp256r1Projective>>, u3_vec: Vec<Vec<Secp256r1Projective>>, c_vec: Vec<Vec<Secp256r1Scalar>>, z1_vec: Vec<Vec<Secp256r1Scalar>>, z2_vec: Vec<Vec<Secp256r1Scalar>>, z3_vec: Vec<Vec<Secp256r1Scalar>>)-> bool{
    // let mut bit = true;
    // for circuit in 0..40{
    let bit = (0..40).into_par_iter().map(|circuit| {
        let mut inner_bit = true;
        for k in 0..80{
            let b_1 = (g*z1_vec[circuit][k] == u1_vec[circuit][k] + ephemeral_pubkey[k]*c_vec[circuit][k] );
            let b_2 = (g*z2_vec[circuit][k] + h*z3_vec[circuit][k] == u2_vec[circuit][k]+ com_vec[circuit][k]*c_vec[circuit][k]);
            let b_3 = (pubkey*(z1_vec[circuit][k] + z2_vec[circuit][k]) == u3_vec[circuit][k]+ derived_key[circuit][k]*c_vec[circuit][k]);

            let mut fs = FiatShamirRng::<Blake2s>::from_seed(b"marlin-example");
            let mut buf = Vec::new();
            u1_vec[circuit][k].serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            u2_vec[circuit][k].serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            u3_vec[circuit][k].serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            derived_key[circuit][k].serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            com_vec[circuit][k].serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            g.serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            h.serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            pubkey.serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            ephemeral_pubkey[k].serialize_compressed(&mut buf).unwrap();
            fs.absorb(&buf);
            let mut bytes = [0u8; 64];
            fs.fill_bytes(&mut bytes);
            let c = Secp256r1Scalar::from_le_bytes_mod_order(&bytes);
            let b_c = (c == c_vec[circuit][k]);

            inner_bit = (inner_bit && b_1 && b_2 && b_3 && b_c)
        }
        inner_bit
    })
    .reduce(|| true, |a, b| a & b);

    return bit
}

fn proof_opening(g:Secp256r1Projective ,h: Secp256r1Projective,com_vec: Vec<Vec<Secp256r1Projective>>,y_vec : Vec<Vec<Secp256r1Scalar>>, rho_vec : Vec<Vec<Secp256r1Scalar>> ) -> bool{
    // let mut bit = true;

    // for circuit in 0..80{
    let bit = (0..80).into_par_iter().map(|circuit| {
        let mut inner_bit = true;
        for k in 0..80{
            let b_1 = (g*y_vec[circuit][k] + h*rho_vec[circuit][k] == com_vec[circuit][k]);
            inner_bit = inner_bit & b_1;
        }
        inner_bit
    })
    .reduce(|| true, |a, b| a & b);
    
    return bit
}

fn verifiable_secret_sharing_estimate( g:G,g2:G2, g_alpha:G, g2_beta: G2, commitment_coeff: Vec<G>,sk_share_vec:Vec<ScalarField>){
    // for circuit in 1..41{
    (1..41).into_par_iter().for_each(|circuit| {
        // println!("Circuitnum: {}", circuit);
        let circuit_scalar = ScalarField::from_bigint(BigInt::from_str( &circuit.to_string() ).unwrap()).unwrap();
        let sk_circuit = sk_share_vec[circuit-1];
        
        // let mut commitment_sum = commitment_coeff[0];
        let mut commitment_sum = G::ZERO;
        for i in 1..41{ //41 for commitment_sum assertion
            // println!("{:?}",circuit_scalar.pow( &[i as u64] ));
            commitment_sum = commitment_sum + (commitment_coeff[i] * circuit_scalar.pow( &[i as u64] ));
        }

        // assert_eq!(g*sk_circuit, g*coeff_sum);
        // assert_eq!(g*sk_circuit, commitment_sum);

        assert_eq!(Bn254::pairing(g, g2)*sk_circuit, Bn254::pairing(g_alpha, g2_beta)+ Bn254::pairing(commitment_sum, g2));
    });
}
fn evaluate_polynomial(x: ScalarField, coeffs: &[ScalarField]) -> ScalarField {
    coeffs.iter()
          .enumerate()
          .map(|(i, &coef)| coef * x.pow( &[i as u64]  ))
        //   .map(|(i, &coef)| coef * x.pow( ScalarField::from_bigint(BigInt::from_str(&i.to_string()).unwrap()).unwrap()  ))
          .sum()
}

fn bench_fibonacci(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

    let alpha_secret = ScalarField::rand(&mut rng);
    let beta_secret = alpha_secret;
    let g = G::rand(&mut rng);
    let g_alpha = g * alpha_secret; //g^alpha
    let g2 = G2::rand(&mut rng); //g2
    let g2_beta = g2 * beta_secret; //g2^beta
    assert_eq!(Bn254::pairing(g, g2)*(alpha_secret*beta_secret), Bn254::pairing(g_alpha, g2_beta));
    // let g_sk = g* (alpha_secret*beta_secret);
    let mut coeff = vec!();
    let mut commitment_coeff = vec!();
    for i in 0..41{
        let scalar = ScalarField::rand(&mut rng);
        coeff.push(scalar);
        commitment_coeff.push(g * scalar);
    }
    coeff[0] = alpha_secret*beta_secret;
    commitment_coeff[0] = g * coeff[0];
    // println!("{}",evaluate_polynomial( ScalarField::from_bigint(BigInt::from_str("0").unwrap()).unwrap() , &coeff));
    // println!("{}",coeff[0]);
    // // Test evaluate at 1 which means add up all coefficient
    // println!("{}",evaluate_polynomial( ScalarField::from_bigint(BigInt::from_str("1").unwrap()).unwrap() , &coeff));
    // let mut coeff_sum = ScalarField::ZERO;
    // for i in 0..41{
    //     coeff_sum += coeff[i];
    // }
    // println!("{}",coeff_sum);
    let mut sk_share_vec = vec!();
    for circuit in 1..41{
        let circuit_scalar = ScalarField::from_bigint(BigInt::from_str( &circuit.to_string() ).unwrap()).unwrap();
        let sk_circuit = evaluate_polynomial( circuit_scalar, &coeff);
        sk_share_vec.push(sk_circuit);
    }

    let mut group = c.benchmark_group("Fast Fibonacci Bench");

    group.sample_size(10);       // Fewer samples (default is 100)
    group.warm_up_time(std::time::Duration::from_secs(1)); // Default is 3s
    group.measurement_time(std::time::Duration::from_secs(2)); // Default is 5s

    let mut rng = ark_std::test_rng();
    let generator_proj: Secp256r1Projective = Projective::<Secp256r1Config>::generator();

    // Generate h 
    let unkown_discrete_log = Secp256r1Scalar::rand(&mut rng);
    let h_proj: Secp256r1Projective = generator_proj * unkown_discrete_log;

    // Generate a secret key
    let private_key_scalar = Secp256r1Scalar::rand(&mut rng);
    let public_key_proj: Secp256r1Projective = generator_proj * private_key_scalar;

    let (shared_keyvec, secret_key_vec, pubkey_e_vec) = shared_keygen(public_key_proj);
    let (derived_key_vec, commit_vec, y_vec, rho_vec) = shared_key_commit_rand(generator_proj, h_proj, shared_keyvec.clone(),public_key_proj);
    let (u1_vec, u2_vec, u3_vec, c_vec, z1_vec, z2_vec, z3_vec) = proof_generation(generator_proj, h_proj, shared_keyvec.clone(),public_key_proj, secret_key_vec.clone(), derived_key_vec.clone(), commit_vec.clone(), y_vec.clone(), rho_vec.clone(), pubkey_e_vec.clone());
    let bit_bool = proof_verification(generator_proj, h_proj, public_key_proj,  pubkey_e_vec.clone(), commit_vec.clone(), derived_key_vec.clone(), u1_vec.clone(), u2_vec.clone(), u3_vec.clone(), c_vec.clone(), z1_vec.clone(),z2_vec.clone(), z3_vec.clone());
    assert_eq!(bit_bool, true);

    let bit_opening = proof_opening(generator_proj, h_proj, commit_vec.clone(),  y_vec.clone(), rho_vec.clone());
    assert_eq!(bit_opening, true);

    // group.bench_function("fibonacci 20", |b| {
    //     // b.iter(|| shared_keygen(public_key_proj) )
    //     // b.iter(|| shared_key_commit_rand(generator_proj, h_proj, shared_keyvec.clone(),public_key_proj) )
    //     // b.iter(|| proof_generation(generator_proj, h_proj, shared_keyvec.clone(),public_key_proj, secret_key_vec.clone(), derived_key_vec.clone(), commit_vec.clone(), y_vec.clone(), rho_vec.clone()) )
    //     // b.iter(|| proof_verification(generator_proj, h_proj, public_key_proj,  pubkey_e_vec.clone(), commit_vec.clone(), derived_key_vec.clone(), u1_vec.clone(), u2_vec.clone(), u3_vec.clone(), c_vec.clone(), z1_vec.clone(),z2_vec.clone(), z3_vec.clone()) )
    //     // b.iter(||  )
    // });

    //New benches
    // group.bench_function("shared_key and commit_rand", |b| {
    //     b.iter(|| shared_key_commit_rand(generator_proj, h_proj, shared_keyvec.clone(),public_key_proj) )
    // });

    //  group.bench_function("proof generation", |b| {
    //     b.iter(|| proof_generation(generator_proj, h_proj, shared_keyvec.clone(),public_key_proj, secret_key_vec.clone(), derived_key_vec.clone(), commit_vec.clone(), y_vec.clone(), rho_vec.clone(),  pubkey_e_vec.clone()) )
    // });

    group.bench_function("proof_verify", |b| {
        b.iter(|| proof_verification(generator_proj, h_proj, public_key_proj,  pubkey_e_vec.clone(), commit_vec.clone(), derived_key_vec.clone(), u1_vec.clone(), u2_vec.clone(), u3_vec.clone(), c_vec.clone(), z1_vec.clone(),z2_vec.clone(), z3_vec.clone()) )
    });

    group.bench_function("opening", |b| {
        b.iter(|| proof_opening(generator_proj, h_proj, commit_vec.clone(),  y_vec.clone(), rho_vec.clone()) )
    });

    group.bench_function("vss_check", |b| {
        b.iter(|| verifiable_secret_sharing_estimate(g,g2,g_alpha,g2_beta,commitment_coeff.clone(), sk_share_vec.clone() ) )
    });

    group.finish();
}

criterion_group!(benches, bench_fibonacci);
criterion_main!(benches);