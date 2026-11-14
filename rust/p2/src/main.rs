//! PQSSI+ prototype: one-time salted PQ credentials with an in-circuit
//! holder binding, proven with Plonky2 (FRI, Poseidon over Goldilocks) in
//! zero-knowledge mode. The issuer signs the credential root with ML-DSA-87
//! outside the circuit.
//!
//! Credential (one per presentation, issued in batches of k):
//!   c_i  = Poseidon(salt_i[4] || attr_i)             i = 0..n-1
//!   pk_h = Poseidon(sk_h[4])
//!   root = Poseidon(c_0..c_{n-1} || pk_h || credId || exp || schemaId)
//!   sigma = ML-DSA-87.Sign(isk, root)
//! Presentation statement x = (root, nonce[4], aud[4], today), witness w =
//! (sk_h, salts, attrs, credId, exp, schemaId); the circuit enforces
//!   root recomputation, knowledge of sk_h, policy attr_0 <= today - ADULT
//!   and exp >= today. nonce and aud are public inputs, hence part of the
//!   Fiat-Shamir transcript. Aligned with the Plonky3 statement: the public
//!   values are exactly (root, nonce, aud, today), with no further output
//!   derived from sk_h, and the same four 29-bit range checks (birth, exp and
//!   both differences); the verifier checks today in [ADULT, 2^29) outside.

use anyhow::Result;
use fips204::ml_dsa_87;
use fips204::traits::{SerDes, Signer, Verifier};
use plonky2::field::types::{Field, PrimeField64, Sample};
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use std::time::Instant;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
const ADULT_DAYS: u64 = 6575; // 18 * 365.25 = 6574.5, rounded up

struct Targets {
    sk: [Target; 4],
    salts: Vec<[Target; 4]>,
    attrs: Vec<Target>,
    meta: [Target; 3], // credId, exp, schemaId
    nonce: [Target; 4],
    aud: [Target; 4],
    today: Target,
}

fn build(n: usize, zk: bool) -> (CircuitData<F, C, D>, Targets) {
    // FRI parameters from the environment (defaults = Plonky2 standard recursion config):
    // RATE (rate_bits), QUERIES (num_query_rounds), POW (proof_of_work_bits)
    let env = |k: &str, d: usize| std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d);
    let mut config = CircuitConfig::standard_recursion_config();
    config.zero_knowledge = zk;
    config.fri_config.rate_bits = env("RATE", 3);
    config.fri_config.num_query_rounds = env("QUERIES", 28);
    config.fri_config.proof_of_work_bits = env("POW", 16) as u32;
    // ARITY (log2 FRI folding arity) and FINAL (log2 max final polynomial length)
    config.fri_config.reduction_strategy =
        plonky2::fri::reduction_strategies::FriReductionStrategy::ConstantArityBits(env("ARITY", 4), env("FINAL", 5));
    let mut b = CircuitBuilder::<F, D>::new(config);
    let sk: [Target; 4] = b.add_virtual_targets(4).try_into().unwrap();
    let salts: Vec<[Target; 4]> = (0..n).map(|_| b.add_virtual_targets(4).try_into().unwrap()).collect();
    let attrs: Vec<Target> = b.add_virtual_targets(n);
    let meta: [Target; 3] = b.add_virtual_targets(3).try_into().unwrap();

    // root = H(c_0..c_{n-1} || pk_h || meta)
    let mut root_in = Vec::new();
    for i in 0..n {
        let mut v = salts[i].to_vec();
        v.push(attrs[i]);
        root_in.extend(b.hash_n_to_hash_no_pad::<PoseidonHash>(v).elements);
    }
    let pk = b.hash_n_to_hash_no_pad::<PoseidonHash>(sk.to_vec());
    root_in.extend(pk.elements);
    root_in.extend(meta);
    let root = b.hash_n_to_hash_no_pad::<PoseidonHash>(root_in);
    b.register_public_inputs(&root.elements);

    // session: nonce, aud, today public (no other public output, as in the Plonky3 AIR)
    let nonce: [Target; 4] = b.add_virtual_targets(4).try_into().unwrap();
    let aud: [Target; 4] = b.add_virtual_targets(4).try_into().unwrap();
    let today = b.add_virtual_target();
    b.register_public_inputs(&nonce);
    b.register_public_inputs(&aud);
    b.register_public_inputs(&[today]);

    // same four 29-bit range checks as the Plonky3 AIR (Lemma 1 of the paper):
    // policy: today - ADULT_DAYS - birth >= 0; validity: exp - today >= 0;
    // birth and exp are day counts below 2^29. today is checked by the verifier.
    let adult = b.constant(F::from_canonical_u64(ADULT_DAYS));
    let t1 = b.sub(today, adult);
    let diff = b.sub(t1, attrs[0]);
    b.range_check(diff, 29);
    let left = b.sub(meta[1], today);
    b.range_check(left, 29);
    b.range_check(attrs[0], 29);
    b.range_check(meta[1], 29);

    let data = b.build::<C>();
    (data, Targets { sk, salts, attrs, meta, nonce, aud, today })
}

fn rand_f() -> F { F::rand() }

fn h(v: &[F]) -> HashOut<F> { PoseidonHash::hash_no_pad(v) }

struct Cred { sk: [F; 4], salts: Vec<[F; 4]>, attrs: Vec<F>, meta: [F; 3], root: HashOut<F> }

fn issue_cred(attrs: &[u64], exp: u64) -> Cred {
    let sk = [0; 4].map(|_| rand_f());
    let salts: Vec<[F; 4]> = attrs.iter().map(|_| [0; 4].map(|_| rand_f())).collect();
    let attrs: Vec<F> = attrs.iter().map(|&a| F::from_canonical_u64(a)).collect();
    let meta = [rand_f(), F::from_canonical_u64(exp), F::from_canonical_u64(7)];
    let mut root_in = Vec::new();
    for i in 0..attrs.len() {
        let mut v = salts[i].to_vec();
        v.push(attrs[i]);
        root_in.extend(h(&v).elements);
    }
    root_in.extend(h(&sk).elements);
    root_in.extend(meta);
    Cred { root: h(&root_in), sk, salts, attrs, meta }
}

fn root_bytes(root: &HashOut<F>) -> Vec<u8> {
    root.elements.iter().flat_map(|e| e.to_canonical_u64().to_le_bytes()).collect()
}

fn prove(data: &CircuitData<F, C, D>, t: &Targets, c: &Cred, nonce: [F; 4], aud: [F; 4], today: u64) -> Result<ProofWithPublicInputs<F, C, D>> {
    let mut pw = PartialWitness::new();
    for j in 0..4 {
        pw.set_target(t.sk[j], c.sk[j])?;
        pw.set_target(t.nonce[j], nonce[j])?;
        pw.set_target(t.aud[j], aud[j])?;
    }
    for i in 0..c.attrs.len() {
        for j in 0..4 { pw.set_target(t.salts[i][j], c.salts[i][j])?; }
        pw.set_target(t.attrs[i], c.attrs[i])?;
    }
    for j in 0..3 { pw.set_target(t.meta[j], c.meta[j])?; }
    pw.set_target(t.today, F::from_canonical_u64(today))?;
    data.prove(pw)
}

/// Recursively verify a (zero-knowledge) presentation proof inside an outer
/// circuit with a high FRI rate, re-exposing the same public inputs. The outer
/// proof needs no blinding: its witness is the inner proof, which is already
/// zero-knowledge.
fn build_wrap(inner: &CircuitData<F, C, D>) -> (CircuitData<F, C, D>, plonky2::plonk::proof::ProofWithPublicInputsTarget<D>) {
    let env = |k: &str, d: usize| std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d);
    let mut config = CircuitConfig::standard_recursion_config();
    config.fri_config.rate_bits = env("WRAP_RATE", 7);
    config.fri_config.num_query_rounds = env("WRAP_QUERIES", 12);
    config.fri_config.proof_of_work_bits = env("WRAP_POW", 16) as u32;
    let mut b = CircuitBuilder::<F, D>::new(config);
    let pt = b.add_virtual_proof_with_pis(&inner.common);
    let vd = b.constant_verifier_data(&inner.verifier_only);
    b.verify_proof::<C>(&pt, &vd, &inner.common);
    b.register_public_inputs(&pt.public_inputs);
    (b.build::<C>(), pt)
}

fn median(mut v: Vec<f64>) -> f64 { v.sort_by(|a, b| a.partial_cmp(b).unwrap()); v[v.len() / 2] }
fn quant(mut v: Vec<f64>, q: f64) -> f64 { v.sort_by(|a, b| a.partial_cmp(b).unwrap()); v[((v.len() - 1) as f64 * q).round() as usize] }

fn main() -> Result<()> {
    let envu = |k: &str, d: usize| std::env::var(k).ok().and_then(|s| s.parse::<usize>().ok()).unwrap_or(d);
    let runs = envu("RUNS", 15);
    let warmup = envu("WARMUP", 3);
    // ZK_ONLY=1: only the zero-knowledge circuit (used for the memory measurement, so that the
    // peak covers one circuit construction plus proving); NO_NEG=1 skips the under-age check.
    let zk_modes: Vec<bool> = if envu("ZK_ONLY", 0) == 1 { vec![true] } else { vec![true, false] };
    let today = 20_747; // 2026-10-21 in days since 1970-01-01
    let (pk_i, sk_i) = ml_dsa_87::try_keygen().map_err(anyhow::Error::msg)?;

    println!("n_attrs,zk,degree_bits,prove_ms_p25,prove_ms_p75,prove_ms_p50,verify_ms_p50,proof_bytes,sign_ms_p50,mldsa_verify_ms_p50,wrap_prove_ms_p50,wrap_verify_ms_p50,wrap_proof_bytes");
    let nl: Vec<usize> = std::env::var("N_LIST").ok().map(|s| s.split(',').map(|x| x.parse().unwrap()).collect()).unwrap_or(vec![1, 5, 10, 20]);
    for &n in &nl {
        for &zk in &zk_modes {
            let (data, t) = build(n, zk);
            let wrap = if zk && std::env::var("WRAP").is_ok() { Some(build_wrap(&data)) } else { None };
            let (mut wpt_ms, mut wvt_ms, mut wsize) = (vec![0.0], vec![0.0], 0usize);
            let mut attrs = vec![10_000u64]; // birth date 1997-05-19
            attrs.extend((1..n).map(|i| 1000 + i as u64));
            let (mut pt, mut vt, mut st, mut svt) = (vec![], vec![], vec![], vec![]);
            let mut size = 0;
            for k in 0..warmup + runs {
                let c = issue_cred(&attrs, today + 365);
                let (np, nv, ns, nsv) = (pt.len(), vt.len(), st.len(), svt.len());
                let t0 = Instant::now();
                let sig = sk_i.try_sign(&root_bytes(&c.root), b"pqssi+").map_err(anyhow::Error::msg)?;
                st.push(t0.elapsed().as_secs_f64() * 1e3);
                let nonce = [0; 4].map(|_| rand_f());
                let aud = [0; 4].map(|_| rand_f());
                let t0 = Instant::now();
                let proof = prove(&data, &t, &c, nonce, aud, today)?;
                pt.push(t0.elapsed().as_secs_f64() * 1e3);
                size = proof.to_bytes().len();
                // verifier: ML-DSA on the root carried in the public inputs, then the proof
                let t0 = Instant::now();
                let pi_root = HashOut { elements: proof.public_inputs[0..4].try_into().unwrap() };
                assert!(pk_i.verify(&root_bytes(&pi_root), &sig, b"pqssi+"));
                svt.push(t0.elapsed().as_secs_f64() * 1e3);
                assert_eq!(&proof.public_inputs[4..8], &nonce);
                assert_eq!(&proof.public_inputs[8..12], &aud);
                if let Some((wd, wpt)) = wrap.as_ref() {
                    let t0 = Instant::now();
                    let mut pw = PartialWitness::new();
                    pw.set_proof_with_pis_target(wpt, &proof)?;
                    let wp = wd.prove(pw)?;
                    wpt_ms.push(t0.elapsed().as_secs_f64() * 1e3);
                    wsize = wp.to_bytes().len();
                    let t0 = Instant::now();
                    wd.verify(wp)?;
                    wvt_ms.push(t0.elapsed().as_secs_f64() * 1e3);
                }
                let t0 = Instant::now();
                assert!((ADULT_DAYS..1 << 29).contains(&today), "verifier: today out of range");
                assert_eq!(proof.public_inputs.len(), 13, "public values: root[4], nonce[4], aud[4], today");
                data.verify(proof)?;
                vt.push(t0.elapsed().as_secs_f64() * 1e3);
                if k < warmup { pt.truncate(np); vt.truncate(nv); st.truncate(ns); svt.truncate(nsv); continue; }
                eprintln!("sample n={} zk={} prove_ms={:.4} verify_ms={:.4} sign_ms={:.4} mldsa_verify_ms={:.4} proof_bytes={}", n, zk, pt[pt.len() - 1], vt[vt.len() - 1], st[st.len() - 1], svt[svt.len() - 1], size);
            }
            println!("{},{},{},{:.2},{:.2},{:.2},{:.2},{},{:.3},{:.3},{:.2},{:.2},{}", n, zk, data.common.degree_bits(), quant(pt.clone(), 0.25), quant(pt.clone(), 0.75), median(pt), median(vt), size, median(st), median(svt), median(wpt_ms), median(wvt_ms), wsize);
        }
    }

    if envu("NO_NEG", 0) == 1 { return Ok(()); }
    // negative check: an under-age holder cannot produce a proof
    let (data, t) = build(1, true);
    let c = issue_cred(&[today - 1000], today + 365);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prove(&data, &t, &c, [F::ONE; 4], [F::ONE; 4], today)));
    println!("under-age proof rejected: {}", !matches!(res, Ok(Ok(_))));
    let _ = pk_i.into_bytes();
    Ok(())
}
