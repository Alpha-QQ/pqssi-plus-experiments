//! PQSSI+ presentation proof as a hand-written AIR over BabyBear, proven with
//! Plonky3's uni-STARK and the hiding FRI PCS (zero-knowledge).
//!
//! One-time credential (issued in batches; never shown twice):
//!   pk_h  = P(sk[8] || PK_DOM || 0^7)[0..8]                  (P = Poseidon2-16)
//!   root  = sponge over blocks, starting from state (pk_h || ROOT_IV):
//!           s_1 = P(pk_h || ROOT_IV); s_{k+1} = P(s_k + (B_k || 0^8))
//!           B_1 = salt[8], B_2.. = (credId, exp, schemaId, birth, attr_1, ...) padded with 0
//!   root  = s_{H-1}[0..8],  sigma = ML-DSA-87.Sign(isk, root)
//! Statement: root[8], nonce[4], aud[4], today, tid. tid identifies the presentation type
//! (schema, policy, parameter version, FRI parameters, trace height); the AIR fixes it, and as a
//! public value it enters the transcript. The AIR proves knowledge of sk, salt and
//! attributes that hash to root, birth <= today - ADULT_DAYS and exp >= today.
//! nonce and aud are public values: they enter the Fiat-Shamir transcript, so the proof is
//! bound to the session and the audience, and (with knowledge of sk) acts as a signature of
//! knowledge by the holder.
//!
//! Trace row r = [Poseidon2 columns of permutation r | SK[8] | Q[8(d-1)] | BB | EB | BR | ER | FL],
//! each of BB, EB, BR, ER holding BITS = 29 bits. BR and ER range-check birth and exp, BB and EB
//! the two differences; with today in [ADULT_DAYS, 2^29) (checked by the verifier) and 2^30 < p,
//! the field differences cannot wrap modulo p, so they imply the integer inequalities.
//! Row 0 computes pk_h; row r >= 1 computes s_r. Q is a shift register of blocks:
//! Q_{r+1}[j] = Q_r[j+8]; the transition r -> r+1 (r >= 1) absorbs Q_r[0..8].

use core::borrow::Borrow;
use core::mem::MaybeUninit;
use std::time::Instant;

use fips204::ml_dsa_87;
use fips204::traits::{Signer, Verifier as _};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL, BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
    BABYBEAR_POSEIDON2_RC_16_INTERNAL, BabyBear, GenericPoseidon2LinearLayersBabyBear,
    default_babybear_poseidon2_16,
};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_poseidon2::ExternalLayerConstants;
use p3_poseidon2_air::{Poseidon2Air, Poseidon2Cols, RoundConstants, generate_trace_rows_for_perm, num_cols};
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, Permutation, SerializingHasher};
use p3_uni_stark::{AirLayout, OpeningShape, StarkConfig, StarkSecurityParams, prove, verify};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

type F = BabyBear;
const W: usize = 16;
const SBOX_DEGREE: u64 = 7;
const SBOX_REGISTERS: usize = 1;
const HALF_FULL: usize = 4;
const PARTIAL: usize = 13;
const P_COLS: usize = num_cols::<W, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL, PARTIAL>();
const BITS: usize = 29;
const ADULT_DAYS: u32 = 6575; // 18 * 365.25 = 6574.5, rounded up
const PK_DOM: u32 = 0x504b; // "PK"
const ROOT_IV: [u32; 8] = [0x524f4f54, 1, 0, 0, 0, 0, 0, 0]; // "ROOT", version 1
const N_PV: usize = 8 + 4 + 4 + 1 + 1; // root, nonce, aud, today, type id
const TYPE_DOM: u32 = 0x54595045; // "TYPE"
const POLICY_AGE_EXP: u32 = 1; // birth <= today - ADULT_DAYS and exp >= today
const PARAM_VERSION: u32 = 1;

type P2Air = Poseidon2Air<F, GenericPoseidon2LinearLayersBabyBear, W, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL, PARTIAL>;
type Cols<T> = Poseidon2Cols<T, W, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL, PARTIAL>;

fn round_constants() -> RoundConstants<F, W, HALF_FULL, PARTIAL> {
    RoundConstants::try_from_layers(
        &ExternalLayerConstants::new(
            BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL.to_vec(),
            BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL.to_vec(),
        ),
        &BABYBEAR_POSEIDON2_RC_16_INTERNAL,
    )
    .unwrap()
}

/// Trace height for n attributes: row 0 (pk), row 1 (pk absorb), salt row, data rows,
/// raised to the hiding budget of the PCS (2 * (4 * 2 + queries) masked evaluations).
/// The height is a public protocol parameter: the issuer pads the sponge with zero blocks.
/// schemaId fixes n and the attribute layout; the AIR for n attributes accepts only this id.
fn schema_id(n: usize) -> u32 { 1000 + n as u32 }

fn data_rows(n: usize) -> usize { 3 + (3 + n).div_ceil(8) }

fn height(n: usize) -> usize {
    let data = data_rows(n);
    let budget = 2 * (4 * 2 + env("QUERIES", 100));
    data.max(budget).max(env("MIN_ROWS", 0)).next_power_of_two()
}

/// Type identifier: Poseidon2 of (TYPE_DOM, schemaId, policy, version, FRI parameters, log2 H).
/// The family of types a verifier accepts must have pairwise distinct identifiers (checked by
/// the deployment; a 31-bit value suffices for a small public family).
fn type_id(n: usize, h: usize, policy: u32) -> F {
    let mut x = [F::ZERO; W];
    let v = [TYPE_DOM, schema_id(n), policy, PARAM_VERSION, env("LOG_BLOWUP", 2) as u32, env("QUERIES", 100) as u32,
             env("ARITY", 1) as u32, env("POW", 16) as u32, env("BATCH_POW", 10) as u32, h.trailing_zeros()];
    for (i, a) in v.iter().enumerate() { x[i] = F::from_u32(*a); }
    perm(x)[0]
}

/// `h` is the type's public trace height. The constraints do not depend on it; the verifier
/// checks the proof's height against it (`PresVerifier::verify`).
struct PqssiAir { p2: P2Air, h: usize, n: usize, mask: usize, tid: F }

impl PqssiAir {
    /// Queue length: blocks B_1..B_{d-1} for the d = data_rows(n) rows that absorb data;
    /// later rows absorb zero blocks, which the shift register supplies.
    fn ql(&self) -> usize { 8 * (data_rows(self.n) - 1) }
    fn sk_off(&self) -> usize { P_COLS }
    fn q_off(&self) -> usize { P_COLS + 8 }
    fn bb_off(&self) -> usize { self.q_off() + self.ql() }
    fn eb_off(&self) -> usize { self.bb_off() + BITS }
    fn br_off(&self) -> usize { self.eb_off() + BITS }
    fn er_off(&self) -> usize { self.br_off() + BITS }
    fn fl_off(&self) -> usize { self.er_off() + BITS }
}

impl BaseAir<F> for PqssiAir {
    fn width(&self) -> usize { self.fl_off() + 1 }
    fn num_public_values(&self) -> usize { N_PV }
}

fn out_of<T: Copy>(c: &Cols<T>) -> [T; W] { c.ending_full_rounds[HALF_FULL - 1].post }

impl<AB: AirBuilder<F = F>> Air<AB> for PqssiAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.current_slice(), main.next_slice());
        let lp: &Cols<AB::Var> = local[..P_COLS].borrow();
        let np: &Cols<AB::Var> = next[..P_COLS].borrow();
        if self.mask & 1 != 0 { p3_poseidon2_air::eval(&self.p2, builder, lp); }

        let pv: Vec<AB::Expr> = builder.public_values().iter().map(|&x| x.into()).collect();
        let (root, today) = (&pv[0..8], pv[16].clone());
        // the type identifier is fixed by the AIR
        builder.when_first_row().assert_eq(pv[17].clone(), AB::Expr::from(self.tid));
        let lout = out_of(lp);
        let (sk, q) = (&local[self.sk_off()..self.sk_off() + 8], &local[self.q_off()..self.q_off() + self.ql()]);
        let nq = &next[self.q_off()..self.q_off() + self.ql()];
        let bb = &local[self.bb_off()..self.bb_off() + BITS];
        let eb = &local[self.eb_off()..self.eb_off() + BITS];
        let br = &local[self.br_off()..self.br_off() + BITS];
        let er = &local[self.er_off()..self.er_off() + BITS];

        // Row 0: input (sk || PK_DOM || 0^7); policy checks on the blocks in Q_0.
        if self.mask & 2 != 0 {
            let mut b = builder.when_first_row();
            for i in 0..8 { b.assert_eq(lp.inputs[i].clone(), sk[i].clone()); }
            b.assert_eq(lp.inputs[8].clone(), AB::Expr::from(F::from_u32(PK_DOM)));
            for i in 9..W { b.assert_zero(lp.inputs[i].clone()); }
            for i in 0..8 { b.assert_zero(q[i].clone()); }
            let (exp, birth) = (q[17].clone(), q[19].clone());
            b.assert_eq(q[18].clone(), AB::Expr::from(F::from_u32(schema_id(self.n))));
            // padding cells after (meta, attrs) in the last data block are zero
            for j in 19 + self.n..self.ql() { b.assert_zero(q[j].clone()); }
            let (mut sb, mut se, mut sr, mut sx) = (AB::Expr::ZERO, AB::Expr::ZERO, AB::Expr::ZERO, AB::Expr::ZERO);
            for i in 0..BITS {
                let w = AB::Expr::from(F::from_u32(1 << i));
                for v in [&bb[i], &eb[i], &br[i], &er[i]] { b.assert_bool(v.clone()); }
                sb += bb[i].clone().into() * w.clone();
                se += eb[i].clone().into() * w.clone();
                sr += br[i].clone().into() * w.clone();
                sx += er[i].clone().into() * w;
            }
            // birth, exp in [0, 2^29); today - ADULT - birth and exp - today in [0, 2^29)
            // MASK bit 32 off reproduces the earlier AIR without these two checks (wrap-around test)
            if self.mask & 32 != 0 {
                b.assert_eq(sr, birth.clone().into());
                b.assert_eq(sx, exp.clone().into());
            }
            b.assert_eq(sb, today.clone() - AB::Expr::from(F::from_u32(ADULT_DAYS)) - birth.into());
            b.assert_eq(se, exp.into() - today.clone());
        }
        // Every transition r -> r+1 absorbs Q_r[0..8] into the rate (Q_0[0..8] = 0). The
        // capacity is carried over, except on 0 -> 1 where it is reset to ROOT_IV; the flag
        // column FL (1 on row 0, 0 elsewhere) selects that case. Uni-STARK's degree model
        // only allows row selectors as the outer filter, so FL is a committed column rather
        // than the expression (1 - is_first_row).
        let (fl, nfl) = (local[self.fl_off()].clone(), next[self.fl_off()].clone());
        builder.when_first_row().assert_one(fl.clone());
        if self.mask & 4 != 0 {
            let mut b = builder.when_transition();
            b.assert_zero(nfl);
            for i in 0..8 {
                b.assert_eq(np.inputs[i].clone(), lout[i].clone().into() + q[i].clone().into());
                let cap: AB::Expr = lout[8 + i].clone().into();
                let iv = AB::Expr::from(F::from_u32(ROOT_IV[i]));
                b.assert_eq(np.inputs[8 + i].clone(), cap.clone() + fl.clone().into() * (iv - cap));
            }
        }
        // Every transition: shift the block queue by one block, refill with zeros.
        if self.mask & 8 != 0 {
            let ql = self.ql();
            let mut b = builder.when_transition();
            for j in 0..ql - 8 { b.assert_eq(nq[j].clone(), q[j + 8].clone()); }
            for j in ql - 8..ql { b.assert_zero(nq[j].clone()); }
        }
        // Last row: the sponge output is the public root.
        if self.mask & 16 == 0 { return; }
        let mut b = builder.when_last_row();
        for i in 0..8 { b.assert_eq(lout[i].clone(), root[i].clone()); }
    }
}

// ---------- native side (issuer, holder) ----------

struct Cred { sk: [F; 8], q0: Vec<F>, root: [F; 8] }

fn perm(x: [F; W]) -> [F; W] { let mut s = x; default_babybear_poseidon2_16().permute_mut(&mut s); s }

/// Blocks B_1..B_{H-1} as laid out in Q_0 (B_1 is unused and zero).
fn blocks(n: usize, salt: [F; 8], meta: [F; 3], attrs: &[F]) -> Vec<F> {
    let mut q = vec![F::ZERO; 8 * (data_rows(n) - 1)];
    q[8..16].copy_from_slice(&salt);
    let data: Vec<F> = meta.iter().chain(attrs.iter()).copied().collect();
    q[16..16 + data.len()].copy_from_slice(&data);
    q
}

/// Uniform field element by rejection sampling (no modulo bias).
fn rand_field<R: RngExt>(rng: &mut R) -> F {
    loop {
        let x = rng.random::<u32>() & 0x7fff_ffff;
        if x < F::ORDER_U32 { return F::from_u32(x); }
    }
}

/// The issuer's check of the schema ranges: compared attributes (birth, exp) lie in [0, 2^29).
fn issuer_accepts(birth: u32, exp: u32) -> bool { birth < 1 << BITS && exp < 1 << BITS }

/// Honest issuance: refuses attributes outside the schema ranges.
fn issue_checked<R: RngExt>(rng: &mut R, h: usize, birth: u32, exp: u32, extra: &[u32]) -> Option<Cred> {
    if issuer_accepts(birth, exp) { Some(issue(rng, h, birth, exp, extra)) } else { None }
}

/// Issuance without the range check (used to build malicious test credentials).
fn issue<R: RngExt>(rng: &mut R, h: usize, birth: u32, exp: u32, extra: &[u32]) -> Cred {
    let rnd = |rng: &mut R| rand_field(rng);
    let sk: [F; 8] = core::array::from_fn(|_| rnd(rng));
    let salt: [F; 8] = core::array::from_fn(|_| rnd(rng));
    let meta = [rnd(rng), F::from_u32(exp), F::from_u32(schema_id(1 + extra.len()))];
    let mut attrs = vec![F::from_u32(birth)];
    attrs.extend(extra.iter().map(|&a| F::from_u32(a)));
    let q0 = blocks(attrs.len(), salt, meta, &attrs);
    Cred { sk, root: root_of(&sk, &q0, h), q0 }
}

/// Root over the blocks in q0 for trace height h (h is a public scheme parameter).
fn root_of(sk: &[F; 8], q0: &[F], h: usize) -> [F; 8] {
    // pk_h is what the holder hands the issuer; the issuer then computes the root.
    let mut x = [F::ZERO; W];
    x[..8].copy_from_slice(sk);
    x[8] = F::from_u32(PK_DOM);
    let pk = perm(x);
    let mut s = [F::ZERO; W];
    s[..8].copy_from_slice(&pk[..8]);
    for i in 0..8 { s[8 + i] = F::from_u32(ROOT_IV[i]); }
    s = perm(s);
    for r in 1..h - 1 {
        for i in 0..8 { s[i] += q0.get(8 * r + i).copied().unwrap_or(F::ZERO); }
        s = perm(s);
    }
    core::array::from_fn(|i| s[i])
}

fn trace(air: &PqssiAir, c: &Cred, today: u32) -> RowMajorMatrix<F> {
    let birth = c.q0[19].as_canonical_u32();
    let exp = c.q0[17].as_canonical_u32();
    assert!(birth < 1 << BITS && exp < 1 << BITS, "attribute out of range");
    assert!(birth + ADULT_DAYS <= today && exp >= today, "policy not satisfied"); // honest builder refuses
    trace_raw(air, c, today)
}

/// Fills the bit columns with the low BITS bits of the canonical field values, without checking
/// anything. A malicious prover can use it to try out-of-range assignments.
fn trace_raw(air: &PqssiAir, c: &Cred, today: u32) -> RowMajorMatrix<F> { trace_at(air, c, today, air.h) }

/// Trace of height h (a malicious prover may choose a height other than the type's).
fn trace_at(air: &PqssiAir, c: &Cred, today: u32, h: usize) -> RowMajorMatrix<F> {
    let (w, ql) = (air.width(), air.ql());
    let rc = round_constants();
    let mut rows = vec![F::ZERO; h * w];
    let mut input = [F::ZERO; W];
    input[..8].copy_from_slice(&c.sk);
    input[8] = F::from_u32(PK_DOM);
    let mut q = c.q0.clone();
    let t = F::from_u32(today);
    let db = (t - F::from_u32(ADULT_DAYS) - c.q0[19]).as_canonical_u32();
    let de = (c.q0[17] - t).as_canonical_u32();
    let (bv, ev) = (c.q0[19].as_canonical_u32(), c.q0[17].as_canonical_u32());
    for r in 0..h {
        let row = &mut rows[r * w..(r + 1) * w];
        let mut cols: Vec<MaybeUninit<F>> = vec![MaybeUninit::uninit(); P_COLS];
        let pc: &mut Cols<MaybeUninit<F>> = cols.as_mut_slice().borrow_mut_cols();
        generate_trace_rows_for_perm::<F, GenericPoseidon2LinearLayersBabyBear, W, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL, PARTIAL>(pc, input, &rc);
        for (dst, src) in row[..P_COLS].iter_mut().zip(cols.iter()) { *dst = unsafe { src.assume_init() }; }
        let out = out_of::<F>(row[..P_COLS].borrow());
        row[P_COLS..P_COLS + 8].copy_from_slice(&c.sk);
        row[P_COLS + 8..P_COLS + 8 + ql].copy_from_slice(&q);
        for i in 0..BITS {
            row[P_COLS + 8 + ql + i] = F::from_u32((db >> i) & 1);
            row[P_COLS + 8 + ql + BITS + i] = F::from_u32((de >> i) & 1);
            row[P_COLS + 8 + ql + 2 * BITS + i] = F::from_u32((bv >> i) & 1);
            row[P_COLS + 8 + ql + 3 * BITS + i] = F::from_u32((ev >> i) & 1);
        }
        row[air.fl_off()] = F::from_bool(r == 0);
        // next input
        if r == 0 {
            input[..8].copy_from_slice(&out[..8]);
            for i in 0..8 { input[8 + i] = F::from_u32(ROOT_IV[i]); }
        } else {
            input = out;
            for i in 0..8 { input[i] += q[i]; }
        }
        q.drain(..8);
        q.extend([F::ZERO; 8]);
    }
    RowMajorMatrix::new(rows, w)
}

trait BorrowMutCols { fn borrow_mut_cols(&mut self) -> &mut Cols<MaybeUninit<F>>; }
impl BorrowMutCols for [MaybeUninit<F>] {
    fn borrow_mut_cols(&mut self) -> &mut Cols<MaybeUninit<F>> { core::borrow::BorrowMut::borrow_mut(self) }
}

// ---------- STARK configuration ----------

type Challenge = BinomialExtensionField<F, 4>;
type ByteHash = Keccak256Hash;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type ValMmcs = MerkleTreeHidingMmcs<[F; p3_keccak::VECTOR_LEN], [u64; p3_keccak::VECTOR_LEN], FieldHash, MyCompress, StdRng, 2, 4, 4>;
type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<F, HashChallenger<u8, ByteHash, 32>>;
type Dft = p3_dft::Radix2DitParallel<F>;
type Pcs = HidingFriPcs<F, Dft, ValMmcs, ChallengeMmcs, StdRng>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

fn env(k: &str, d: usize) -> usize { std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d) }

fn fri_params(val_mmcs: ValMmcs, batch_pow: usize) -> FriParameters<ChallengeMmcs> {
    FriParameters {
        log_blowup: env("LOG_BLOWUP", 2),
        log_final_poly_len: 0,
        max_log_arity: env("ARITY", 1),
        num_queries: env("QUERIES", 100),
        batch_proof_of_work_bits: batch_pow,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: env("POW", 16),
        mmcs: ChallengeMmcs::new(val_mmcs),
    }
}

/// STARK configuration; the hiding randomness of the PCS and of the Merkle leaves is drawn
/// from an OS-seeded CSPRNG. Prover and verifier each build their own instance.
fn config() -> MyConfig {
    let u64_hash = U64Hash::new(KeccakF {});
    let val_mmcs = ValMmcs::new(FieldHash::new(u64_hash), MyCompress::new(u64_hash), 0, rand::make_rng::<StdRng>());
    let fri = fri_params(val_mmcs.clone(), env("BATCH_POW", 10));
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri, 4, rand::make_rng::<StdRng>());
    MyConfig::new(pcs, Challenger::from_hasher(vec![], Keccak256Hash {}))
}

/// Security estimates of Plonky3 at the pinned commit for the real instance shape (this AIR,
/// trace height h, hiding PCS with 4 random codewords, Keccak-256 = 128-bit collision
/// resistance, degree-4 extension of BabyBear: floor(log2 |K|) = floor(123.6) = 123 bits,
/// max_combo 2). batch_pow is the batching proof-of-work credited by the estimator.
fn security_params(air: &PqssiAir, h: usize, batch_pow: usize) -> StarkSecurityParams {
    let u64_hash = U64Hash::new(KeccakF {});
    let val_mmcs = ValMmcs::new(FieldHash::new(u64_hash), MyCompress::new(u64_hash), 0, StdRng::seed_from_u64(0));
    let fri = fri_params(val_mmcs, batch_pow);
    StarkSecurityParams::from_air::<F, Challenge, _>(
        fri.security_regime(),
        air,
        AirLayout::from_air::<F>(air),
        TwoAdicMultiplicativeCoset::new(F::ONE, h.trailing_zeros() as usize).unwrap(),
        123,
        128,
        2,
        OpeningShape::hiding(4),
        fri.grinding_sites(),
    )
}

fn quant(mut v: Vec<f64>, q: f64) -> f64 { v.sort_by(|a, b| a.partial_cmp(b).unwrap()); v[((v.len() - 1) as f64 * q).round() as usize] }
fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let m = v.len() / 2;
    if v.len() % 2 == 1 { v[m] } else { (v[m - 1] + v[m]) / 2.0 }
}
fn root_bytes(r: &[F]) -> Vec<u8> { r.iter().flat_map(|x| x.as_canonical_u32().to_le_bytes()).collect() }

/// A presentation as it travels: STARK proof, issuer-signed root, issuer signature, nonce.
/// The verifier supplies aud, today and the type identifier itself.
struct Presentation { proof: p3_uni_stark::Proof<MyConfig>, root: [F; 8], sig: [u8; ml_dsa_87::SIG_LEN], nonce: [F; 4] }

/// Verifier of one presentation type: own STARK configuration instance, own audience and day,
/// the type's AIR and height, and a record of issued and consumed nonces.
struct PresVerifier<'a> {
    air: &'a PqssiAir,
    cfg: MyConfig,
    ipk: &'a ml_dsa_87::PublicKey,
    aud: [F; 4],
    today: u32,
    /// nonce -> (type identifier, reference day, time of issue); entries are removed on use
    issued: std::collections::HashMap<[u32; 4], (u32, u32, Instant)>,
    ttl_ms: u128,
}

fn key(n: &[F; 4]) -> [u32; 4] { n.map(|x| x.as_canonical_u32()) }

impl<'a> PresVerifier<'a> {
    fn new(air: &'a PqssiAir, ipk: &'a ml_dsa_87::PublicKey, aud: [F; 4], today: u32) -> Self {
        PresVerifier { air, cfg: config(), ipk, aud, today, issued: Default::default(), ttl_ms: env("NONCE_TTL_MS", 60_000) as u128 }
    }
    /// Fresh nonce, recorded as issued and not yet used.
    fn challenge<R: RngExt>(&mut self, rng: &mut R) -> [F; 4] {
        let n: [F; 4] = core::array::from_fn(|_| rand_field(rng));
        self.issued.insert(key(&n), (self.air.tid.as_canonical_u32(), self.today, Instant::now()));
        n
    }
    fn statement(&self, root: &[F; 8], nonce: &[F; 4]) -> Vec<F> {
        let mut pv = root.to_vec();
        pv.extend(nonce);
        pv.extend(self.aud);
        pv.push(F::from_u32(self.today));
        pv.push(self.air.tid);
        pv
    }
    /// Checks in order: reference time, trace height, nonce record, issuer signature, STARK.
    /// Returns the outcome and the ML-DSA and STARK verification times (ms).
    fn verify(&mut self, p: &Presentation) -> (Result<(), &'static str>, f64, f64) {
        if !(ADULT_DAYS..1 << BITS).contains(&self.today) { return (Err("rejected by the reference-time check"), 0.0, 0.0); }
        // the zero-knowledge mode doubles the trace, so degree_bits = log2(H) + 1
        if p.proof.degree_bits != self.air.h.trailing_zeros() as usize + 1 { return (Err("rejected by the height check"), 0.0, 0.0); }
        // the nonce must have been issued by this verifier, for this type and day, and not have expired
        match self.issued.get(&key(&p.nonce)) {
            Some(&(tid, day, at)) if tid == self.air.tid.as_canonical_u32() && day == self.today
                && at.elapsed().as_millis() <= self.ttl_ms => {}
            _ => return (Err("rejected by the nonce record"), 0.0, 0.0),
        }
        let t0 = Instant::now();
        let sig_ok = self.ipk.verify(&root_bytes(&p.root), &p.sig, b"pqssi+");
        let ms = t0.elapsed().as_secs_f64() * 1e3;
        if !sig_ok { return (Err("rejected by ML-DSA verification"), ms, 0.0); }
        let t0 = Instant::now();
        let ok = verify(&self.cfg, self.air, &p.proof, &self.statement(&p.root, &p.nonce)).is_ok();
        let vs = t0.elapsed().as_secs_f64() * 1e3;
        if !ok { return (Err("rejected by the STARK verifier"), ms, vs); }
        self.issued.remove(&key(&p.nonce)); // consumed: each nonce is accepted at most once
        (Ok(()), ms, vs)
    }
}

/// Prove with a fresh prover configuration; "prover returned an error" / "prover panicked"
/// are reported as such and are not counted as verifier rejections.
fn try_prove(air: &PqssiAir, tr: RowMajorMatrix<F>, pv: &[F]) -> Result<p3_uni_stark::Proof<MyConfig>, &'static str> {
    let cfg = config();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prove(&cfg, air, tr, pv))) {
        Ok(Ok(p)) => Ok(p),
        Ok(Err(_)) => Err("prover returned an error"),
        Err(_) => Err("prover panicked"),
    }
}

/// Outcome string of one negative case, printed as
/// `negative test [layer=<expected layer>] [<name>]: <outcome>` ("accepted" if it verified).
fn report(layer: &str, name: &str, outcome: &str, bad: &mut Vec<String>, expect: &str) {
    eprintln!("negative test [layer={}] [{}]: {}", layer, name, outcome);
    if outcome != expect { bad.push(format!("{}: {} (expected {})", name, outcome, expect)); }
}

fn outcome(r: Result<(), &'static str>) -> &'static str { match r { Ok(()) => "accepted", Err(e) => e } }

/// Negative tests for one presentation type, each run through the full verifier.
fn negative_tests<R: RngExt>(rng: &mut R, air: &PqssiAir, n: usize, today: u32,
                             ipk: &ml_dsa_87::PublicKey, isk: &ml_dsa_87::PrivateKey) -> Vec<String> {
    let h = air.h;
    let extra: Vec<u32> = (1..n as u32).map(|i| 1000 + i).collect();
    let sign = |r: &[F; 8]| isk.try_sign(&root_bytes(r), b"pqssi+").unwrap();
    let mut bad = vec![];
    let aud: [F; 4] = core::array::from_fn(|_| rand_field(rng));
    let mut v = PresVerifier::new(air, ipk, aud, today);
    let ranges_on = air.mask & 32 != 0;

    // honest presentation, used by the session and replay cases
    let c = issue(rng, h, 10_000, today + 365, &extra);
    let nonce = v.challenge(rng);
    let proof = try_prove(air, trace(air, &c, today), &v.statement(&c.root, &nonce)).unwrap();
    let honest = Presentation { proof, root: c.root, sig: sign(&c.root), nonce };
    // positive control: an independent verifier instance (own configuration) accepts it
    report("positive control", "fresh verifier instance, unchanged statement", outcome(v.verify(&honest).0), &mut bad, "accepted");

    // session layer: the same proof under another issued nonce
    let n2 = v.challenge(rng);
    let moved = Presentation { nonce: n2, ..clone_pres(&honest) };
    report("session/transcript", "changed nonce", outcome(v.verify(&moved).0), &mut bad, "rejected by the STARK verifier");
    // ... at a verifier with another audience that issued the same nonce
    let mut v2 = PresVerifier::new(air, ipk, core::array::from_fn(|_| rand_field(rng)), today);
    v2.issued.insert(key(&honest.nonce), (air.tid.as_canonical_u32(), today, Instant::now()));
    report("session/transcript", "changed audience", outcome(v2.verify(&clone_pres(&honest)).0), &mut bad, "rejected by the STARK verifier");
    // ... and a proof made for another reference time (yesterday) under a nonce issued for today
    let cy = issue(rng, h, 10_000, today + 365, &extra);
    let ny = v.challenge(rng);
    let mut pvy = v.statement(&cy.root, &ny);
    pvy[16] = F::from_u32(today - 1);
    let py = try_prove(air, trace(air, &cy, today - 1), &pvy).unwrap();
    report("session/transcript", "proof for another reference time", outcome(v.verify(&Presentation { proof: py, root: cy.root, sig: sign(&cy.root), nonce: ny }).0),
           &mut bad, "rejected by the STARK verifier");
    // nonce record: a valid presentation under a nonce issued for another type, for another day,
    // or one that has expired
    for (name, tid, day, expire) in [("nonce issued for another type", air.tid.as_canonical_u32() ^ 1, today, false),
                                      ("nonce issued for another day", air.tid.as_canonical_u32(), today - 1, false),
                                      ("expired nonce", air.tid.as_canonical_u32(), today, true)] {
        let cn = issue(rng, h, 10_000, today + 365, &extra);
        let nn: [F; 4] = core::array::from_fn(|_| rand_field(rng));
        v.issued.insert(key(&nn), (tid, day, Instant::now()));
        let pn = try_prove(air, trace(air, &cn, today), &v.statement(&cn.root, &nn)).unwrap();
        let ttl = v.ttl_ms;
        if expire { v.ttl_ms = 0; std::thread::sleep(std::time::Duration::from_millis(2)); }
        let o = outcome(v.verify(&Presentation { proof: pn, root: cn.root, sig: sign(&cn.root), nonce: nn }).0);
        v.ttl_ms = ttl;
        report("nonce record", name, o, &mut bad, "rejected by the nonce record");
    }
    // nonce record: exact replay, and a fresh proof (other credential) under the consumed nonce
    report("nonce record", "replayed presentation", outcome(v.verify(&clone_pres(&honest)).0), &mut bad, "rejected by the nonce record");
    let c2 = issue(rng, h, 10_000, today + 365, &extra);
    let p2 = try_prove(air, trace(air, &c2, today), &v.statement(&c2.root, &honest.nonce)).unwrap();
    report("nonce record", "new proof under a used nonce", outcome(v.verify(&Presentation { proof: p2, root: c2.root, sig: sign(&c2.root), nonce: honest.nonce }).0),
           &mut bad, "rejected by the nonce record");

    // issuer-signature layer: a valid STARK for a root the issuer never signed
    let cu = issue(rng, h, 10_000, today + 365, &extra);
    let nu = v.challenge(rng);
    let pu = try_prove(air, trace(air, &cu, today), &v.statement(&cu.root, &nu)).unwrap();
    report("issuer signature", "valid proof, root not signed by the issuer",
           outcome(v.verify(&Presentation { proof: pu, root: cu.root, sig: honest.sig, nonce: nu }).0), &mut bad, "rejected by ML-DSA verification");

    // type layer: a proof for another type of the same shape (other policy identifier)
    let air_b = PqssiAir { p2: P2Air::new(round_constants()), h, n, mask: air.mask, tid: type_id(n, h, POLICY_AGE_EXP + 1) };
    let ct = issue(rng, h, 10_000, today + 365, &extra);
    let nt = v.challenge(rng);
    let mut pvb = v.statement(&ct.root, &nt);
    pvb[17] = air_b.tid;
    let pt = try_prove(&air_b, trace(&air_b, &ct, today), &pvb).unwrap();
    report("type binding", "proof for another type of the same shape",
           outcome(v.verify(&Presentation { proof: pt, root: ct.root, sig: sign(&ct.root), nonce: nt }).0), &mut bad, "rejected by the STARK verifier");

    // height layer: a signed root at height 2H, proven at height 2H against this type's AIR
    let ch = issue(rng, 2 * h, 10_000, today + 365, &extra);
    let nh = v.challenge(rng);
    let pvh = v.statement(&ch.root, &nh);
    match try_prove(air, trace_at(air, &ch, today, 2 * h), &pvh) {
        Ok(ph) => {
            // diagnostic: the STARK check alone accepts it, so the height check is needed
            let alone = verify(&config(), air, &ph, &pvh).is_ok();
            eprintln!("diagnostic [height 2H, STARK check alone]: {}", if alone { "accepted" } else { "rejected" });
            report("height check", "proof at height 2H",
                   outcome(v.verify(&Presentation { proof: ph, root: ch.root, sig: sign(&ch.root), nonce: nh }).0), &mut bad, "rejected by the height check");
        }
        Err(e) => report("height check", "proof at height 2H", e, &mut bad, "rejected by the height check"),
    }

    // input validation: the issuer refuses an out-of-range attribute
    let refused = issue_checked(rng, h, F::ORDER_U32 - 1, today + 365, &extra).is_none();
    report("input validation", "issuer, birth = p-1", if refused { "refused" } else { "accepted" }, &mut bad, "refused");
    // input validation: the honest trace builder refuses
    for (name, b, e) in [("birth = p-1", F::ORDER_U32 - 1, today), ("underage", today - ADULT_DAYS + 1, today + 365), ("expired", 10_000, today - 1)] {
        let cc = issue(rng, h, b, e, &extra);
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // the expected refusal is a panic; keep stderr clean
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| trace(air, &cc, today))).is_err();
        std::panic::set_hook(hook);
        report("input validation", &format!("honest builder, {}", name), if refused { "refused" } else { "accepted" }, &mut bad, "refused");
    }

    // AIR layer: malicious traces from the unchecked generator, with a recomputed root that the
    // issuer signed, so that only the constraints can fail.
    // wrap-around: birth = p-1 makes today - ADULT - birth a small field element; with the range
    // checks on the attributes (MASK bit 32) it must fail, without them it verifies (ablation)
    let cw = issue(rng, h, F::ORDER_U32 - 1, today, &extra);
    let expect_wrap = if ranges_on { "rejected by the STARK verifier" } else { "accepted" };
    air_case(rng, &mut v, isk, "wrap-around birth date", &cw, trace_raw(air, &cw, today), expect_wrap, &mut bad);
    let mut cp = issue(rng, h, 10_000, today + 365, &extra);
    if 19 + n < air.ql() {
        cp.q0[19 + n] = F::ONE;
        cp.root = root_of(&cp.sk, &cp.q0, h);
        air_case(rng, &mut v, isk, "nonzero padding", &cp, trace_raw(air, &cp, today), "rejected by the STARK verifier", &mut bad);
    }
    let ct2 = issue(rng, h, 10_000, today + 365, &extra);
    let mut tampered = trace(air, &ct2, today);
    tampered.values[air.q_off() + 19] += F::ONE;
    air_case(rng, &mut v, isk, "tampered birth cell", &ct2, tampered, "rejected by the STARK verifier", &mut bad);
    let cu2 = issue(rng, h, today - ADULT_DAYS + 1, today + 365, &extra);
    air_case(rng, &mut v, isk, "underage holder", &cu2, trace_raw(air, &cu2, today), "rejected by the STARK verifier", &mut bad);
    let ce = issue(rng, h, 10_000, today - 1, &extra);
    air_case(rng, &mut v, isk, "expired credential", &ce, trace_raw(air, &ce, today), "rejected by the STARK verifier", &mut bad);
    // wrong holder secret: the thief knows salt, metadata, attributes and the signed root
    let mut cs = issue(rng, h, 10_000, today + 365, &extra);
    let signed = cs.root;
    cs.sk = core::array::from_fn(|_| rand_field(rng));
    let tr = trace_raw(air, &cs, today);
    cs.root = signed;
    air_case(rng, &mut v, isk, "wrong holder secret", &cs, tr, "rejected by the STARK verifier", &mut bad);
    bad
}

fn air_case<R: RngExt>(rng: &mut R, v: &mut PresVerifier, isk: &ml_dsa_87::PrivateKey, name: &str, cc: &Cred,
                       tr: RowMajorMatrix<F>, expect: &str, bad: &mut Vec<String>) {
    let nn = v.challenge(rng);
    let o = match try_prove(v.air, tr, &v.statement(&cc.root, &nn)) {
        Ok(p) => {
            let sig = isk.try_sign(&root_bytes(&cc.root), b"pqssi+").unwrap();
            outcome(v.verify(&Presentation { proof: p, root: cc.root, sig, nonce: nn }).0)
        }
        Err(e) => e,
    };
    report("AIR", name, o, bad, expect);
}

fn clone_pres(p: &Presentation) -> Presentation {
    let bytes = postcard::to_allocvec(&p.proof).unwrap();
    Presentation { proof: postcard::from_bytes(&bytes).unwrap(), root: p.root, sig: p.sig, nonce: p.nonce }
}

fn main() {
    let runs = env("RUNS", 15);
    let warmup = env("WARMUP", 3);
    let neg_only = env("NEG_ONLY", 0) == 1;
    // Secrets, salts, nonces and audiences come from an OS-seeded CSPRNG.
    let mut rng: StdRng = rand::make_rng();
    let today: u32 = 20_747; // 2026-10-21
    let (ipk, isk) = ml_dsa_87::try_keygen().unwrap();

    let bits = p3_uni_stark::ConjecturedSecurity::compute_ldt_only(
        env("LOG_BLOWUP", 2), env("QUERIES", 100), env("POW", 16), 128, 123).security_bits;
    eprintln!("log_blowup={} queries={} pow={} batch_pow={} conjectured_ldt_bits<={}", env("LOG_BLOWUP", 2), env("QUERIES", 100), env("POW", 16), env("BATCH_POW", 10), bits);
    if env("BITS_ONLY", 0) == 1 { return; }
    let ns: Vec<usize> = if env("MIN_ROWS", 0) > 0 { vec![1] } else if env("N_ONLY", 0) > 0 { vec![env("N_ONLY", 0)] } else { vec![1, 5, 10, 20, 40] };
    if !neg_only {
        println!("n_attrs,height,width,prove_ms_p50,prove_ms_p25,prove_ms_p75,verify_ms_p50,proof_bytes_p50,sign_ms_p50,mldsa_verify_ms_p50");
    }
    let mut failures = vec![];
    for &n in &ns {
        let h = height(n);
        let air = PqssiAir { p2: P2Air::new(round_constants()), h, n, mask: env("MASK", 63), tid: type_id(n, h, POLICY_AGE_EXP) };
        if neg_only {
            failures.extend(negative_tests(&mut rng, &air, n, today, &ipk, &isk));
            continue;
        }
        let extra: Vec<u32> = (1..n as u32).map(|i| 1000 + i).collect();
        let aud: [F; 4] = core::array::from_fn(|_| rand_field(&mut rng));
        let mut verifier = PresVerifier::new(&air, &ipk, aud, today);
        let (mut pt, mut vt, mut st, mut svt, mut sizes) = (vec![], vec![], vec![], vec![], vec![]);
        let (mut it, mut et) = (vec![], vec![]);
        for k in 0..warmup + runs {
            let ti = Instant::now();
            let c = issue_checked(&mut rng, h, 10_000, today + 365, &extra).expect("issuer refused an honest credential");
            let t0 = Instant::now();
            let sig = isk.try_sign(&root_bytes(&c.root), b"pqssi+").unwrap();
            let sign_ms = t0.elapsed().as_secs_f64() * 1e3;
            let issue_ms = ti.elapsed().as_secs_f64() * 1e3;
            let nonce = verifier.challenge(&mut rng);
            let pv = verifier.statement(&c.root, &nonce);
            let cfg = config(); // prover's configuration, created before the timer
            let t0 = Instant::now();
            let tr = trace(&air, &c, today);
            let proof = prove(&cfg, &air, tr, &pv).unwrap();
            let prove_ms = t0.elapsed().as_secs_f64() * 1e3;
            if k == warmup {
                let pr = proof.proven_security(&security_params(&air, h, env("BATCH_POW", 10)));
                let cj = proof.conjectured_security(&security_params(&air, h, env("BATCH_POW", 10))).security_bits;
                let cj0 = proof.conjectured_security(&security_params(&air, h, 0)).security_bits;
                eprintln!("security n={} conjectured_bits={} proven_bits={} proven_udr_bits={} proven_ldr_bits={} legacy_bits={} conjectured_no_batch_pow_bits={}",
                    n, cj, pr.security_bits(), pr.unique_decoding_bits, pr.list_decoding_bits,
                    proof.legacy_security(&security_params(&air, h, env("BATCH_POW", 10))).security_bits, cj0);
            }
            let size = postcard::to_allocvec(&proof).unwrap().len();
            let pres = Presentation { proof, root: c.root, sig, nonce };
            let (r, mldsa_ms, stark_ms) = verifier.verify(&pres);
            r.expect("honest presentation rejected");
            if k < warmup { continue; }
            it.push(issue_ms); st.push(sign_ms); pt.push(prove_ms); svt.push(mldsa_ms); vt.push(stark_ms);
            sizes.push(size as f64);
            et.push(prove_ms + mldsa_ms + stark_ms);
            eprintln!("sample n={} k={} issue_ms={:.4} sign_ms={:.4} prove_ms={:.4} mldsa_verify_ms={:.4} verify_ms={:.4} proof_bytes={}", n, k - warmup, issue_ms, sign_ms, prove_ms, mldsa_ms, stark_ms, size);
        }
        // presentation bytes on the wire: STARK proof + 4627-byte signature + root and nonce (12 field elements);
        // the verifier holds aud, today and the type identifier itself
        // (conservative: aud, today and the type identifier are also known to the verifier)
        let wire = median(sizes.clone()) as usize + 4627 + 4 * 12;
        eprintln!("e2e n={} issue_ms_p50={:.3} wire_bytes_p50={} prove+verify_ms_p50={:.2} verifier_total_ms_p50={:.3}",
            n, median(it), wire, median(et), median(svt.iter().zip(vt.iter()).map(|(a, b)| a + b).collect()));
        println!("{},{},{},{:.2},{:.2},{:.2},{:.2},{},{:.3},{:.3}", n, h, air.width(), median(pt.clone()), quant(pt.clone(), 0.25), quant(pt, 0.75), median(vt), median(sizes), median(st), median(svt));
    }
    if !failures.is_empty() {
        for f in &failures { eprintln!("UNEXPECTED {}", f); }
        if env("ABLATION", 0) != 1 { std::process::exit(1); }
    }
}
