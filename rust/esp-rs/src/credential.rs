// SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Anonymous credentials for the Typed Hive (GAP-017, ADR-0021).
//!
//! Thin, stateless wrappers around the `zkryptium` crate (Apache-2.0), which implements the
//! IRTF CFRG drafts:
//!
//! - BBS signatures (`draft-irtf-cfrg-bbs-signatures-12`);
//! - blind BBS signatures (`draft-irtf-cfrg-bbs-blind-signatures-02`);
//! - BBS per-verifier linkability (`draft-irtf-cfrg-bbs-per-verifier-linkability-03`).
//!
//! Ciphersuite `BLS12-381-SHA-256`. No pairing or proof arithmetic is implemented here.
//!
//! Flow:
//! 1. The member commits to a random prover nym secret (`commit`).
//! 2. The issuer blind-signs that commitment together with public attributes, adding its
//!    own entropy (`blind_sign`). The issuer never learns the member's nym secret.
//! 3. The member checks the signature and derives the final nym secret (`finalize`).
//! 4. For each episode, the member proves possession of the credential, discloses only
//!    the attributes the policy asks for, and outputs a pseudonym for the episode's
//!    context id (`prove`).
//! 5. The verifier checks the proof and the pseudonym (`verify`).
//!
//! The pseudonym is deterministic per (nym secret, context id). The same member therefore
//! has one pseudonym per episode, which blocks double joins, and pseudonyms of different
//! episodes are unlinkable.

use zkryptium::bbsplus::commitment::BlindFactor;
use zkryptium::bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey};
use zkryptium::bbsplus::pseudonym::{BBSplusPseudonym, PseudonymSecret};
use zkryptium::keys::pair::KeyPair;
use zkryptium::schemes::algorithms::BbsBls12381Sha256;
use zkryptium::schemes::generics::{BlindSignature, Commitment, PoKSignature};

type S = BbsBls12381Sha256;

/// One prover nym secret per credential (the draft allows a vector).
pub const NYM_LEN: usize = 1;

pub type CredResult<T> = Result<T, String>;

fn err<E: std::fmt::Debug>(e: E) -> String {
    format!("{e:?}")
}

fn arr32(b: &[u8], what: &str) -> CredResult<[u8; 32]> {
    b.try_into().map_err(|_| format!("{what} must be 32 bytes"))
}

fn pk_of(b: &[u8]) -> CredResult<BBSplusPublicKey> {
    BBSplusPublicKey::from_bytes(b).map_err(err)
}

pub struct IssuerKeys {
    pub sk: Vec<u8>,
    pub pk: Vec<u8>,
}

/// Issuer key generation from at least 32 bytes of key material.
pub fn keygen(ikm: &[u8]) -> CredResult<IssuerKeys> {
    if ikm.len() < 32 {
        return Err("key material must be at least 32 bytes".into());
    }
    let kp = KeyPair::<S>::generate(ikm, None, None).map_err(err)?;
    Ok(IssuerKeys {
        sk: kp.private_key().to_bytes().to_vec(),
        pk: kp.public_key().to_bytes().to_vec(),
    })
}

pub struct CommitOut {
    pub commitment: Vec<u8>,
    pub prover_blind: Vec<u8>,
    pub prover_nym: Vec<u8>,
}

/// Member side: commit to a fresh random nym secret (and optional hidden messages).
pub fn commit(committed: &[Vec<u8>]) -> CredResult<CommitOut> {
    let nyms = PseudonymSecret::random_vec(NYM_LEN);
    let nym = nyms[0].to_bytes().to_vec();
    let (c, blind) = Commitment::<S>::commit_with_nym(Some(committed), nyms).map_err(err)?;
    Ok(CommitOut {
        commitment: c.to_bytes(),
        prover_blind: blind.to_bytes().to_vec(),
        prover_nym: nym,
    })
}

pub struct SignOut {
    pub signature: Vec<u8>,
    pub signer_nym_entropy: Vec<u8>,
}

/// Issuer side: verify the commitment proof and blind-sign it with public attributes.
pub fn blind_sign(
    sk: &[u8],
    pk: &[u8],
    commitment: &[u8],
    header: &[u8],
    messages: &[Vec<u8>],
) -> CredResult<SignOut> {
    let sk = BBSplusSecretKey::from_bytes(sk).map_err(err)?;
    let pk = pk_of(pk)?;
    let entropy = PseudonymSecret::random();
    let sig = BlindSignature::<S>::blind_sign_with_nym(
        &sk,
        &pk,
        Some(commitment),
        NYM_LEN,
        Some(header),
        &entropy,
        Some(messages),
    )
    .map_err(err)?;
    Ok(SignOut {
        signature: sig.to_bytes().to_vec(),
        signer_nym_entropy: entropy.to_bytes().to_vec(),
    })
}

/// Member side: verify the blind signature and derive the final nym secret.
#[allow(clippy::too_many_arguments)]
pub fn finalize(
    pk: &[u8],
    header: &[u8],
    messages: &[Vec<u8>],
    committed: &[Vec<u8>],
    prover_nym: &[u8],
    signer_nym_entropy: &[u8],
    prover_blind: &[u8],
    signature: &[u8],
) -> CredResult<Vec<u8>> {
    let pk = pk_of(pk)?;
    let sig_bytes: [u8; 80] = signature
        .try_into()
        .map_err(|_| "signature must be 80 bytes".to_string())?;
    let sig = BlindSignature::<S>::from_bytes(&sig_bytes).map_err(err)?;
    let nym = PseudonymSecret::from_bytes(&arr32(prover_nym, "prover nym")?).map_err(err)?;
    let entropy =
        PseudonymSecret::from_bytes(&arr32(signer_nym_entropy, "entropy")?).map_err(err)?;
    let blind = BlindFactor::from_bytes(&arr32(prover_blind, "prover blind")?).map_err(err)?;
    let secrets = sig
        .verify_finalize_with_nym(
            &pk,
            Some(header),
            Some(messages),
            Some(committed),
            vec![nym],
            Some(&entropy),
            Some(&blind),
        )
        .map_err(err)?;
    Ok(secrets[0].to_bytes().to_vec())
}

pub struct ProveOut {
    pub proof: Vec<u8>,
    pub pseudonym: Vec<u8>,
}

/// Member side: proof of possession with selective disclosure and a context pseudonym.
#[allow(clippy::too_many_arguments)]
pub fn prove(
    pk: &[u8],
    signature: &[u8],
    header: &[u8],
    presentation_header: &[u8],
    nym_secret: &[u8],
    context_id: &[u8],
    messages: &[Vec<u8>],
    committed: &[Vec<u8>],
    disclosed: &[usize],
    disclosed_committed: &[usize],
    prover_blind: &[u8],
) -> CredResult<ProveOut> {
    let pk = pk_of(pk)?;
    let secret = PseudonymSecret::from_bytes(&arr32(nym_secret, "nym secret")?).map_err(err)?;
    let blind = BlindFactor::from_bytes(&arr32(prover_blind, "prover blind")?).map_err(err)?;
    let (proof, nym) = PoKSignature::<S>::proof_gen_with_nym(
        &pk,
        signature,
        Some(header),
        Some(presentation_header),
        &vec![secret],
        context_id,
        Some(messages),
        Some(committed),
        Some(disclosed),
        Some(disclosed_committed),
        Some(&blind),
    )
    .map_err(err)?;
    Ok(ProveOut {
        proof: proof.to_bytes(),
        pseudonym: nym.to_bytes(),
    })
}

/// Verifier side. `total_messages` is the number of issuer-signed messages (L).
#[allow(clippy::too_many_arguments)]
pub fn verify(
    pk: &[u8],
    header: &[u8],
    presentation_header: &[u8],
    proof: &[u8],
    pseudonym: &[u8],
    context_id: &[u8],
    total_messages: usize,
    disclosed: &[(usize, Vec<u8>)],
    disclosed_committed: &[(usize, Vec<u8>)],
) -> CredResult<()> {
    let pk = pk_of(pk)?;
    if pseudonym.len() != 48 {
        return Err("pseudonym must be 48 bytes".into());
    }
    let nym = BBSplusPseudonym::from_bytes(pseudonym).map_err(err)?;
    let poks = PoKSignature::<S>::from_bytes(proof).map_err(err)?;
    let idx: Vec<usize> = disclosed.iter().map(|(i, _)| *i).collect();
    let msgs: Vec<Vec<u8>> = disclosed.iter().map(|(_, m)| m.clone()).collect();
    let cidx: Vec<usize> = disclosed_committed.iter().map(|(i, _)| *i).collect();
    let cmsgs: Vec<Vec<u8>> = disclosed_committed.iter().map(|(_, m)| m.clone()).collect();
    poks.proof_verify_with_nym(
        &pk,
        Some(header),
        Some(presentation_header),
        &nym,
        context_id,
        NYM_LEN,
        Some(total_messages),
        Some(&msgs),
        Some(&cmsgs),
        Some(&idx),
        Some(&cidx),
    )
    .map_err(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkryptium::schemes::generics::Signature;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// draft-irtf-cfrg-bbs-signatures-12, BLS12-381-SHA-256 "valid single message signature"
    /// (signature001): signing is deterministic, so the output must match byte for byte.
    #[test]
    fn draft_vector_signature001_is_byte_exact() {
        let sk = BBSplusSecretKey::from_bytes(&h(
            "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc",
        ))
        .unwrap();
        let pk = pk_of(&h("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c")).unwrap();
        let msgs = vec![h(
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
        )];
        let sig = Signature::<S>::sign(
            Some(&msgs),
            &sk,
            &pk,
            Some(&h("11223344556677889900aabbccddeeff")),
        )
        .unwrap();
        assert_eq!(
            hex::encode(sig.to_bytes()),
            "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0"
        );
    }

    struct NymVector {
        pk: Vec<u8>,
        signature: Vec<u8>,
        entropy: Vec<u8>,
        prover_nym: Vec<u8>,
        nym_secret: Vec<u8>,
        pseudonym: Vec<u8>,
        blind: Vec<u8>,
        context: Vec<u8>,
        header: Vec<u8>,
        ph: Vec<u8>,
        messages: Vec<Vec<u8>>,
        committed: Vec<Vec<u8>>,
        proof: Vec<u8>,
    }

    /// draft-irtf-cfrg-bbs-per-verifier-linkability-03, BLS12-381-SHA-256 nymProof001.
    fn nym_proof001() -> NymVector {
        let s = |v: &[&str]| v.iter().map(|x| h(x)).collect::<Vec<_>>();
        NymVector {
            pk: h("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"),
            signature: h("818f434f737d58ed13b7cbb53885b7a19fe9b4b7d7dc34d8fcc53ca1bfe376bd569053d8733a89b97fed23da4a04833c57ce2b42cfd0d60e1b862f7774431e80b0ed910a217f37837ab90a94dc1253bb"),
            entropy: h("3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5"),
            prover_nym: h("6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418"),
            nym_secret: h("3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc"),
            pseudonym: h("b04bd002c85e31d2735ee2e6b36aea85147cbf197934f99ae26a7da73b98ebc34561848426aded0967e07fb333f79487"),
            blind: h("15494ae70742a6a4f420106c79ee405c138557385f3f6f7256449d147ebf22b8"),
            context: h("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a"),
            header: h("11223344556677889900aabbccddeeff"),
            ph: h("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501"),
            messages: s(&[
                "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
                "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
                "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
                "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
                "496694774c5604ab1b2544eababcf0f53278ff50",
                "515ae153e22aae04ad16f759e07237b4",
                "d183ddc6e2665aa4e2f088af",
                "ac55fb33a75909ed",
                "96012096",
                "",
            ]),
            committed: s(&[
                "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3",
                "a75d8b634891af92282cc81a675972d1929d3149863c1fc0",
                "835889a40744813a892eff9deb1edaeb",
                "e1ca9729410dc6ba",
                "",
            ]),
            proof: h("8b461b6d894ca153a2e1c05ac10c1bf21778b4ba08e9ca80949525afd86d533bf4b4f53ae3f7db67b9dcf55b5c4d3816b80b033b140c3bab14da11a54bb7afeb32c357cf6a1b73f100cbf1cb4e1c3fa1376a57d3be7e2f0395ec59b9e2c39c6ba744a214e5cec73752d3aa6ca1461cc38b4f69397282e8c9552b8f2add6e878f4edb8370003e141bacca3c3131bdbe016a02395e38459b716da68c90eedf33e13d01684d271148dc05c11f934a11986c40664e63c3eddd2a7f84edac4b092dfa6eb0bc58b8ae5c44b7b4392b288e700f59c56be0674865eb7e89069c2f39fd0a2a61379d615db25d33473774ff72033304a8a62dbf5515d4475808a5f9fae6052f5031d741535af95294195a97e9f87336fa53bf566b1e88bc8987b6850b0f06fc7423d92910970ac6cf33a8a53d1fad10343839f7ad6c221366c10e96eb67949f2bcfc83614232ee7a5f9f564fe2499"),
        }
    }

    fn all(n: usize, v: &[Vec<u8>]) -> Vec<(usize, Vec<u8>)> {
        (0..n).map(|i| (i, v[i].clone())).collect()
    }

    #[test]
    fn draft_vector_nym_secret_and_pseudonym_are_byte_exact() {
        let v = nym_proof001();
        let secret = finalize(
            &v.pk,
            &v.header,
            &v.messages,
            &v.committed,
            &v.prover_nym,
            &v.entropy,
            &v.blind,
            &v.signature,
        )
        .unwrap();
        assert_eq!(secret, v.nym_secret);
        // a fresh proof is randomized, but its pseudonym is deterministic
        let p = prove(
            &v.pk,
            &v.signature,
            &v.header,
            &v.ph,
            &secret,
            &v.context,
            &v.messages,
            &v.committed,
            &(0..10).collect::<Vec<_>>(),
            &(0..5).collect::<Vec<_>>(),
            &v.blind,
        )
        .unwrap();
        assert_eq!(p.pseudonym, v.pseudonym);
    }

    #[test]
    fn draft_vector_proof_verifies_and_tampering_fails() {
        let v = nym_proof001();
        let d = all(10, &v.messages);
        let dc = all(5, &v.committed);
        verify(
            &v.pk,
            &v.header,
            &v.ph,
            &v.proof,
            &v.pseudonym,
            &v.context,
            10,
            &d,
            &dc,
        )
        .unwrap();
        let mut bad = v.proof.clone();
        bad[100] ^= 1;
        assert!(verify(
            &v.pk,
            &v.header,
            &v.ph,
            &bad,
            &v.pseudonym,
            &v.context,
            10,
            &d,
            &dc
        )
        .is_err());
        let mut other_ctx = v.context.clone();
        other_ctx[0] ^= 1;
        assert!(verify(
            &v.pk,
            &v.header,
            &v.ph,
            &v.proof,
            &v.pseudonym,
            &other_ctx,
            10,
            &d,
            &dc
        )
        .is_err());
        let mut lie = d.clone();
        lie[0].1 = h("00");
        assert!(verify(
            &v.pk,
            &v.header,
            &v.ph,
            &v.proof,
            &v.pseudonym,
            &v.context,
            10,
            &lie,
            &dc
        )
        .is_err());
    }

    #[test]
    fn issuance_selective_disclosure_and_per_context_pseudonyms() {
        let issuer = keygen(&[7u8; 32]).unwrap();
        let header = b"esp/v1/hive-credential".to_vec();
        let attrs = vec![b"class:panel-a".to_vec(), b"valid_until:2027".to_vec()];
        let c = commit(&[]).unwrap();
        let s = blind_sign(&issuer.sk, &issuer.pk, &c.commitment, &header, &attrs).unwrap();
        let secret = finalize(
            &issuer.pk,
            &header,
            &attrs,
            &[],
            &c.prover_nym,
            &s.signer_nym_entropy,
            &c.prover_blind,
            &s.signature,
        )
        .unwrap();
        let mk = |ctx: &[u8]| {
            prove(
                &issuer.pk,
                &s.signature,
                &header,
                b"join",
                &secret,
                ctx,
                &attrs,
                &[],
                &[0],
                &[],
                &c.prover_blind,
            )
            .unwrap()
        };
        let a1 = mk(b"episode-1");
        let a2 = mk(b"episode-1");
        let b = mk(b"episode-2");
        assert_eq!(a1.pseudonym, a2.pseudonym); // one pseudonym per episode
        assert_ne!(a1.pseudonym, b.pseudonym); // unlinkable across episodes
        assert_ne!(a1.proof, a2.proof); // proofs are re-randomized
        let disclosed = vec![(0usize, attrs[0].clone())];
        verify(
            &issuer.pk,
            &header,
            b"join",
            &a1.proof,
            &a1.pseudonym,
            b"episode-1",
            2,
            &disclosed,
            &[],
        )
        .unwrap();
        // wrong pseudonym, wrong presentation header, wrong issuer all fail
        assert!(verify(
            &issuer.pk,
            &header,
            b"join",
            &a1.proof,
            &b.pseudonym,
            b"episode-1",
            2,
            &disclosed,
            &[]
        )
        .is_err());
        assert!(verify(
            &issuer.pk,
            &header,
            b"exit",
            &a1.proof,
            &a1.pseudonym,
            b"episode-1",
            2,
            &disclosed,
            &[]
        )
        .is_err());
        let other = keygen(&[9u8; 32]).unwrap();
        assert!(verify(
            &other.pk,
            &header,
            b"join",
            &a1.proof,
            &a1.pseudonym,
            b"episode-1",
            2,
            &disclosed,
            &[]
        )
        .is_err());
    }

    #[test]
    fn issuer_refuses_a_forged_commitment() {
        let issuer = keygen(&[7u8; 32]).unwrap();
        let mut c = commit(&[]).unwrap();
        c.commitment[60] ^= 1;
        assert!(blind_sign(
            &issuer.sk,
            &issuer.pk,
            &c.commitment,
            b"h",
            &[b"x".to_vec()]
        )
        .is_err());
    }
}
