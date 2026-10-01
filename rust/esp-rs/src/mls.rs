// SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! MLS (RFC 9420) group layer for the Typed Hive (GAP-017, ADR-0021).
//!
//! Thin state machine over the audited `openmls` crate. MLS itself is never
//! re-implemented here. One [`Member`] holds one participant's keys and group
//! state; members exchange only opaque, serialized MLS messages (key packages,
//! commits, welcomes), relayed by an untrusted delivery service.
//!
//! Ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001), the
//! RFC 9420 mandatory-to-implement suite.
//!
//! The per-epoch secret the Hive uses is the MLS exporter (RFC 9420 §8.5):
//! `MLS-Exporter(label, context, length)`. A member that was removed can no
//! longer export (its group is inactive), and every commit (add, remove,
//! self-update) moves the group to a new epoch with a fresh exporter secret.

use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    #[error("mls: {0}")]
    Protocol(String),
    #[error("mls: no group (create or join first)")]
    NoGroup,
    #[error("mls: already in a group")]
    AlreadyInGroup,
    #[error("mls: unknown member {0}")]
    UnknownMember(String),
    #[error("mls: expected a commit")]
    NotACommit,
}

fn err<E: std::fmt::Debug>(context: &str) -> impl Fn(E) -> MlsError + '_ {
    move |e| MlsError::Protocol(format!("{context}: {e:?}"))
}

/// Output of an operation that changes the group: the commit for existing
/// members and, for adds, the welcome for new ones.
pub struct CommitOut {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub epoch: u64,
}

pub struct Member {
    name: String,
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    group: Option<MlsGroup>,
}

impl Member {
    pub fn new(name: &str) -> Result<Self, MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(err("signature key"))?;
        signer
            .store(provider.storage())
            .map_err(err("store signature key"))?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        Ok(Member {
            name: name.to_string(),
            provider,
            signer,
            credential,
            group: None,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// A fresh, single-use key package (serialized), to be sent to the group.
    pub fn key_package(&self) -> Result<Vec<u8>, MlsError> {
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(err("key package"))?;
        bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(err("serialize key package"))
    }

    pub fn create(&mut self) -> Result<u64, MlsError> {
        if self.group.is_some() {
            return Err(MlsError::AlreadyInGroup);
        }
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new(
            &self.provider,
            &self.signer,
            &config,
            self.credential.clone(),
        )
        .map_err(err("create group"))?;
        let epoch = group.epoch().as_u64();
        self.group = Some(group);
        Ok(epoch)
    }

    fn group(&self) -> Result<&MlsGroup, MlsError> {
        self.group.as_ref().ok_or(MlsError::NoGroup)
    }

    /// Add members from their serialized key packages (signatures verified).
    pub fn add(&mut self, key_packages: &[Vec<u8>]) -> Result<CommitOut, MlsError> {
        let mut kps = Vec::with_capacity(key_packages.len());
        for raw in key_packages {
            let kp = KeyPackageIn::tls_deserialize_exact(raw.as_slice())
                .map_err(err("decode key package"))?
                .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(err("invalid key package"))?;
            kps.push(kp);
        }
        let (provider, signer) = (&self.provider, &self.signer);
        let group = self.group.as_mut().ok_or(MlsError::NoGroup)?;
        let (commit, welcome, _info) = group
            .add_members(provider, signer, &kps)
            .map_err(err("add members"))?;
        group
            .merge_pending_commit(provider)
            .map_err(err("merge own commit"))?;
        Ok(CommitOut {
            commit: commit.to_bytes().map_err(err("serialize commit"))?,
            welcome: Some(welcome.to_bytes().map_err(err("serialize welcome"))?),
            epoch: group.epoch().as_u64(),
        })
    }

    /// Join from a serialized Welcome (authenticated by MLS; tampering is refused).
    pub fn join(&mut self, welcome: &[u8]) -> Result<u64, MlsError> {
        if self.group.is_some() {
            return Err(MlsError::AlreadyInGroup);
        }
        let msg = MlsMessageIn::tls_deserialize_exact(welcome).map_err(err("decode welcome"))?;
        let MlsMessageBodyIn::Welcome(welcome) = msg.extract() else {
            return Err(MlsError::Protocol("not a welcome".into()));
        };
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let group = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
            .map_err(err("stage welcome"))?
            .into_group(&self.provider)
            .map_err(err("join group"))?;
        let epoch = group.epoch().as_u64();
        self.group = Some(group);
        Ok(epoch)
    }

    /// Remove members by name (their identity in the basic credential).
    pub fn remove(&mut self, names: &[String]) -> Result<CommitOut, MlsError> {
        let group = self.group()?;
        let mut idx = Vec::new();
        for n in names {
            let m = group
                .members()
                .find(|m| m.credential.serialized_content() == n.as_bytes())
                .ok_or_else(|| MlsError::UnknownMember(n.clone()))?;
            idx.push(m.index);
        }
        let (provider, signer) = (&self.provider, &self.signer);
        let group = self.group.as_mut().ok_or(MlsError::NoGroup)?;
        let (commit, _welcome, _info) = group
            .remove_members(provider, signer, &idx)
            .map_err(err("remove members"))?;
        group
            .merge_pending_commit(provider)
            .map_err(err("merge own commit"))?;
        Ok(CommitOut {
            commit: commit.to_bytes().map_err(err("serialize commit"))?,
            welcome: None,
            epoch: group.epoch().as_u64(),
        })
    }

    /// Self-update: new leaf key material (post-compromise security), new epoch.
    pub fn update(&mut self) -> Result<CommitOut, MlsError> {
        let (provider, signer) = (&self.provider, &self.signer);
        let group = self.group.as_mut().ok_or(MlsError::NoGroup)?;
        let bundle = group
            .self_update(provider, signer, LeafNodeParameters::default())
            .map_err(err("self update"))?;
        let (commit, _welcome, _info) = bundle.into_contents();
        group
            .merge_pending_commit(provider)
            .map_err(err("merge own commit"))?;
        Ok(CommitOut {
            commit: commit.to_bytes().map_err(err("serialize commit"))?,
            welcome: None,
            epoch: group.epoch().as_u64(),
        })
    }

    /// Process a commit from another member (authenticated; tampering is refused).
    pub fn process(&mut self, message: &[u8]) -> Result<u64, MlsError> {
        let provider = &self.provider;
        let group = self.group.as_mut().ok_or(MlsError::NoGroup)?;
        let msg = MlsMessageIn::tls_deserialize_exact(message).map_err(err("decode message"))?;
        let protocol = msg
            .try_into_protocol_message()
            .map_err(err("not a protocol message"))?;
        let processed = group
            .process_message(provider, protocol)
            .map_err(err("process"))?;
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                group
                    .merge_staged_commit(provider, *staged)
                    .map_err(err("merge commit"))?;
                Ok(group.epoch().as_u64())
            }
            _ => Err(MlsError::NotACommit),
        }
    }

    pub fn epoch(&self) -> Result<u64, MlsError> {
        Ok(self.group()?.epoch().as_u64())
    }

    pub fn active(&self) -> bool {
        self.group.as_ref().is_some_and(|g| g.is_active())
    }

    pub fn members(&self) -> Result<Vec<String>, MlsError> {
        Ok(self
            .group()?
            .members()
            .map(|m| String::from_utf8_lossy(m.credential.serialized_content()).into_owned())
            .collect())
    }

    /// RFC 9420 exporter for the current epoch; refused once removed.
    pub fn export(&self, label: &str, context: &[u8], length: usize) -> Result<Vec<u8>, MlsError> {
        self.group()?
            .export_secret(self.provider.crypto(), label, context, length)
            .map_err(err("export"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LABEL: &str = "esp/v1/hive-round";

    fn group(n: usize) -> Vec<Member> {
        let mut ms: Vec<Member> = (0..n)
            .map(|i| Member::new(&format!("m{i}")).unwrap())
            .collect();
        ms[0].create().unwrap();
        let kps: Vec<Vec<u8>> = ms[1..].iter().map(|m| m.key_package().unwrap()).collect();
        let out = ms[0].add(&kps).unwrap();
        let welcome = out.welcome.unwrap();
        for m in ms[1..].iter_mut() {
            m.join(&welcome).unwrap();
        }
        ms
    }

    fn secrets(ms: &[Member], ctx: &[u8]) -> Vec<Vec<u8>> {
        ms.iter()
            .map(|m| m.export(LABEL, ctx, 32).unwrap())
            .collect()
    }

    #[test]
    fn six_members_share_one_exporter_secret_per_epoch() {
        let ms = group(6);
        let s = secrets(&ms, b"ep1");
        assert!(s.iter().all(|x| x == &s[0]));
        assert_ne!(secrets(&ms, b"ep2")[0], s[0]); // context separates rounds
        assert!(ms.iter().all(|m| m.epoch().unwrap() == 1));
        assert_eq!(ms[3].members().unwrap().len(), 6);
    }

    #[test]
    fn self_update_moves_everyone_to_a_new_epoch_and_secret() {
        let mut ms = group(4);
        let before = secrets(&ms, b"r")[0].clone();
        let out = ms[2].update().unwrap();
        for (i, m) in ms.iter_mut().enumerate() {
            if i != 2 {
                assert_eq!(m.process(&out.commit).unwrap(), out.epoch);
            }
        }
        let after = secrets(&ms, b"r");
        assert!(after.iter().all(|x| x == &after[0]));
        assert_ne!(after[0], before);
    }

    #[test]
    fn removed_member_cannot_export_the_next_epoch() {
        let mut ms = group(4);
        let out = ms[0].remove(&["m3".to_string()]).unwrap();
        for m in ms[1..3].iter_mut() {
            m.process(&out.commit).unwrap();
        }
        let _ = ms[3].process(&out.commit); // the removed member learns it is out
        assert!(!ms[3].active());
        assert!(ms[3].export(LABEL, b"r", 32).is_err());
        let s = secrets(&ms[..3], b"r");
        assert!(s.iter().all(|x| x == &s[0]));
        assert_eq!(ms[0].members().unwrap().len(), 3);
    }

    #[test]
    fn tampered_commit_and_welcome_are_refused() {
        let mut ms = group(3);
        let mut out = ms[0].update().unwrap();
        let last = out.commit.len() - 1;
        out.commit[last] ^= 1;
        assert!(ms[1].process(&out.commit).is_err());
        let mut a = Member::new("a").unwrap();
        let b = Member::new("b").unwrap();
        a.create().unwrap();
        let mut w = a.add(&[b.key_package().unwrap()]).unwrap().welcome.unwrap();
        let last = w.len() - 1;
        w[last] ^= 1;
        let mut b = b;
        assert!(b.join(&w).is_err());
    }

    #[test]
    fn an_authenticated_proposal_is_not_taken_for_a_commit() {
        let mut ms = group(3);
        let Member {
            provider,
            signer,
            group,
            ..
        } = &mut ms[1];
        let (proposal, _ref) = group
            .as_mut()
            .unwrap()
            .propose_self_update(&*provider, &*signer, LeafNodeParameters::default())
            .unwrap();
        let bytes = proposal.to_bytes().unwrap();
        let before = ms[0].epoch().unwrap();
        assert!(matches!(ms[0].process(&bytes), Err(MlsError::NotACommit)));
        assert_eq!(ms[0].epoch().unwrap(), before); // no epoch change from a proposal
    }

    #[test]
    fn forged_key_package_is_refused() {
        let mut a = Member::new("a").unwrap();
        a.create().unwrap();
        let mut kp = Member::new("b").unwrap().key_package().unwrap();
        let last = kp.len() - 1;
        kp[last] ^= 1; // breaks the key package signature
        assert!(a.add(&[kp]).is_err());
    }
}
