# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""FROST(Ed25519, SHA-512) against RFC 9591 Appendix E.1, plus threshold properties."""

import pytest

from esp.hive import frost

pytestmark = pytest.mark.security

# RFC 9591 Appendix E.1 (FROST(Ed25519, SHA-512)); MAX=3, MIN=2, participants 1 and 3.
RFC = {
    "group_secret_key": "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304",
    "group_public_key": "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673",
    "message": "74657374",
    "coefficient_1": "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204",
    "shares": {
        1: "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509",
        2: "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d",
        3: "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02",
    },
    "randomness": {
        1: (
            "0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec",
            "69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501",
        ),
        3: (
            "86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f",
            "13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775",
        ),
    },
    "nonces": {
        1: (
            "812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407",
            "b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301",
        ),
        3: (
            "c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e",
            "243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d",
        ),
    },
    "commitments": {
        1: (
            "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3",
            "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932",
        ),
        3: (
            "cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91",
            "7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552",
        ),
    },
    "binding_factor_input_1": (
        "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673504df914fa965023fb75c2"
        "5ded4bb260f417de6d32e5c442c6ba313791cc9a4948d6273e8d3511f93348ea7a708a9b862bc73ba2a79c"
        "fdfe07729a193751cbc973af46d8ac3440e518d4ce440a0e7d4ad5f62ca8940f32de6d8dc00fc12c660b81"
        "7d587d82f856d277ce6473cae6d2f5763f7da2e8b4d799a3f3e725d4522ec70100000000000000000000000"
        "000000000000000000000000000000000000000"
    ),
    "binding_factors": {
        1: "f2cb9d7dd9beff688da6fcc83fa89046b3479417f47f55600b106760eb3b5603",
        3: "b087686bf35a13f3dc78e780a34b0fe8a77fef1b9938c563f5573d71d8d7890f",
    },
    "sig_shares": {
        1: "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603",
        3: "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007",
    },
    "sig": (
        "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbe"
        "bd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b"
    ),
}


def _le(h: str) -> int:
    return int.from_bytes(bytes.fromhex(h), "little")


def rfc_group() -> tuple[frost.GroupInfo, list[frost.KeyShare]]:
    return frost.trusted_dealer_keygen(
        3, 2, _le(RFC["group_secret_key"]), [_le(RFC["coefficient_1"])]
    )


def test_rfc9591_e1_byte_exact() -> None:
    info, shares = rfc_group()
    assert info.group_public.hex() == RFC["group_public_key"]
    for sh in shares:
        assert frost.serialize_scalar(sh.secret).hex() == RFC["shares"][sh.identifier]
    msg = bytes.fromhex(RFC["message"])
    signers = [shares[0], shares[2]]
    nonces, comms = {}, []
    for sh in signers:
        rh, rb = RFC["randomness"][sh.identifier]
        n, c = frost.commit(sh, (bytes.fromhex(rh), bytes.fromhex(rb)))
        eh, eb = RFC["nonces"][sh.identifier]
        assert frost.serialize_scalar(n.hiding).hex() == eh
        assert frost.serialize_scalar(n.binding).hex() == eb
        assert (c.hiding.hex(), c.binding.hex()) == RFC["commitments"][sh.identifier]
        nonces[sh.identifier], comms = n, [*comms, c]
    assert (
        frost.binding_factor_input(info.group_public, comms, msg, 1).hex()
        == RFC["binding_factor_input_1"]
    )
    rho = frost.compute_binding_factors(info.group_public, comms, msg)
    for i, expected in RFC["binding_factors"].items():
        assert frost.serialize_scalar(rho[i]).hex() == expected
    shares_z = {sh.identifier: frost.sign(sh, nonces[sh.identifier], msg, comms) for sh in signers}
    for i, z in shares_z.items():
        assert z.hex() == RFC["sig_shares"][i]
        assert frost.verify_signature_share(info, i, z, comms, msg)
    sig = frost.aggregate(info, comms, msg, shares_z)
    assert sig.hex() == RFC["sig"]
    assert frost.verify(info.group_public, msg, sig)  # plain Ed25519 verification


def _session(
    info: frost.GroupInfo, signers: list[frost.KeyShare], msg: bytes
) -> tuple[list[frost.Commitment], dict[int, bytes]]:
    rounds = [frost.commit(sh) for sh in signers]
    comms = [c for _, c in rounds]
    return comms, {
        sh.identifier: frost.sign(sh, n, msg, comms)
        for sh, (n, _) in zip(signers, rounds, strict=True)
    }


@pytest.mark.parametrize("subset", [(1, 2, 3), (2, 4, 5), (1, 3, 5), (1, 2, 3, 4, 5)])
def test_any_threshold_subset_signs(subset: tuple[int, ...]) -> None:
    info, shares = frost.trusted_dealer_keygen(5, 3)
    msg = b"esp collective intent"
    signers = [shares[i - 1] for i in subset]
    comms, z = _session(info, signers, msg)
    sig = frost.aggregate(info, comms, msg, z)
    assert frost.verify(info.group_public, msg, sig)
    assert not frost.verify(info.group_public, msg + b"!", sig)


def test_below_threshold_refused_and_cannot_forge() -> None:
    info, shares = frost.trusted_dealer_keygen(5, 3)
    msg = b"m"
    comms, z = _session(info, shares[:2], msg)
    with pytest.raises(frost.FrostError, match="MIN_PARTICIPANTS"):
        frost.aggregate(info, comms, msg, z)
    # Forcing aggregation with two shares of a 3-of-5 key yields an invalid signature:
    rho = frost.compute_binding_factors(info.group_public, comms, msg)
    r = frost.compute_group_commitment(comms, rho)
    forged = frost.serialize_element(r) + frost.serialize_scalar(
        sum(frost.deserialize_scalar(s) for s in z.values())
    )
    assert not frost.verify(info.group_public, msg, forged)


def test_bad_share_identified() -> None:
    info, shares = frost.trusted_dealer_keygen(4, 3)
    msg = b"m"
    comms, z = _session(info, shares[:3], msg)
    z[2] = frost.serialize_scalar(frost.deserialize_scalar(z[2]) + 1)
    with pytest.raises(frost.FrostError, match=r"misbehaving participants \[2\]"):
        frost.aggregate(info, comms, msg, z)


def test_nonce_reuse_refused() -> None:
    _, shares = frost.trusted_dealer_keygen(3, 2)
    n1, c1 = frost.commit(shares[0])
    _, c2 = frost.commit(shares[1])
    frost.sign(shares[0], n1, b"a", [c1, c2])
    with pytest.raises(frost.FrostError, match="reused"):
        frost.sign(shares[0], n1, b"b", [c1, c2])


def test_input_validation() -> None:
    _, shares = frost.trusted_dealer_keygen(3, 2)
    n1, c1 = frost.commit(shares[0])
    _, c2 = frost.commit(shares[1])
    with pytest.raises(frost.FrostError, match="sorted"):
        frost.sign(shares[0], n1, b"m", [c2, c1])
    with pytest.raises(frost.FrostError, match="own commitment"):
        frost.sign(shares[0], n1, b"m", [c2])
    with pytest.raises(frost.FrostError):
        frost.deserialize_element(bytes(32))  # not a valid point with y = 0 / identity handling
    identity_enc = (1).to_bytes(32, "little")
    with pytest.raises(frost.FrostError, match="identity"):
        frost.deserialize_element(identity_enc)
    with pytest.raises(frost.FrostError, match="range"):
        frost.deserialize_scalar(frost.L.to_bytes(32, "little"))
    with pytest.raises(frost.FrostError, match="invalid parameters"):
        frost.derive_interpolating_value([1, 1, 2], 1)


def test_small_order_point_rejected() -> None:
    # (0, -1) has order 2: encoding of y = p - 1, sign 0.
    order2 = (frost.P - 1).to_bytes(32, "little")
    with pytest.raises(frost.FrostError, match="subgroup"):
        frost.deserialize_element(order2)
