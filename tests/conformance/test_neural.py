# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-090: the ``neural`` conformance category and its CLI options."""

import json
import stat
import sys
from pathlib import Path

import pytest

from esp.adapters.neural import SimulatedNeuralAdapter
from esp.adapters.neural.interface import ContractReport, check_adapter_contract
from esp.conformance import neural
from esp.conformance.runner import DEFAULT_VECTORS, Suite, main
from esp.neural_sdk import CONTRACT_VERSION
from esp.neural_sdk.jsonl import dump_adapter

pytestmark = [pytest.mark.conformance, pytest.mark.security]


def _neural(suite: Suite) -> list[tuple[str, bool, str]]:
    suite.neural()
    return [(r.name, r.passed, r.detail) for r in suite.report.results if r.category == "neural"]


def test_neural_category_passes_on_this_implementation() -> None:
    results = _neural(Suite(DEFAULT_VECTORS))
    assert len(results) >= 19
    assert all(ok for _, ok, _ in results), [r for r in results if not r[1]]


@pytest.mark.parametrize("name", sorted(neural.BROKEN_ADAPTERS))
def test_each_broken_adapter_is_refused_with_exactly_its_rule(name: str) -> None:
    factory, expected = neural.BROKEN_ADAPTERS[name]
    got = {v.rule for v in check_adapter_contract(factory()).violations}
    assert got == expected


@pytest.mark.parametrize("mode", neural.BROKEN_DECODERS)
def test_each_broken_decoder_is_refused(mode: str) -> None:
    neural.check_broken_decoder(mode)


def test_a_permissive_checker_fails_the_category(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the contract checker accepted everything, conformance must fail loudly."""
    monkeypatch.setattr(
        neural,
        "check_adapter_contract",
        lambda adapter, **kw: ContractReport(adapter.info.adapter_id, 1, 1, ()),
    )
    results = _neural(Suite(DEFAULT_VECTORS))
    failed = {name for name, ok, _ in results if not ok}
    assert failed == {f"refuses_{n}" for n in neural.BROKEN_ADAPTERS}


def test_a_checker_reporting_the_wrong_rule_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    real = check_adapter_contract

    def mislabel(adapter, **kw):  # type: ignore[no-untyped-def]
        r = real(adapter, **kw)
        return ContractReport(
            r.subject,
            r.blocks,
            r.samples,
            tuple(type(v)("other", v.detail) for v in r.violations),
        )

    monkeypatch.setattr(neural, "check_adapter_contract", mislabel)
    with pytest.raises(neural.NeuralConformanceError, match="expected rules"):
        neural.check_broken_adapter(*neural.BROKEN_ADAPTERS["non_monotonic_clock"])


def broken_vendor() -> object:
    """An external adapter factory that violates the contract (interpretive channel)."""
    return neural.BROKEN_ADAPTERS["interpretive_channel_name"][0]()


def test_cli_checks_an_external_adapter(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    args = ["run", "--neural-adapter", "esp.neural_sdk.example:example_adapter", "--json", str(out)]
    assert main(args) == 0
    report = json.loads(out.read_text())
    names = {r["name"] for r in report["results"] if r["category"] == "neural"}
    assert "external:esp.neural_sdk.example:example_adapter" in names
    bad = ["run", "--neural-adapter", f"{__name__}:broken_vendor", "--json", str(out)]
    assert main(bad) == 1
    failed = [r for r in json.loads(out.read_text())["results"] if not r["passed"]]
    assert [r["name"] for r in failed] == [f"external:{__name__}:broken_vendor"]
    assert "neutral" in failed[0]["detail"]


def test_factory_spec_must_name_module_and_callable() -> None:
    with pytest.raises(ValueError, match="module:factory"):
        neural.load_factory("esp.neural_sdk.example")


def _fake_rust(tmp_path: Path, verdict_rules: list[str], version: str = CONTRACT_VERSION) -> Path:
    """A stand-in 'esp-rs' that prints a clean simulator transcript and a chosen verdict."""
    lines = dump_adapter(SimulatedNeuralAdapter(1, n_channels=4), version, reads=4, max_samples=64)
    lines.append(
        json.dumps(
            {
                "type": "verdict",
                "ok": not verdict_rules,
                "violations": [{"rule": r, "detail": "x"} for r in verdict_rules],
            }
        )
    )
    data = tmp_path / "transcript.jsonl"
    data.write_text("\n".join(lines) + "\n")
    script = tmp_path / "fake-esp-rs"
    script.write_text(
        f"#!{sys.executable}\nimport sys\nsys.stdout.write(open({str(data)!r}).read())\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


def test_rust_cross_check_agrees_on_a_clean_transcript(tmp_path: Path) -> None:
    neural.check_rust_mode(_fake_rust(tmp_path, []), "none", frozenset())


def test_rust_cross_check_detects_disagreement(tmp_path: Path) -> None:
    with pytest.raises(neural.NeuralConformanceError, match="Rust rules"):
        neural.check_rust_mode(_fake_rust(tmp_path, ["clock"]), "none", frozenset())


def test_rust_cross_check_detects_version_drift(tmp_path: Path) -> None:
    with pytest.raises(neural.NeuralConformanceError, match="contract version"):
        neural.check_rust_mode(_fake_rust(tmp_path, [], version="0.9.0"), "none", frozenset())


def test_rust_cross_check_requires_the_expected_rules(tmp_path: Path) -> None:
    with pytest.raises(neural.NeuralConformanceError, match="expected"):
        neural.check_rust_mode(_fake_rust(tmp_path, []), "none", frozenset({"clock"}))
