from paca.bench import compute


def test_benchmark_headline_properties():
    d = compute()
    m = d["metrics"]
    assert m["paca"]["asr_vig"] < m["sandbox"]["asr_vig"] < m["none"]["asr_vig"] + 1
    assert m["paca"]["asr_vig"] <= 15 and m["paca"]["completion"] == 100.0
    # residual cases must stay visible: PACA++ does not claim to stop them
    sc = {s["id"]: s for s in d["scenarios"]}
    assert sc["R01"]["results"]["paca"]["vig"]["harmed"] and sc["R02"]["results"]["paca"]["vig"]["harmed"]
    # the worm is limited, not prevented
    assert 0 < sc["E02"]["results"]["paca"]["vig"]["evil"] < sc["E02"]["results"]["none"]["vig"]["evil"]


def test_audit_chain_valid_in_every_run():
    d = compute()
    assert all(s["results"]["paca"]["audit_ok"] for s in d["scenarios"])
