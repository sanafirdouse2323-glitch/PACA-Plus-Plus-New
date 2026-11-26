from paca.bench import compute


def test_benchmark_headline_properties():
    d = compute()
    m = d["metrics"]
    incomplete = [
        {
            "id": scenario["id"],
            "trace": [
                {
                    key: event.get(key)
                    for key in (
                        "kind",
                        "action",
                        "verdict",
                        "executed",
                        "checks",
                        "text",
                    )
                    if key in event
                }
                for event in scenario["results"]["paca"]["trace"]
                if event.get("kind") in {"act", "skip", "memread"}
            ],
        }
        for scenario in d["scenarios"]
        if scenario["kind"] == "benign"
        and not scenario["results"]["paca"]["vig"]["completed"]
    ]
    assert not incomplete, f"PACA++ incomplete benign workflows: {incomplete}"
    assert m["paca"]["asr_vig"] < m["sandbox"]["asr_vig"] < m["none"]["asr_vig"] + 1
    assert m["paca"]["asr_vig"] <= 15 and m["paca"]["completion"] == 100.0
    # residual cases must stay visible: PACA++ does not claim to stop them
    sc = {s["id"]: s for s in d["scenarios"]}
    assert (
        sc["R01"]["results"]["paca"]["vig"]["harmed"]
        and sc["R02"]["results"]["paca"]["vig"]["harmed"]
    )
    # the worm is limited, not prevented
    assert (
        0
        < sc["E02"]["results"]["paca"]["vig"]["evil"]
        < sc["E02"]["results"]["none"]["vig"]["evil"]
    )


def test_audit_chain_valid_in_every_run():
    d = compute()
    assert all(s["results"]["paca"]["audit_ok"] for s in d["scenarios"])


def test_simulator_results_are_explicitly_labelled_as_non_vendor_evidence():
    data = compute()

    assert data["schema_version"] == "1.0.0"
    assert data["evidence"]["class"] == "S"
    assert data["evidence"]["status"] == "internal_simulation"
    assert data["evidence"]["baseline_type"] == "hand_authored_toy_models"
    assert data["evidence"]["model_in_loop"] is False
    assert data["evidence"]["live_vendor_execution"] is False
    assert data["evidence"]["independent_scenario_templates_verified"] is False
    assert data["evidence"]["n_scenarios"] == len(data["scenarios"])
