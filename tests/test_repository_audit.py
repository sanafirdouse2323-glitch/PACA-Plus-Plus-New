from paca.harness import Session
from paca.monitor import Monitor, canonical_path_target, match_grant
from paca.provenance import Arg, Label
from paca.runtime import Capability, Request, Tool


USER = Label("trusted", origins=frozenset({"user"}))


def capability(grants):
    return Capability("c", "tester", "acme", "task", "assistant", grants, 100)


def test_path_grant_rejects_parent_directory_traversal():
    cap = capability({"read_file": ("/acme/*",)})
    assert canonical_path_target("/acme/docs/report.txt") == "/acme/docs/report.txt"
    assert canonical_path_target("/acme/../../etc/passwd") is None
    assert match_grant(cap, "read_file", "/acme/../../etc/passwd") is None
    request = Request("read_file", {"path": Arg("/acme/../../etc/passwd", USER)}, cap, 1)
    decision = Monitor().decide(request)
    assert decision.verdict == "deny"
    assert "C1" in decision.checks


def test_protected_file_checks_written_content_provenance():
    monitor = Monitor()
    cap = capability({"write_file": ("/repo/.github/workflows/ci.yml",)})
    request = Request("write_file", {
        "path": Arg("/repo/.github/workflows/ci.yml", USER),
        "content": Arg("steps: upload secrets", Label("untrusted")),
    }, cap, 1)
    decision = monitor.decide(request)
    assert decision.verdict == "deny"
    assert any(v.check == "C10a" for v in decision.violations)


def test_setting_change_checks_value_provenance():
    monitor = Monitor()
    cap = capability({"change_setting": ("mfa.guest-17",)})
    request = Request("change_setting", {
        "name": Arg("mfa.guest-17", USER),
        "value": Arg("off", Label("untrusted")),
    }, cap, 1)
    decision = monitor.decide(request)
    assert decision.verdict == "deny"
    assert any(v.check == "C4e" for v in decision.violations)


def test_delegation_checks_child_grant_provenance():
    monitor = Monitor()
    cap = capability({"delegate": ("worker-1",), "read_file": ("/acme/docs/*",)})
    request = Request("delegate", {
        "agent": Arg("worker-1", USER),
        "child_grants": Arg({"read_file": ["/acme/docs/*"]}, Label("untrusted")),
    }, cap, 1)
    decision = monitor.decide(request)
    assert decision.verdict == "deny"
    assert any(v.check == "C4c" for v in decision.violations)


def test_denied_read_returns_no_content_and_does_not_log_data():
    session = Session(Monitor())
    session.start_task("Read only own tenant", {"read_file": ["/acme/*"]})
    result = session.ingest("read_file", "/tenants/globex/private.txt", "secret globex rows",
                            "user_files", tenant="globex", sens=2, evil=True)
    assert result is None
    event = next(x for x in session.trace if x.get("kind") == "act" and x.get("action") == "read_file")
    assert event["executed"] is False
    assert event["content"] is None
    assert event["label"] is None


def test_memory_read_requires_current_task_capability_before_value_lookup():
    class TrackingDict(dict):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.lookups = 0

        def get(self, key, default=None):
            self.lookups += 1
            return super().get(key, default)

    session = Session(Monitor())
    session.start_task("Write note", {"mem_write": ["notes/*"]})
    assert session.act("mem_write", key="notes/x", value=session.lit("private note"))
    tracked = TrackingDict(session.world.memory)
    session.world.memory = tracked

    session.start_task("No memory access", {"read_file": ["/acme/*"]})
    assert session.mem_read("notes/x") is None
    assert tracked.lookups == 0
    denied = [x for x in session.trace if x.get("kind") == "memread"][-1]
    assert denied["denied"] is True and denied["found"] is None

    session.start_task("Read note", {"mem_read": ["notes/*"]})
    value = session.mem_read("notes/x")
    assert value is not None and value.value == "private note"
    assert tracked.lookups == 1


def test_unlabelled_argument_defaults_to_untrusted():
    assert Arg("unclassified").label.integrity == "untrusted"



def test_session_derive_marks_missing_source_untrusted():
    from paca.harness import Session
    from paca.monitor import Monitor
    result = Session(Monitor()).derive("a value guessed without the blocked read", None)
    assert result.label.integrity == "untrusted"
    assert "unavailable_source" in result.label.origins



def test_derivation_without_sources_is_untrusted():
    from paca.provenance import derive
    assert derive("generated without source").label.integrity == "untrusted"


def test_mem_write_without_required_value_is_denied():
    monitor = Monitor()
    cap = capability({"mem_write": ("notes/*",)})
    request = Request("mem_write", {"key": Arg("notes/missing-value", USER)}, cap, 1)
    decision = monitor.decide(request)
    assert decision.verdict == "deny"
    assert "C14" in decision.checks



def test_required_argument_validation_cannot_be_disabled():
    monitor = Monitor(disable={"C14"})
    cap = capability({"mem_write": ("notes/*",)})
    request = Request("mem_write", {"key": Arg("notes/missing-value", USER)}, cap, 1)
    decision = monitor.decide(request)
    assert decision.verdict == "deny"
    assert "C14" in decision.checks


def test_unlabelled_action_and_tool_values_default_to_untrusted():
    session = Session(Monitor())
    session.start_task("Store a note", {"mem_write": ["notes/*"]})
    assert session.act("mem_write", key="notes/raw", value="unlabelled value")
    assert session.world.memory["notes/raw"].label.integrity == "untrusted"

    assert session.act(
        "mem_write",
        key=session.lit("notes/explicit"),
        value=session.lit("explicit user value"),
    )
    assert session.world.memory["notes/explicit"].label.integrity == "trusted"

    tool = Tool("docs_summarize", "1.0", "Summarise a document")
    session.start_task("Summarise a document", {"call_tool": ["docs_summarize"]}, pins=[tool])
    assert session.act("call_tool", tool=tool)
    tool_arg = session.trace[-1]["args"]["tool"]
    assert tool_arg[1] == "U/S0"


def test_ingest_does_not_promote_an_unlabelled_target_to_trusted():
    session = Session(Monitor())
    session.start_task("Read a project file", {"read_file": ["/acme/*"]})
    result = session.ingest(
        "read_file", "/acme/report.txt", "project report", "user_files", tenant="acme"
    )
    assert result is not None
    read_action = [item for item in session.trace if item.get("action") == "read_file"][-1]
    assert read_action["args"]["path"][1] == "U/S0"
    assert result.label.integrity == "trusted"


def test_required_target_must_be_a_non_empty_string():
    monitor = Monitor()
    cap = capability({"read_file": ("/acme/*",)})
    for step, invalid_target in enumerate(("", 7), start=1):
        request = Request(
            "read_file",
            {"path": Arg(invalid_target, USER)},
            cap,
            step,
        )
        decision = monitor.decide(request)
        assert decision.verdict == "deny"
        assert "C14" in decision.checks

