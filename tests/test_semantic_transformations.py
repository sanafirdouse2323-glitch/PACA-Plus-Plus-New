"""Synthetic conformance fixtures for provenance across semantic transformations.

These tests check that explicitly declared derivation edges preserve source restrictions
when wording changes. They do not test whether an LLM discovers every latent semantic
dependency or reconstructs source facts without a supplied lineage edge.
"""

from __future__ import annotations

import hashlib

import pytest

from paca.provenance import Arg, Label, ProvenanceGraph, derive as derive_untracked


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _restricted_source(graph: ProvenanceGraph) -> Arg:
    value = "The restricted recovery phrase is amber-orchid-742."
    return graph.add_source(
        value,
        object_id="customer-record-17",
        version_id="v1",
        source="crm:customer-record-17",
        source_class="confidential_customer_record",
        content_digest=_digest(value),
        label=Label(
            integrity="untrusted",
            sensitivity=3,
            tenant="tenant-acme",
            origins=frozenset({"crm:customer-record-17"}),
        ),
        purpose="customer-support",
    )


@pytest.mark.parametrize(
    ("transformation", "derived_value"),
    [
        pytest.param(
            "paraphrase",
            "The customer's recovery phrase is amber orchid, number 742.",
            id="paraphrase",
        ),
        pytest.param(
            "summarise",
            "A restricted recovery phrase is recorded for this customer.",
            id="summary",
        ),
        pytest.param(
            "translate",
            "La frase de recuperación restringida es amber-orchid-742.",
            id="translation",
        ),
        pytest.param(
            "structured_extraction",
            '{"recovery_phrase":"amber-orchid-742"}',
            id="structured-extraction",
        ),
        pytest.param(
            "reconstruction",
            "The combined fragments identify amber-orchid-742 as the recovery phrase.",
            id="semantic-reconstruction-with-declared-source",
        ),
    ],
)
def test_reworded_derived_value_retains_restricted_source_lineage(
    transformation: str,
    derived_value: str,
):
    graph = ProvenanceGraph()
    source = _restricted_source(graph)

    derived = graph.derive(
        derived_value,
        source,
        object_id=f"derived-{transformation}",
        version_id="v1",
        content_digest=_digest(derived_value),
        transformation=transformation,
        purpose="customer-support",
    )

    assert derived.label.integrity == "untrusted"
    assert derived.label.sensitivity == 3
    assert derived.label.tenant == "tenant-acme"
    assert "crm:customer-record-17" in derived.label.origins
    assert not derived.lineage_incomplete

    derived_node_id = next(iter(derived.lineage_refs))
    derived_node = graph.get_node(derived_node_id)
    assert derived_node is not None
    assert derived_node.transformation == transformation
    assert derived_node.parent_ids == tuple(source.lineage_refs)
    assert graph.ancestors(derived_node_id)[0].source == "crm:customer-record-17"


def test_restrictions_survive_memory_compaction_retrieval_and_agent_transfer():
    graph = ProvenanceGraph()
    source = _restricted_source(graph)

    summary = graph.derive(
        "Customer record summary, including a restricted recovery credential.",
        source,
        object_id="summary",
        version_id="v1",
        content_digest=_digest(
            "Customer record summary, including a restricted recovery credential."
        ),
        transformation="summarise",
        purpose="customer-support",
    )
    compacted = graph.derive(
        "compact-summary:customer-17",
        summary,
        object_id="memory-entry",
        version_id="v1",
        content_digest=_digest("compact-summary:customer-17"),
        transformation="memory_compaction",
        purpose="customer-support",
    )
    retrieved = graph.derive(
        "A retrieved summary containing the customer's recovery detail.",
        compacted,
        object_id="retrieved-summary",
        version_id="v1",
        content_digest=_digest(
            "A retrieved summary containing the customer's recovery detail."
        ),
        transformation="memory_retrieval",
        purpose="customer-support",
    )
    transferred = graph.derive(
        "Message to specialist agent: customer recovery detail attached.",
        retrieved,
        object_id="agent-message",
        version_id="v1",
        content_digest=_digest(
            "Message to specialist agent: customer recovery detail attached."
        ),
        transformation="agent_to_agent_transfer",
        purpose="customer-support",
    )

    assert transferred.label.sensitivity == 3
    assert transferred.label.integrity == "untrusted"
    assert transferred.label.tenants == frozenset({"tenant-acme"})
    assert transferred.label.origins == frozenset({"crm:customer-record-17"})

    nodes = graph.ancestors(next(iter(transferred.lineage_refs)))
    assert [node.transformation for node in nodes] == [
        "source",
        "summarise",
        "memory_compaction",
        "memory_retrieval",
        "agent_to_agent_transfer",
    ]


def test_combining_fragments_preserves_every_parent_and_highest_restriction():
    graph = ProvenanceGraph()
    first = graph.add_source(
        "Customer's first identifier fragment: amber",
        object_id="fragment-a",
        version_id="v1",
        source="crm:fragment-a",
        source_class="confidential_customer_record",
        content_digest=_digest("Customer's first identifier fragment: amber"),
        label=Label("trusted", sensitivity=2, tenant="tenant-acme"),
    )
    second = graph.add_source(
        "Customer's second identifier fragment: orchid-742",
        object_id="fragment-b",
        version_id="v1",
        source="billing:fragment-b",
        source_class="restricted_billing_record",
        content_digest=_digest("Customer's second identifier fragment: orchid-742"),
        label=Label("untrusted", sensitivity=3, tenant="tenant-acme"),
    )
    output = "Combined customer recovery phrase: amber-orchid-742."
    reconstructed = graph.derive(
        output,
        first,
        second,
        object_id="combined-reconstruction",
        version_id="v1",
        content_digest=_digest(output),
        transformation="combine_fragments",
    )

    assert reconstructed.label.integrity == "untrusted"
    assert reconstructed.label.sensitivity == 3
    assert reconstructed.label.tenants == frozenset({"tenant-acme"})
    assert reconstructed.label.origins == frozenset(
        {"crm:fragment-a", "billing:fragment-b"}
    )
    node = graph.get_node(next(iter(reconstructed.lineage_refs)))
    assert node is not None
    assert set(node.parent_ids) == set(first.lineage_refs | second.lineage_refs)


def test_untracked_or_incomplete_dependency_fails_closed_for_explicit_lineage():
    graph = ProvenanceGraph()
    source = _restricted_source(graph)
    incomplete = Arg(
        "text generated using hidden, unrecorded context",
        label=source.label,
        lineage_refs=source.lineage_refs,
        lineage_incomplete=True,
    )

    with pytest.raises(ValueError, match="complete explicit source lineage"):
        graph.derive(
            "output that may depend on omitted context",
            incomplete,
            object_id="incomplete-derived",
            version_id="v1",
            content_digest=_digest("output that may depend on omitted context"),
            transformation="unknown_dependency",
        )



def test_opaque_model_output_without_recorded_source_edges_stays_incomplete():
    """Unknown model context must not be silently upgraded into complete lineage."""
    opaque_model_output = Arg(
        "A reconstructed value derived from context the adapter did not record.",
        label=Label(
            integrity="untrusted",
            sensitivity=3,
            tenant="tenant-acme",
        ),
    )

    derived = derive_untracked(
        "A paraphrase emitted by a model from opaque context.",
        opaque_model_output,
    )

    assert derived.lineage_refs == frozenset()
    assert derived.lineage_incomplete is True
    assert derived.label.integrity == "untrusted"
    assert derived.label.sensitivity == 3
    assert derived.label.tenants == frozenset({"tenant-acme"})

    with pytest.raises(ValueError, match="complete explicit source lineage"):
        ProvenanceGraph().derive(
            "A value that must not be treated as lineage-complete.",
            derived,
            object_id="opaque-model-output",
            version_id="v1",
            content_digest=_digest(
                "A value that must not be treated as lineage-complete."
            ),
            transformation="opaque_model_generation",
        )
