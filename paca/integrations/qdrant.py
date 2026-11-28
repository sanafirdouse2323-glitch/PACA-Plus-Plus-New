"""Read-only, tenant-scoped Qdrant vector search connector."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import quote, urlparse

from .provider_core import (
    ProviderAuthenticationError,
    ProviderCapture,
    ProviderPage,
    ProviderProtocolError,
    _ProviderHTTPClient,
    _version_id,
)


class QdrantVectorConnector:
    """Read-only Qdrant search connector using an injected API-key provider."""

    def __init__(
        self,
        base_url: str,
        *,
        cluster_id: str,
        tenant_id: str,
        api_key_provider: Callable[[], str],
        tenant_payload_key: str = "tenant_id",
        client: Any = None,
        max_response_bytes: int = 2_097_152,
        allow_insecure_localhost: bool = False,
    ) -> None:
        parsed = urlparse(base_url) if isinstance(base_url, str) else None
        local_http = (
            allow_insecure_localhost
            and parsed is not None
            and parsed.scheme == "http"
            and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        )
        if (
            parsed is None
            or (parsed.scheme != "https" and not local_http)
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Qdrant base_url must be a fixed HTTPS origin")
        if not isinstance(cluster_id, str) or not cluster_id:
            raise ValueError("cluster_id must be non-empty")
        if not isinstance(tenant_id, str) or not tenant_id or len(tenant_id) > 256:
            raise ValueError(
                "tenant_id must be a bounded non-empty trusted tenant identifier"
            )
        if (
            not isinstance(tenant_payload_key, str)
            or re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", tenant_payload_key)
            is None
        ):
            raise ValueError(
                "tenant_payload_key must be a simple or dotted Qdrant payload field path"
            )
        if not callable(api_key_provider):
            raise TypeError("api_key_provider must be a callable secret provider")
        self.base_url = base_url.rstrip("/")
        self.cluster_id = cluster_id
        self.tenant_id = tenant_id
        self.tenant_payload_key = tenant_payload_key
        self.connector_id = "qdrant:" + cluster_id + ":tenant:" + tenant_id
        self.api_key_provider = api_key_provider
        self.http = _ProviderHTTPClient(
            client=client,
            max_response_bytes=max_response_bytes,
            allow_insecure_localhost=allow_insecure_localhost,
        )

    def search(
        self,
        collection: str,
        vector: Sequence[float],
        *,
        limit: int = 10,
        query_filter: Mapping[str, Any] | None = None,
        with_payload: bool = True,
    ) -> ProviderPage:
        if not isinstance(collection, str) or not collection or len(collection) > 256:
            raise ValueError("Qdrant collection must be bounded and non-empty")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 200
        ):
            raise ValueError("Qdrant search limit must be between 1 and 200")
        if not isinstance(with_payload, bool):
            raise TypeError("with_payload must be a boolean")
        if not with_payload:
            raise ValueError(
                "Qdrant tenant isolation requires with_payload=True so every result can be verified"
            )
        if (
            not isinstance(vector, Sequence)
            or isinstance(vector, (str, bytes))
            or not vector
            or len(vector) > 65_536
        ):
            raise ValueError("Qdrant vector must be a bounded non-empty sequence")
        values = []
        for value in vector:
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise ValueError("Qdrant vector entries must be finite numbers")
            values.append(float(value))
        body: dict[str, Any] = {
            "vector": values,
            "limit": limit,
            "with_payload": True,
            "with_vector": False,
        }
        tenant_condition = {
            "key": self.tenant_payload_key,
            "match": {"value": self.tenant_id},
        }
        mandatory_filter: dict[str, Any] = {"must": [tenant_condition]}
        if query_filter is not None:
            if not isinstance(query_filter, Mapping):
                raise TypeError("Qdrant query_filter must be a mapping")
            try:
                encoded_filter = json.dumps(
                    query_filter,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
            except (TypeError, ValueError):
                raise ValueError("Qdrant filter must be canonical JSON") from None
            if len(encoded_filter) > 32_768:
                raise ValueError("Qdrant query_filter is too large")
            if query_filter:
                # Qdrant accepts a Filter object recursively as a Condition
                # inside "must". Keeping it as a separate conjunct prevents
                # the caller filter (including must_not/should clauses) from
                # replacing or weakening the mandatory tenant predicate.
                mandatory_filter["must"].append(dict(query_filter))
        body["filter"] = mandatory_filter
        try:
            key = self.api_key_provider()
        except Exception:  # noqa: BLE001 - secret-provider callbacks are trusted extensions; never expose their errors.
            # Secret-provider exceptions can contain backend details or secret
            # material. Do not propagate them into logs or API responses.
            raise ProviderAuthenticationError(
                "Qdrant API key provider failed"
            ) from None
        if not isinstance(key, str) or not key:
            raise ProviderAuthenticationError("Qdrant API key provider returned no key")
        url = (
            self.base_url
            + "/collections/"
            + quote(collection, safe="")
            + "/points/search"
        )
        response = self.http.request_json(
            "POST",
            url,
            headers={"api-key": key, "Content-Type": "application/json"},
            json_body=body,
        )
        result = response.get("result", [])
        if not isinstance(result, list):
            raise ProviderProtocolError("Qdrant result field was not a list")
        captures = []
        for item in result:
            if not isinstance(item, dict) or "id" not in item:
                raise ProviderProtocolError(
                    "Qdrant returned a point without an identifier"
                )
            payload = item.get("payload")
            if not isinstance(payload, Mapping):
                raise ProviderProtocolError(
                    "Qdrant returned a point without verifiable tenant payload metadata"
                )
            tenant_value: Any = payload
            for component in self.tenant_payload_key.split("."):
                if (
                    not isinstance(tenant_value, Mapping)
                    or component not in tenant_value
                ):
                    tenant_value = None
                    break
                tenant_value = tenant_value[component]
            if tenant_value != self.tenant_id:
                raise ProviderProtocolError(
                    "Qdrant returned a point outside the connector's authenticated tenant"
                )
            point_id = str(item["id"])
            captured_value = {
                **item,
                "collection": collection,
                "tenant_id": self.tenant_id,
            }
            captures.append(
                ProviderCapture(
                    provider="qdrant",
                    connector_id=self.connector_id,
                    object_id=f"qdrant:{self.cluster_id}:{collection}:{point_id}",
                    version_id=_version_id(captured_value),
                    provider_version=str(item.get("version", "")),
                    value=captured_value,
                )
            )
        return ProviderPage(tuple(captures), None)

    def close(self) -> None:
        self.http.close()

