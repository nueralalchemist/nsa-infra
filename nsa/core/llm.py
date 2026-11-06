"""OpenAI-compatible chat client. One class for both local (Ollama) and cloud (LiteLLM) modes."""
from __future__ import annotations

import re
from dataclasses import dataclass

import httpx

from nsa.core.audit import Audit, sha256_short
from nsa.core.redact import Redactor

_THINK = re.compile(r"<think>.*?</think>", re.S)


class LLMError(RuntimeError):
    pass


@dataclass(frozen=True)
class Endpoint:
    mode: str
    base_url: str
    api_key: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.base_url)

    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}


class LLMClient:
    def __init__(
        self,
        endpoint: Endpoint,
        models: dict,
        *,
        redact_level: str = "standard",
        audit: Audit | None = None,
        agent: str = "",
        transport: httpx.BaseTransport | None = None,
    ):
        if not endpoint.configured:
            raise LLMError(f"{endpoint.mode} endpoint is not configured")
        self.endpoint = endpoint
        self.models = models
        self.defaults = models.get("defaults", {})
        self.audit = audit
        self.agent = agent
        self.redactor = Redactor(redact_level) if endpoint.mode == "cloud" else None
        self._http = httpx.Client(
            base_url=endpoint.base_url.rstrip("/") + "/",
            headers=endpoint.headers(),
            timeout=float(self.defaults.get("timeout", 300)),
            transport=transport,
        )

    @property
    def mode(self) -> str:
        return self.endpoint.mode

    def model_for(self, alias: str) -> str:
        entry = self.models.get("aliases", {}).get(alias)
        if not entry or not entry.get(self.mode):
            raise LLMError(f"no model mapped for alias '{alias}' in {self.mode} mode (config/models.yaml)")
        return entry[self.mode]

    def chat(
        self,
        messages: list[dict],
        alias: str = "main",
        *,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        model = self.model_for(alias)
        outgoing = messages
        if (self.models.get("aliases", {}).get(alias) or {}).get("no_think") and model.startswith("qwen3"):
            # Qwen3 soft switch: skip the long reasoning trace for cheap routing/classification calls.
            outgoing = [*messages[:-1], {**messages[-1], "content": messages[-1]["content"] + " /no_think"}]
        if self.redactor:
            outgoing = [{**m, "content": self.redactor.redact(m["content"])} for m in outgoing]
        payload: dict = {
            "model": model,
            "messages": outgoing,
            "stream": False,
            "temperature": self.defaults.get("temperature", 0.2) if temperature is None else temperature,
            "max_tokens": max_tokens or self.defaults.get("max_tokens", 2048),
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        effort = (self.models.get("aliases", {}).get(alias) or {}).get("reasoning_effort")
        if isinstance(effort, dict):  # per-mode setting, e.g. {local: "", cloud: "none"}
            effort = effort.get(self.mode)
        if effort:
            # Current Ollama/LiteLLM honour this; /no_think alone no longer stops Qwen3 from reasoning.
            payload["reasoning_effort"] = effort
        try:
            resp = self._http.post("chat/completions", json=payload)
            resp.raise_for_status()
            choice = resp.json()["choices"][0]
            content = choice["message"]["content"] or ""
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            if _looks_like_auth_failure(code, exc.response.text):
                raise LLMError(f"{self.mode} endpoint rejected the API key ({code}). "
                               f"Check NSA_{self.mode.upper()}_KEY or re-run `nsa connect`.") from exc
            if code == 404 and "model" in exc.response.text.lower():
                raise LLMError(f"{self.mode} endpoint does not serve model '{model}'. "
                               f"Run `nsa doctor` to compare config/models.yaml with what the endpoint offers.") from exc
            raise LLMError(f"{self.mode} endpoint returned {code}: {exc.response.text[:200]}") from exc
        except httpx.HTTPError as exc:
            raise LLMError(f"cannot reach {self.mode} endpoint {self.endpoint.base_url}: {exc}") from exc
        except (KeyError, IndexError, ValueError) as exc:
            raise LLMError(f"unexpected response shape from {self.mode} endpoint") from exc

        content = _THINK.sub("", content).strip()
        if not content:
            if choice.get("finish_reason") == "length":
                raise LLMError(
                    f"the {self.mode} model used its whole token budget ({payload['max_tokens']}) on hidden reasoning and "
                    "produced no answer. Options: raise defaults.max_tokens in config/models.yaml (slower); for a model that can toggle "
                    "thinking (e.g. qwen3:8b) set reasoning_effort: none for the alias; for a thinking-only model (e.g. qwen3:4b, "
                    "where 'none' would leak its reasoning into the answer) switch to an instruct variant such as qwen3:4b-instruct.")
            raise LLMError(f"the {self.mode} endpoint returned an empty reply")
        if self.redactor:
            content = self.redactor.restore(content)
        if self.audit:
            self.audit.log(
                "llm_call", agent=self.agent, mode=self.mode, model=model,
                prompt_sha=sha256_short("".join(m["content"] for m in messages)),
                prompt_chars=sum(len(m["content"]) for m in messages), reply_chars=len(content),
            )
        return content


def probe(endpoint: Endpoint, timeout: float = 2.0, transport: httpx.BaseTransport | None = None) -> bool:
    """True if the endpoint answers GET /models."""
    if not endpoint.configured:
        return False
    try:
        with httpx.Client(timeout=timeout, transport=transport) as client:
            r = client.get(endpoint.base_url.rstrip("/") + "/models", headers=endpoint.headers())
        return r.status_code < 500
    except httpx.HTTPError:
        return False


@dataclass(frozen=True)
class EndpointStatus:
    state: str  # ok | unconfigured | unreachable | auth_failed | error
    detail: str = ""
    models: tuple[str, ...] = ()


_AUTH_MARKERS = ("no_db_connection", "authentication error", "invalid api key", "invalid_api_key", "unauthorized")


def _looks_like_auth_failure(status: int, body: str) -> bool:
    """401/403, or the error shapes LiteLLM uses for a bad key when it runs without a database."""
    low = body.lower()
    return status in (401, 403) or (status in (400, 500) and any(m in low for m in _AUTH_MARKERS))


def check_endpoint(endpoint: Endpoint, timeout: float = 5.0,
                   transport: httpx.BaseTransport | None = None) -> EndpointStatus:
    """Authenticated GET /models, with the failure reason spelled out (unreachable vs bad key vs other)."""
    if not endpoint.configured:
        return EndpointStatus("unconfigured")
    try:
        with httpx.Client(timeout=timeout, transport=transport) as client:
            r = client.get(endpoint.base_url.rstrip("/") + "/models", headers=endpoint.headers())
    except httpx.TimeoutException:
        return EndpointStatus("unreachable", "timed out (firewall, wrong address, or the box/tailnet is down)")
    except httpx.HTTPError as exc:
        return EndpointStatus("unreachable", exc.__class__.__name__)
    if _looks_like_auth_failure(r.status_code, r.text):
        return EndpointStatus("auth_failed", f"HTTP {r.status_code}: the endpoint rejected the API key")
    if r.status_code >= 400:
        hint = "" if endpoint.api_key else " (no API key is configured; the gateway may require one)"
        return EndpointStatus("error", f"HTTP {r.status_code}{hint}")
    try:
        ids = tuple(m.get("id", "") for m in r.json().get("data", []))
    except (ValueError, AttributeError):
        return EndpointStatus("error", "response is not an OpenAI-style model list")
    return EndpointStatus("ok", models=ids)


def _ollama_root(endpoint: Endpoint) -> str:
    root = endpoint.base_url.rstrip("/")
    return root[:-3] if root.endswith("/v1") else root


def ollama_loaded_models(endpoint: Endpoint, timeout: float = 3.0,
                         transport: httpx.BaseTransport | None = None) -> list[dict] | None:
    """Models currently loaded in Ollama (name, size, size_vram), or None if this is not Ollama."""
    try:
        with httpx.Client(timeout=timeout, transport=transport) as client:
            r = client.get(_ollama_root(endpoint) + "/api/ps")
        r.raise_for_status()
        return [{"name": m.get("name", ""), "size": m.get("size", 0), "size_vram": m.get("size_vram", 0)}
                for m in r.json().get("models", [])]
    except (httpx.HTTPError, ValueError, AttributeError):
        return None


def ollama_warm(endpoint: Endpoint, model: str, timeout: float = 300.0,
                transport: httpx.BaseTransport | None = None) -> bool:
    """Load a model into memory without generating (empty prompt). True on success."""
    try:
        with httpx.Client(timeout=timeout, transport=transport) as client:
            r = client.post(_ollama_root(endpoint) + "/api/generate", json={"model": model, "prompt": "", "stream": False})
        return r.status_code == 200
    except httpx.HTTPError:
        return False


def cpu_only_models(loaded: list[dict]) -> list[str]:
    """Names of loaded models that have nothing in VRAM."""
    return [m["name"] for m in loaded if m.get("size", 0) > 0 and m.get("size_vram", 0) == 0]


def list_models(endpoint: Endpoint, timeout: float = 5.0) -> list[str]:
    with httpx.Client(timeout=timeout) as client:
        r = client.get(endpoint.base_url.rstrip("/") + "/models", headers=endpoint.headers())
        r.raise_for_status()
        return [m.get("id", "") for m in r.json().get("data", [])]
