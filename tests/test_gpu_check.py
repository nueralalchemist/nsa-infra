import httpx

from nsa.core.llm import Endpoint, cpu_only_models, ollama_loaded_models, ollama_warm

EP = Endpoint("local", "http://localhost:11434/v1")


def _client(payload, status=200):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(status, json=payload)

    return httpx.MockTransport(handler), seen


def test_loaded_models_parsed_from_api_ps_and_v1_suffix_stripped():
    transport, seen = _client({"models": [{"name": "qwen3:8b", "size": 5_900_000_000, "size_vram": 0}]})
    loaded = ollama_loaded_models(EP, transport=transport)
    assert seen == ["http://localhost:11434/api/ps"]
    assert cpu_only_models(loaded) == ["qwen3:8b"]


def test_gpu_resident_model_is_not_flagged():
    transport, _ = _client({"models": [{"name": "m", "size": 5_000, "size_vram": 5_000}]})
    assert cpu_only_models(ollama_loaded_models(EP, transport=transport)) == []


def test_partial_offload_is_not_flagged_but_empty_vram_is():
    assert cpu_only_models([{"name": "a", "size": 10, "size_vram": 4}]) == []
    assert cpu_only_models([{"name": "b", "size": 10, "size_vram": 0}]) == ["b"]


def test_non_ollama_endpoint_returns_none():
    transport, _ = _client({"detail": "nope"}, status=404)
    assert ollama_loaded_models(EP, transport=transport) is None


def test_warm_posts_empty_prompt():
    bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content)
        return httpx.Response(200, json={"done": True})

    assert ollama_warm(EP, "qwen3:8b", transport=httpx.MockTransport(handler))
    assert b'"prompt": ""' in bodies[0] or b'"prompt":""' in bodies[0]
