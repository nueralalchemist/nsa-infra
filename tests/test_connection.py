import os
import stat

import httpx
import pytest

from nsa.cli import tunnel_command
from nsa.core.config import set_env_values
from nsa.core.llm import Endpoint, LLMClient, LLMError, check_endpoint
from nsa.core.modes import ModeError

EP = Endpoint("cloud", "http://100.64.0.9:4000/v1", "sk-test")


def _status(code=200, body=None, exc=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if exc:
            raise exc
        assert request.headers["authorization"] == "Bearer sk-test"
        return httpx.Response(code, json=body if body is not None else {})
    return httpx.MockTransport(handler)


def test_check_endpoint_distinguishes_every_failure_mode():
    ok = check_endpoint(EP, transport=_status(200, {"data": [{"id": "qwen3:4b"}]}))
    assert (ok.state, ok.models) == ("ok", ("qwen3:4b",))
    assert check_endpoint(EP, transport=_status(401)).state == "auth_failed"
    assert check_endpoint(EP, transport=_status(403)).state == "auth_failed"
    assert check_endpoint(EP, transport=_status(502)).state == "error"
    # LiteLLM without a database: a wrong key comes back as 400 no_db_connection, a missing key as a bare 500
    litellm_bad_key = {"error": {"message": "No connected db.", "type": "no_db_connection", "code": "400"}}
    assert check_endpoint(EP, transport=_status(400, litellm_bad_key)).state == "auth_failed"
    assert check_endpoint(EP, transport=_status(500, {"error": {"message": "Authentication Error"}})).state == "auth_failed"
    assert check_endpoint(EP, transport=_status(500, {"error": {"message": "disk on fire"}})).state == "error"
    assert check_endpoint(EP, transport=_status(200, {"oops": 1})).state == "ok"  # empty list is still a valid answer
    assert check_endpoint(EP, transport=_status(exc=httpx.ConnectError("x"))).state == "unreachable"
    timeout = check_endpoint(EP, transport=_status(exc=httpx.ConnectTimeout("x")))
    assert timeout.state == "unreachable" and "timed out" in timeout.detail
    assert check_endpoint(Endpoint("cloud", ""), transport=_status()).state == "unconfigured"


@pytest.mark.parametrize("code,needle", [(401, "rejected the API key"), (404, "does not serve model"),
                                         (400, "rejected the API key")])
def test_chat_errors_explain_what_to_do(code, needle):
    def handler(request):
        return httpx.Response(code, text="model 'x' not found" if code == 404 else ("No connected db. no_db_connection" if code == 400 else "unauthorized"))
    llm = LLMClient(EP, {"aliases": {"main": {"cloud": "qwen3:4b"}}}, transport=httpx.MockTransport(handler))
    with pytest.raises(LLMError, match=needle):
        llm.chat([{"role": "user", "content": "hi"}])


def test_set_env_values_updates_in_place_with_private_mode(tmp_path):
    env = tmp_path / ".env"
    env.write_text("# keep me\nNSA_CLOUD_URL=old\nOTHER=1\n")
    os.chmod(env, 0o644)
    set_env_values({"NSA_CLOUD_URL": "http://h:4000/v1", "NSA_CLOUD_KEY": "sk-abc"}, env)
    assert env.read_text() == "# keep me\nNSA_CLOUD_URL=http://h:4000/v1\nOTHER=1\nNSA_CLOUD_KEY=sk-abc\n"
    assert stat.S_IMODE(env.stat().st_mode) == 0o600
    set_env_values({"NSA_CLOUD_URL": "http://h:4000/v1"}, env)               # idempotent
    assert env.read_text().count("NSA_CLOUD_URL=") == 1


def test_set_env_values_refuses_injection(tmp_path):
    for bad in ({"NSA_X": "a\nNSA_CLOUD_KEY=stolen"}, {"bad key": "v"}, {"lower": "v"}):
        with pytest.raises(ValueError):
            set_env_values(bad, tmp_path / ".env")


def test_set_env_values_creates_from_example(tmp_path, monkeypatch):
    monkeypatch.setattr("nsa.core.config.ROOT", tmp_path)
    (tmp_path / ".env.example").write_text("NSA_CLOUD_URL=\n# note\n")
    path = set_env_values({"NSA_CLOUD_URL": "http://h/v1"})
    assert path.read_text() == "NSA_CLOUD_URL=http://h/v1\n# note\n"


def test_tunnel_command_is_safe_and_correct():
    cmd = tunnel_command("ubuntu@203.0.113.9", 4100, "~/.ssh/id")
    assert cmd[:3] == ["ssh", "-N", "-L"] and "127.0.0.1:4100:127.0.0.1:4100" in cmd
    assert "ExitOnForwardFailure=yes" in cmd and cmd[-2:] == ["--", "ubuntu@203.0.113.9"]
    for bad in ("-oProxyCommand=evil", "host;rm -rf /", "a b", "", "$(id)"):
        with pytest.raises(ModeError):
            tunnel_command(bad, 4000)
    with pytest.raises(ModeError):
        tunnel_command("host", 70000)
