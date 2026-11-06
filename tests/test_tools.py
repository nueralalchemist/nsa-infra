import pytest

from nsa.core.tools import ToolDenied, ToolError, ToolRunner
from nsa.tools import builtin


def test_read_file_guards(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "ok.txt").write_text("hello")
    (tmp_path / "bin.dat").write_bytes(b"MZ\x00\x01binary")
    assert builtin.read_file("ok.txt") == "hello"
    with pytest.raises(ToolError, match="binary"):
        builtin.read_file("bin.dat")
    with pytest.raises(ToolError, match="outside allowed roots"):
        builtin.read_file("/etc/passwd")


def test_write_file_is_confined_to_output_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NSA_OUT", str(tmp_path / "out"))
    assert builtin.write_file("sigma/a.yml", "x").endswith("out/sigma/a.yml")
    for bad in ("../evil", "/etc/evil"):
        with pytest.raises(ToolError):
            builtin.write_file(bad, "x")


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://localhost:11434/", "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.5/", "file:///etc/passwd", "ftp://example.com/",
])
def test_fetch_url_blocks_ssrf_targets(url):
    with pytest.raises(ToolError):
        builtin.fetch_url(url)


def test_runner_enforces_allowlist_and_risk_tiers(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "f.txt").write_text("x")
    runner = ToolRunner(["read_file", "write_file"], approver=lambda t, a: False, agent="t")
    assert runner.call("read_file", path="f.txt") == "x"          # read tier: automatic
    with pytest.raises(ToolDenied):                                # not on this agent's allowlist
        runner.call("fetch_url", url="https://example.com")
    with pytest.raises(ToolDenied):                                # write tier: approver said no
        runner.call("write_file", path="a", content="b")
    with pytest.raises(ToolDenied):                                # no approver at all: deny by default
        ToolRunner(["write_file"]).call("write_file", path="a", content="b")
