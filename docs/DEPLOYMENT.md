# Deployment guide

How to run NSA on your own machine, and how to add the optional cloud gateway. For the exact commands on a fresh machine see [`infra/RUNBOOK.md`](../infra/RUNBOOK.md); for the installers' internals see [`infra/README.md`](../infra/README.md).

## 1. Choose a topology

| Topology | What you run | Good for | Trade-off |
|---|---|---|---|
| **A. Local only** | Ollama + `nsa` on your machine | Day-to-day work with sensitive data; nothing leaves the machine | Bound by your own GPU/CPU |
| **B. Local + cloud, SSH tunnel** | A, plus a gateway box that listens on its own `127.0.0.1` | Offloading non-sensitive work; fewest moving parts | You keep a tunnel process running |
| **C. Local + cloud, Tailscale** | A, plus a gateway on your tailnet | A permanent, always-reachable remote model | Needs Tailscale on both ends and `/dev/net/tun` on the box |

Start with **A**, add **B** to validate the cloud path, move to **C** if you want it permanent. Sensitive agents stay local in every topology.

## 2. Topology A: local only

```bash
git clone <your-repo-url> nsa && cd nsa
python3 -m venv .venv && . .venv/bin/activate
pip install -e .                    # runtime deps: httpx, pyyaml
cp .env.example .env                # defaults work with Ollama on localhost
ollama pull qwen3:8b                # or whichever models config/models.yaml names
nsa doctor --warm                   # endpoint, model names, and GPU offload
nsa run "what is a SIEM?"
```

`nsa doctor --warm` is the important check on a GPU machine: it confirms the model is really in VRAM. If it is not, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md#ollama-is-using-the-cpu-instead-of-the-gpu).

## 3. Topologies B and C: the cloud gateway

### 3.1 What it builds

```
 workstation                         gateway host (Debian/Ubuntu, systemd)
 ┌──────────┐  tunnel or tailnet   ┌────────────────────────────────────────┐
 │ nsa CLI  │ ───────────────────▶ │ LiteLLM :4000  (API key required)      │
 └──────────┘   OpenAI /v1 API     │      └─▶ Ollama 127.0.0.1:11434        │
                                   └────────────────────────────────────────┘
```

Ollama never leaves localhost. LiteLLM is the single entry point, runs as the unprivileged `nsa` user from a read-only virtualenv, and binds to `127.0.0.1` or the Tailscale IP, never `0.0.0.0`. The host keeps **no state worth saving**: rebuild it by running the installer on a new machine.

### 3.2 Host requirements

| | Minimum | Notes |
|---|---|---|
| OS | Debian or Ubuntu, x86_64 or aarch64 | The installer uses `apt`. |
| Init | systemd (recommended) | Without it the shell edition falls back to `nohup`: no restart after reboot. The Ansible edition requires systemd. |
| Access | root or passwordless `sudo` | |
| Network | outbound HTTPS to `ollama.com`, `registry.ollama.ai`, `pypi.org` (+ `pkgs.tailscale.com`) | `preflight` checks all of them. |
| Disk | 10 GB free on `/` for a fresh install | A re-run needs only 2 GB. |
| RAM | 6 GB+ | A 4B Q4 model needs ~4 GB. |

Run the read-only check first: `./shell/bootstrap.sh preflight`.

### 3.3 Shell or Ansible?

| | Shell edition (`infra/shell/`) | Ansible edition (`infra/ansible/`) |
|---|---|---|
| Best for | one box, quick start | several hosts, review before applying |
| Needs on the target | bash, curl | Python (+ ansible-core wherever you run it) |
| Preview | `--dry-run` | `--check --diff` |
| Settings | `infra/infra.env` | `infra/ansible/group_vars/all.yml` |
| Extras | `preflight`, `verify`, nohup fallback | tags, `--limit`, opt-in `hardening` role (firewall + auto-updates) |

Both render byte-identical gateway config, systemd unit and Ollama override. The shell edition has been run on real machines; the Ansible edition has only been linted, syntax-checked and render-compared ([TESTING.md](TESTING.md)).

### 3.4 Procedure

```bash
# on the host (files from infra/)
./shell/bootstrap.sh preflight
cp infra.env.example infra.env && sed -i 's/^NSA_EXPOSE=.*/NSA_EXPOSE=localhost/' infra.env
sudo -E ./shell/bootstrap.sh server --dry-run | head -60       # preview
sudo -E ./shell/bootstrap.sh server 2>&1 | tee ~/nsa-install.log
```

The install ends with a smoke test (liveness, key rejection, model listing, a real completion) and prints the versions it installed so you can pin them. Then fetch the key to your workstation and connect:

```bash
# key -> private file on the workstation (never paste it anywhere)
ssh myhost "sudo grep '^LITELLM_MASTER_KEY=' /etc/nsa/gateway.env" | cut -d= -f2- > ~/nsa-gateway.key && chmod 600 ~/nsa-gateway.key
nsa tunnel myhost                  # topology B; leave running
nsa connect --url http://127.0.0.1:4000/v1 --key-file ~/nsa-gateway.key
nsa doctor
```

For topology C set `NSA_EXPOSE=tailscale` and `export TAILSCALE_AUTHKEY=...` before the install, put the workstation on the same tailnet, and `nsa connect --url http://<tailscale-ip>:4000/v1 ...` with no tunnel.

## 4. Choosing the gateway model

The model matters more than anything else on a small CPU machine.

| Model | Type | On 4 vCPU / 8 GiB | Verdict |
|---|---|---|---|
| `qwen3:4b-instruct` | non-thinking | one-word reply 3-6 s; SOC triage 27 s; Sigma + self-test 36 s | **Default.** |
| `qwen3:4b` | thinking-only | triage exhausted a 4096-token budget (3.5 min, no answer); with `reasoning_effort: none` its reasoning leaks into the answer | Avoid for structured agents. |
| larger models | n/a | RAM-bound; also needs disk (a 4B model is ~2.5 GB) | Change `NSA_MODEL_*_CLOUD` and re-run. |

Use the **same model for both aliases** on a small box: Ollama keeps one model loaded, so two different models are reloaded on every switch.

## 5. Measured footprint (4 vCPU / 8 GiB / 16 GiB root, Debian 13)

Measured on the test provider's VM (see [section 7](#7-choosing-a-cloud-provider)); other providers will differ mainly in network speed.

| Item | Result |
|---|---|
| Fresh install, command to "All checks passed" | 66 s on a fast network (about 1 minute of downloads included) |
| Disk used on `/` by the stack | ≈ 6.3 GB: Ollama ≈ 2.4 GB, one 4B model ≈ 2.5 GB, LiteLLM venv ≈ 0.74 GB |
| Gateway ready after a (re)start | ≈ 20 s |
| Idle RAM | not separately measured |

A 16 GiB root disk therefore holds **one** extra model at most. Keep an eye on `df -h /`.

## 6. Operating it

| Task | How |
|---|---|
| Health check | `sudo ./shell/bootstrap.sh verify` on the host; `nsa doctor` from the workstation |
| Logs | `sudo journalctl -u nsa-gateway -u ollama --no-pager -n 80` |
| Change/upgrade the model | edit the two `NSA_MODEL_*_CLOUD` lines, re-run the installer (it pulls and re-renders the config), set the same names on the client, `nsa connect` again. Remove the old model with `ollama rm <name>` to reclaim disk. |
| Add models | `NSA_EXTRA_MODELS="name1 name2"` (chat models) and re-run |
| Pin versions | after a good install copy `NSA_LITELLM_VERSION=` from its output into `infra.env`; set `NSA_OLLAMA_INSTALL_SHA256` to the hash printed in the log |
| Re-run / repair | re-run the installer: it is idempotent and keeps the key (the key file hash stays identical) |
| Rotate the key | delete `/etc/nsa/gateway.env`, re-run the installer, then `nsa connect --key-file` with the new key. *(By design; not exercised in testing.)* |
| Reboot | services return on their own (verified) |
| Tear down | delete the machine. There is nothing to back up. |

## 7. Choosing a cloud provider

NSA does not depend on a particular provider. Any of them will do if the machine offers:

| Check | Why it matters |
|---|---|
| Debian or Ubuntu image, x86_64 or aarch64 | the installer uses `apt` |
| SSH access with root or passwordless `sudo` | the installer creates a user, services and files under `/etc` and `/opt` |
| systemd | services restart on reboot (the shell edition falls back to `nohup` without it) |
| Outbound HTTPS to `ollama.com`, `registry.ollama.ai`, `pypi.org` | downloads; `preflight` tests these |
| ≥ 10 GB free on `/` and ≥ 6 GB RAM | one 4B model, Ollama and LiteLLM; see the footprint above |
| `/dev/net/tun` (Tailscale mode only) | otherwise use `NSA_EXPOSE=localhost` and an SSH tunnel |

Things worth reading in your provider's terms before relying on it: the number of machines your plan allows, idle auto-pause and maximum runtime (services restart on wake, but any tunnel drops while the machine is paused), and what the operator may see on a machine you do not control (see [SECURITY.md](SECURITY.md)).

Run `./shell/bootstrap.sh preflight` on a new machine first. It checks every item above in a few seconds and changes nothing.

### Example: the provider used in our tests (instabox)

The real-machine results in this repository were obtained on [instabox](https://instabox.sh) VMs (free plan, Debian 13, 4 vCPU / 8 GiB, 16 GiB root disk):

- Its CLI can replace `ssh`/`scp`: `instabox push`, `instabox exec --background` (+ `jobs wait`) and `instabox port-forward <machine> 4000:4000` as the tunnel. The exact sequence is in the [runbook appendix](../infra/RUNBOOK.md#appendix-using-a-provider-cli-example-instabox).
- The free plan allowed **one** machine, so rebuilding meant deleting the old one first (nothing on it was worth keeping).
- Idle machines pause after 30 minutes and runtime is capped by the plan. *(Pause and resume were not exercised.)*
