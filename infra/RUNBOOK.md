# Runbook: install the gateway on a fresh machine

Goal: **a brand-new machine + this folder + one script = a working cloud gateway that your workstation's `nsa` can use**, and a machine you can throw away and rebuild the same way.

This sequence has been run end to end on real Debian 13 machines (4 vCPU / 8 GiB): fresh install, re-runs, a reboot, a model swap, and a rebuild on a brand-new machine. It has **not** been run on other distributions or architectures, and Tailscale mode and the Ansible edition are untested. If something fails, see [If something fails](#if-something-fails).

Conventions: `WSL$` = your workstation (WSL, Linux or macOS), `BOX$` = the gateway machine. If you log in as `root` on the box, drop `sudo`. The examples use [instabox](https://instabox.sh) for the machine; any Debian/Ubuntu host works.

## 0. Before you start

Create the machine in instabox (Ubuntu or Debian image if you can choose). Then add an alias to `~/.ssh/config` on **WSL** using whatever host, user, port and key instabox gives you. Using an alias keeps every later command identical:

```
Host instabox
  HostName <ip-or-hostname>
  User <user>
  Port <port-if-not-22>
  IdentityFile ~/.ssh/<your-key>
```

Check you can log in: `WSL$ ssh instabox 'hostname; whoami'`.

## Shortcut: the instabox CLI (verified end to end on a real machine)

If `instabox whoami` works on your WSL, you can skip SSH aliases and scp. This is exactly what was used to test it (`BOX` = the machine name from `instabox ls`):

```bash
WSL$ BOX=my-machine
WSL$ cd ~/neural_security_agent && instabox push $BOX ./infra /data/home/                       # upload installer
WSL$ instabox exec $BOX -- 'cd ~/infra && ./shell/bootstrap.sh preflight'                       # check
WSL$ instabox exec $BOX -- 'cd ~/infra && cp infra.env.example infra.env && sed -i "s/^NSA_EXPOSE=.*/NSA_EXPOSE=localhost/" infra.env'
WSL$ instabox exec --background $BOX -- 'cd ~/infra && sudo -E ./shell/bootstrap.sh server > ~/nsa-install.log 2>&1'   # prints a job id
WSL$ instabox jobs wait $BOX <job-id> --timeout 9m; instabox exec $BOX -- 'tail -30 ~/nsa-install.log'
WSL$ instabox exec $BOX -- 'sudo grep "^LITELLM_MASTER_KEY=" /etc/nsa/gateway.env' | cut -d= -f2- | tr -d '\r\n' > ~/nsa-gateway.key; chmod 600 ~/nsa-gateway.key
WSL$ instabox port-forward $BOX 4000:4000 &                                                      # the tunnel
WSL$ nsa connect --url http://127.0.0.1:4000/v1 --key-file ~/nsa-gateway.key
```

The generic ssh/scp steps below are equivalent for any other provider. Timings measured on a real instabox machine (4 vCPU / 8 GiB, free plan): full install ~1 minute on its fast network (about 6 GB of disk used on `/`), gateway ready ~20 s after a restart, SOC triage 27 s, Sigma rule with self-test 36 s, research plan about 2 minutes.

## 1. Put the installer on the box

You have not pushed to GitHub yet, so use the tarball (it contains only `infra/`, 20 KB, no secrets):

```bash
WSL$ cd ~/neural_security_agent
WSL$ tar --exclude='__pycache__' --exclude='infra/infra.env' --exclude='infra/ansible/inventory.ini' -czf /tmp/nsa-infra.tgz infra
WSL$ scp /tmp/nsa-infra.tgz instabox:~/
WSL$ ssh instabox
BOX$ tar -xzf nsa-infra.tgz && cd infra
```

(After you push the repo you can use `git clone` instead.)

## 2. Preflight (changes nothing)

```bash
BOX$ ./shell/bootstrap.sh preflight
```

You want `RESULT: ready to install`. Meaning of the lines: `FAIL` must be fixed (wrong OS, no disk, no internet). `WARN` is survivable: no systemd means services will not survive a reboot; no passwordless sudo means use `sudo -E`.

## 3. Configure for a small CPU box

```bash
BOX$ cp infra.env.example infra.env
BOX$ sed -i 's/^NSA_EXPOSE=.*/NSA_EXPOSE=localhost/' infra.env
BOX$ grep -E '^NSA_(EXPOSE|MODEL_.*_CLOUD)' infra.env
```

Why: `localhost` mode (reach the gateway through an SSH tunnel) has the fewest moving parts for a first test; Tailscale is section 9. The default model is **`qwen3:4b-instruct`** for both aliases: it does not do hidden reasoning, so it answers in seconds on 4 CPU cores. (Plain `qwen3:4b` is a *thinking-only* model: it spent a 4096-token budget on reasoning for 3.5 minutes and returned nothing. One model for both aliases also avoids reloads and saves disk.)

## 4. Install

```bash
BOX$ sudo -E ./shell/bootstrap.sh server --dry-run | head -70
BOX$ sudo -E ./shell/bootstrap.sh server 2>&1 | tee ~/nsa-install.log
```

Estimated 10-25 minutes, mostly downloads (Ollama ~2 GB, the model ~2.5 GB, LiteLLM ~0.7 GB). These are estimates; I could not measure them on instabox. Success looks like:

```
  PASS gateway is alive
  PASS request with no key is rejected (HTTP 500)
  PASS request with wrong key is rejected (HTTP 400)
  PASS authenticated /v1/models works (1 models)
  PASS model served: qwen3:4b-instruct
  PASS chat completion answered in NNs: "OK"
All checks passed.
================ NSA server ready ================
```

and at the end a line `NSA_LITELLM_VERSION=x.y.z`: keep it for section 10. The first completion can take a minute or more because the model has to load.

Quick health check you can repeat any time: `BOX$ sudo ./shell/bootstrap.sh verify` and `BOX$ systemctl is-active ollama nsa-gateway`.

## 5. Bring the gateway key to WSL (never paste it into a chat)

```bash
WSL$ ssh instabox "sudo grep '^LITELLM_MASTER_KEY=' /etc/nsa/gateway.env" | cut -d= -f2- > ~/nsa-gateway.key
WSL$ chmod 600 ~/nsa-gateway.key && wc -c ~/nsa-gateway.key
```

If `sudo` asks for a password over a non-interactive ssh, log in normally and read the key with `sudo cat /etc/nsa/gateway.env`, then paste it into the file yourself.

## 6. Connect from WSL

Terminal 1 (leave it running; Ctrl+C closes the tunnel):

```bash
WSL$ cd ~/neural_security_agent && source .venv/bin/activate
WSL$ nsa tunnel instabox
```

Terminal 2:

```bash
WSL$ cd ~/neural_security_agent && source .venv/bin/activate
WSL$ cp -n .env.example .env && chmod 600 .env
WSL$ sed -i 's/^NSA_LLM_TIMEOUT=.*/NSA_LLM_TIMEOUT=600/' .env
WSL$ nsa connect --url http://127.0.0.1:4000/v1 --key-file ~/nsa-gateway.key
WSL$ nsa doctor
```

`NSA_LLM_TIMEOUT=600` gives a slow CPU box time to answer. Do **not** set `NSA_*_REASONING_CLOUD=none` for `qwen3:4b-instruct` or `qwen3:4b`: it only works for models that can toggle thinking (like your local `qwen3:8b`); for these it makes raw reasoning leak into the answer.

Expected: `connect` ends with `round trip ok in N s: 'OK'`; `doctor` shows `cloud ... reachable, key accepted` with `main` and `fast` both `ok`.

## 7. Behaviour tests (what each should do)

```bash
WSL$ nsa run -m cloud -a assistant "In two sentences, what is a SIEM?"
WSL$ nsa run -m cloud -a research "Research plan: prompt injection in LLM agent frameworks"
WSL$ nsa run -m cloud -a soc_triage "Alert: 40 failed logons then success from 203.0.113.50"
WSL$ nsa run -m cloud -a soc_triage --allow-sensitive-cloud "Alert: 40 failed logons then success from 10.9.8.7"
WSL$ nsa run -m auto -a assistant "Name three logging best practices."
```

1. and 2. answer from the box (slow: estimate 10-60 s each; I have not measured CPU speed on instabox).
3. is **blocked** with `local-only` and sends nothing: that is the sensitivity gate working.
4. goes through with prompts redacted (the private IP never leaves WSL).
5. uses your **local GPU** (auto prefers local).

Fallback test: stop the tunnel (Ctrl+C in terminal 1), then `nsa doctor` should say `cloud UNREACHABLE` with a tunnel hint, and `nsa run -m auto -a assistant "hi"` should still work locally.

## 8. The two proofs that matter

**Idempotent re-run** (should be fast, change nothing, keep the same key):

```bash
BOX$ sudo sha256sum /etc/nsa/gateway.env
BOX$ sudo -E ./shell/bootstrap.sh server 2>&1 | grep -E 'already|PASS|All checks'
BOX$ sudo sha256sum /etc/nsa/gateway.env
```

Both hashes must match.

**Survives a reboot:**

```bash
BOX$ sudo reboot
# wait ~1 minute, then
WSL$ ssh instabox 'systemctl is-active ollama nsa-gateway && sudo /home/$USER/infra/shell/bootstrap.sh verify | tail -3'
```

**The real claim (rebuild from scratch):** when you are done, delete the machine, create a new one, and repeat sections 1-6 with the **same** commands. You should need nothing else except the new key (`nsa connect` with the new key file). If anything extra was needed, tell me: that is a bug in the playbook.

## 9. Optional: Tailscale mode (second pass)

Create a reusable, **tagged, expiring** auth key in the Tailscale admin console, then on the box set `NSA_EXPOSE=tailscale` in `infra.env`, run `export TAILSCALE_AUTHKEY=tskey-...` and re-run the installer. Your WSL must also be on the tailnet (install Tailscale inside WSL: your WSL has systemd, so this works). Then `nsa connect --url http://<box-tailscale-ip>:4000/v1 ...` with no tunnel. Needs `/dev/net/tun` on the box; `preflight` tells you.

## 10. Afterwards

1. Pin what worked so rebuilds are reproducible: in `infra/infra.env` set `NSA_LITELLM_VERSION=<printed version>`.
2. Delete the throwaway key from WSL if you will not keep the box: `shred -u ~/nsa-gateway.key`, and remove `NSA_CLOUD_KEY` from `.env`.
3. Remember the box belongs to a third party. Do not send real customer data, SIEM exports or malware samples to it. The CLI already keeps `soc_triage` and `malware_triage` local-only and redacts everything else, but treat that as a seatbelt, not a vault.

## Optional: the enterprise (Ansible) edition

Test it on a **fresh** machine, not the one you already installed, so the two editions don't mask each other's bugs.

```bash
BOX$ sudo apt-get update && sudo apt-get install -y ansible-core
BOX$ cd ~/infra/ansible && ansible-galaxy collection install -r requirements.yml
BOX$ printf '[nsa_servers]\ncloud1 ansible_connection=local\n' > inventory.ini
BOX$ sed -i 's/^nsa_expose:.*/nsa_expose: localhost/' group_vars/all.yml
BOX$ ansible-playbook site.yml --limit nsa_servers --check --diff | tail -30
BOX$ ansible-playbook site.yml --limit nsa_servers
```

## If something fails

Run these on the box and include the output (they contain no secrets; do **not** send `/etc/nsa/gateway.env`):

```bash
BOX$ tail -60 ~/nsa-install.log
BOX$ sudo journalctl -u nsa-gateway -u ollama --no-pager -n 80
BOX$ systemctl is-active ollama nsa-gateway; ss -ltnp | grep -E ':(4000|11434)'
BOX$ ollama list; df -h / | tail -1; free -h | head -2
WSL$ nsa doctor
```
