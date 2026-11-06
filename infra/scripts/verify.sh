#!/usr/bin/env bash
# Smoke-test a running NSA gateway. Used by both the shell and the Ansible editions.
#   GATEWAY_URL    base URL without /v1          (default http://127.0.0.1:4000)
#   GATEWAY_KEY    API key; falls back to NSA_CLOUD_KEY, then /etc/nsa/gateway.env if readable
#   EXPECT_MODELS  space separated model names that must be listed (optional)
#   SKIP_COMPLETION=1  skip the tiny generation test
#   VERIFY_TIMEOUT     seconds to wait for that generation (default 900)
set -Eeuo pipefail

URL="${GATEWAY_URL:-http://127.0.0.1:4000}"; URL="${URL%/}"; URL="${URL%/v1}"
KEY="${GATEWAY_KEY:-${NSA_CLOUD_KEY:-}}"
if [[ -z "$KEY" && -r /etc/nsa/gateway.env ]]; then
  KEY="$(grep -m1 '^LITELLM_MASTER_KEY=' /etc/nsa/gateway.env | cut -d= -f2-)"
fi

fail=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
miss() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=1; }

command -v curl >/dev/null || { echo "curl is required"; exit 2; }
command -v jq   >/dev/null || { echo "jq is required"; exit 2; }
auth=(); [[ -n "$KEY" ]] && auth=(-H "Authorization: Bearer $KEY")

echo "Verifying gateway at $URL"

if curl -fsS -m 5 "$URL/health/liveliness" >/dev/null 2>&1; then pass "gateway is alive"
else miss "gateway not reachable at $URL (is the service running and bound to this address?)"; exit 1; fi

if [[ -z "$KEY" ]]; then miss "no API key available (set GATEWAY_KEY)"; exit 1; fi

# Unauthenticated and wrong-key requests must be refused. LiteLLM without a database rejects through error
# paths (500 / 400 no_db_connection) rather than a clean 401, so the test is "not served", not "is a 401".
for label in "no key" "wrong key"; do
  if [[ "$label" == "no key" ]]; then hdr=(); else hdr=(-H "Authorization: Bearer sk-definitely-wrong"); fi
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 ${hdr[@]+"${hdr[@]}"} "$URL/v1/models" || true)
  if [[ "$code" =~ ^2 ]]; then miss "$label: gateway answered $code and served data: authentication is NOT enforced"
  else pass "request with $label is rejected (HTTP $code)"; fi
done

models_json=$(curl -fsS -m 10 "${auth[@]}" "$URL/v1/models" 2>/dev/null || true)
if [[ -z "$models_json" ]]; then miss "could not list models with the key"; exit 1; fi
listed=$(jq -r '.data[].id' <<<"$models_json")
pass "authenticated /v1/models works ($(wc -l <<<"$listed" | tr -d ' ') models)"
for m in ${EXPECT_MODELS:-}; do
  if grep -qx "$m" <<<"$listed"; then pass "model served: $m"; else miss "model missing: $m"; fi
done

if [[ "${SKIP_COMPLETION:-0}" != 1 ]]; then
  first=$(head -1 <<<"${EXPECT_MODELS:-$listed}" | awk '{print $1}')
  echo "  ...generating a few tokens with $first (the first call loads the model: minutes on a small CPU box)"
  body=$(jq -n --arg m "$first" '{model:$m, messages:[{role:"user",content:"Reply with the single word OK."}], max_tokens:1500, stream:false}')
  start=$(date +%s)
  reply=$(curl -fsS -m "${VERIFY_TIMEOUT:-900}" "${auth[@]}" -H 'Content-Type: application/json' -d "$body" "$URL/v1/chat/completions" 2>/dev/null || true)
  text=$(jq -r '.choices[0].message.content // empty' 2>/dev/null <<<"$reply" || true)
  if [[ ${#text} -gt 300 ]]; then miss "the reply to a one-word request is ${#text} characters long: hidden reasoning is probably leaking into the answer (${text:0:60}...)"
  elif [[ -n "${text// /}" ]]; then pass "chat completion answered in $(( $(date +%s) - start ))s: \"${text:0:40}\""
  elif [[ -n "$reply" ]]; then miss "chat completion returned an EMPTY answer (finish_reason: $(jq -r '.choices[0].finish_reason // "?"' <<<"$reply"))"
  else miss "chat completion failed or timed out (raise VERIFY_TIMEOUT on slow boxes)"; fi
fi

if [[ $fail -eq 0 ]]; then echo "All checks passed."; else echo "Some checks failed."; fi
exit $fail
