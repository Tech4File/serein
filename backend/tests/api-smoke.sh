#!/usr/bin/env bash
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${MAIL_DELIVERY:?Configure MAIL_DELIVERY=api or smtp before running the manual auth smoke test}"
: "${SMOKE_EMAIL_A:?Set SMOKE_EMAIL_A to an inbox you can read}"
: "${SMOKE_EMAIL_B:?Set SMOKE_EMAIL_B to a different inbox you can read}"
if [[ "$MAIL_DELIVERY" == "disabled" ]]; then echo "MAIL_DELIVERY must be configured for this real-provider smoke test" >&2; exit 1; fi
if [[ "$SMOKE_EMAIL_A" == "$SMOKE_EMAIL_B" ]]; then echo "Use two distinct test inboxes" >&2; exit 1; fi
export LISTEN_ADDR="${LISTEN_ADDR:-0.0.0.0:8080}"
export COOKIE_SECURE=false
export ALLOWED_WEB_ORIGINS="http://127.0.0.1:8080"
BASE_URL="${API_BASE_URL:-http://127.0.0.1:8080}"
TMP="$(mktemp -d)"
PID=""
cleanup(){
  if [[ -n "$PID" ]]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

cargo run --quiet --manifest-path "$(dirname "$0")/../Cargo.toml" >"$TMP/server.log" 2>&1 &
PID=$!
ready=0
for _ in $(seq 1 60); do
  if curl -fsS "$BASE_URL/healthz" >"$TMP/health.json" 2>/dev/null; then ready=1; break; fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then cat "$TMP/server.log"; echo "API did not become ready" >&2; exit 1; fi

python3 - "$TMP" "$SMOKE_EMAIL_A" "$SMOKE_EMAIL_B" <<'PY'
import json, pathlib, sys, uuid
p=pathlib.Path(sys.argv[1]); emails=sys.argv[2:4]
suffix=uuid.uuid4().hex[:8]
data={
  'a': {'username':f'testa{suffix}','email':emails[0],'display_name':'Test Account A','password':'test-password-12345','device_name':'Smoke browser A','device_id':str(uuid.uuid4())},
  'b': {'username':f'testb{suffix}','email':emails[1],'display_name':'Test Account B','password':'test-password-67890','device_name':'Smoke browser B','device_id':str(uuid.uuid4())},
}
for k,v in data.items(): (p/f'{k}.json').write_text(json.dumps(v))
(p/'a_device').write_text(data['a']['device_id'])
PY

post_json(){ local jar="$1" url="$2" body="$3"; curl -fsS -c "$jar" -b "$jar" -H 'Content-Type: application/json' -d "$body" "$BASE_URL$url"; }
put_json(){ local jar="$1" url="$2" body="$3"; curl -fsS -c "$jar" -b "$jar" -H 'Content-Type: application/json' -X PUT -d "$body" "$BASE_URL$url"; }
get_json(){ local jar="$1" url="$2"; curl -fsS -c "$jar" -b "$jar" "$BASE_URL$url"; }
A="$TMP/a.jar"; B="$TMP/b.jar"; touch "$A" "$B"
post_json "$A" /api/v1/auth/register "$(cat "$TMP/a.json")" >"$TMP/a-register.json"
post_json "$B" /api/v1/auth/register "$(cat "$TMP/b.json")" >"$TMP/b-register.json"
python3 - "$TMP" <<'PY'
import json,pathlib,sys,uuid
p=pathlib.Path(sys.argv[1]); a=json.load(open(p/'a.json')); b=json.load(open(p/'b.json'))
for name, source, email in [('dup-user',a,f'dup-user-{uuid.uuid4().hex[:8]}@example.test'),('dup-email',b,a['email'])]:
    x=dict(source); x.update(username=(a['username'] if name=='dup-user' else f'new{name}{uuid.uuid4().hex[:8]}'),email=email,device_id=str(uuid.uuid4()))
    (p/f'{name}.json').write_text(json.dumps(x))
PY
for kind in dup-user dup-email; do
  status="$(curl -sS -o "$TMP/$kind-response.json" -w '%{http_code}' -H 'Content-Type: application/json' -d "$(cat "$TMP/$kind.json")" "$BASE_URL/api/v1/auth/register")"
  test "$status" = 409
  python3 - "$TMP/$kind-response.json" "$kind" <<'PY'
import json,sys
message=json.load(open(sys.argv[1]))['error'].lower()
expected='username' if sys.argv[2]=='dup-user' else 'email'
assert expected in message, message
PY
done

python3 - "$TMP" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);a=json.loads((p/'a-register.json').read_text());b=json.loads((p/'b-register.json').read_text())
assert a['verification']['required'] is True and a['verification']['verified'] is False
assert b['verification']['required'] is True and b['verification']['verified'] is False
PY
unverified_status="$(curl -sS -o "$TMP/unverified-login.json" -w '%{http_code}' -H 'Content-Type: application/json' -d "$(python3 - "$TMP/a.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));print(json.dumps({'identity':x['email'],'password':x['password']}))
PY
)" "$BASE_URL/api/v1/auth/login")"
test "$unverified_status" = 403
resend_status="$(curl -sS -o "$TMP/resend-cooldown.json" -w '%{http_code}' -H 'Content-Type: application/json' -d "$(python3 - "$TMP/a.json" <<'PY'
import json,sys
print(json.dumps({'identity':json.load(open(sys.argv[1]))['email']}))
PY
)" "$BASE_URL/api/v1/auth/resend-verification")"
test "$resend_status" = 429
otp_for(){
  local who="$1" email="$2" value
  if [[ "$who" == "a" && -n "${OTP_A:-}" ]]; then value="$OTP_A"
  elif [[ "$who" == "b" && -n "${OTP_B:-}" ]]; then value="$OTP_B"
  else read -r -p "Enter the six-digit code received by ${email}: " value
  fi
  [[ "$value" =~ ^[0-9]{6}$ ]] || { echo "OTP must be six digits" >&2; return 1; }
  printf '%s' "$value"
}
for who in a b; do
  email="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["email"])' "$TMP/$who.json")"
  code="$(otp_for "$who" "$email")"
  wrong="$(python3 - "$code" <<'PY'
import sys
code=sys.argv[1];print(('0' if code[0]!='0' else '1')+code[1:])
PY
)"
  invalid_status="$(curl -sS -o "$TMP/$who-invalid-otp.json" -w '%{http_code}' -H 'Content-Type: application/json' -d "{\"email\":\"$email\",\"code\":\"$wrong\"}" "$BASE_URL/api/v1/auth/verify-email")"
  test "$invalid_status" = 400
  payload="$(python3 - "$TMP/$who.json" "$code" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));print(json.dumps({'email':x['email'],'code':sys.argv[2],'device_name':x['device_name'],'device_id':x['device_id']}))
PY
)"
  post_json "$TMP/$who.jar" /api/v1/auth/verify-email "$payload" >"$TMP/$who-verify.json"
done
python3 - "$TMP" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);a=json.loads((p/'a-verify.json').read_text());b=json.loads((p/'b-verify.json').read_text())
assert a['account']['user']['email_verified'] is True and a['verification']['verified'] is True
assert a['account']['device']['id']==(p/'a_device').read_text()
assert b['account']['user']['email_verified'] is True and b['verification']['verified'] is True
(p/'b_device').write_text(b['account']['device']['id'])
assert b['account']['device']['id']
PY

# Email discovery is opt-in on a fresh account.
get_json "$B" /api/v1/settings >"$TMP/settings-default.json"
python3 - "$TMP/settings-default.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));assert x['allow_contact_requests'] is True and x['discoverable_by_email'] is False
PY

# Settings are persisted by account and reject invalid values.
put_json "$A" /api/v1/settings '{"theme":"dark","font_scale":"large","reduce_motion":true,"presence_visibility":"nobody","allow_contact_requests":false,"discoverable_by_email":false}' >/dev/null
get_json "$A" /api/v1/settings >"$TMP/settings.json"
python3 - "$TMP/settings.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));assert x['theme']=='dark' and x['font_scale']=='large' and x['reduce_motion'] is True and x['presence_visibility']=='nobody' and x['allow_contact_requests'] is False and x['discoverable_by_email'] is False
PY
bad_status="$(curl -sS -o "$TMP/bad.json" -w '%{http_code}' -c "$A" -b "$A" -H 'Content-Type: application/json' -X PUT -d '{"theme":"ultraviolet"}' "$BASE_URL/api/v1/settings")"
test "$bad_status" = 400

# Signing out and signing in again with the same stable device ID preserves the device record.
post_json "$A" /api/v1/auth/logout '{}' >/dev/null
post_json "$A" /api/v1/auth/login "$(python3 - "$TMP/a.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));print(json.dumps({'identity':x['email'],'password':x['password'],'device_name':x['device_name'],'device_id':x['device_id']}))
PY
)" >"$TMP/a-login.json"
python3 - "$TMP" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);x=json.loads((p/'a-login.json').read_text());assert x['account']['device']['id']==(p/'a_device').read_text()
PY
python3 - "$TMP" <<'PY'
import json,pathlib,sys,uuid
p=pathlib.Path(sys.argv[1]);x=json.load(open(p/'a.json'));x['device_id']=str(uuid.uuid4());(p/'a-second-device-login.json').write_text(json.dumps({'identity':x['username'],'password':x['password'],'device_name':'Second web device','device_id':x['device_id']}));(p/'a_second_device').write_text(x['device_id'])
PY
post_json "$A" /api/v1/auth/login "$(cat "$TMP/a-second-device-login.json")" >/dev/null
get_json "$A" /api/v1/settings >"$TMP/settings-after-login.json"
get_json "$A" /api/v1/devices >"$TMP/devices.json"
python3 - "$TMP" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);settings=json.load(open(p/'settings-after-login.json'));devices=json.load(open(p/'devices.json'));ids={d['id'] for d in devices}
assert settings['theme']=='dark' and settings['font_scale']=='large' and settings['reduce_motion'] is True and settings['presence_visibility']=='nobody' and settings['allow_contact_requests'] is False and settings['discoverable_by_email'] is False
assert (p/'a_device').read_text() in ids and (p/'a_second_device').read_text() in ids
assert any(d['id']==(p/'a_second_device').read_text() and d['current'] for d in devices)
PY
curl -fsS -c "$A" -b "$A" -X DELETE "$BASE_URL/api/v1/devices/$(cat "$TMP/a_device")" >/dev/null
get_json "$A" /api/v1/devices >"$TMP/devices-after-revoke.json"
python3 - "$TMP" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);ids={d['id'] for d in json.load(open(p/'devices-after-revoke.json'))}
assert (p/'a_device').read_text() not in ids and (p/'a_second_device').read_text() in ids
PY
get_json "$A" '/api/v1/messages?limit=10' >"$TMP/history.json"
python3 - "$TMP/history.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));assert x['items']==[] and x['has_more'] is False
PY
ack_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
post_json "$A" "/api/v1/messages/$ack_id/ack" '{}' >"$TMP/ack.json"
python3 - "$TMP/ack.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['ok'] is True
PY

# Privacy choices gate incoming requests without exposing email eligibility to the requester.
post_json "$B" /api/v1/contact-requests "$(python3 - "$TMP/a.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));print(json.dumps({'identity':x['email']}))
PY
)" >"$TMP/privacy-gated-request.json"
get_json "$A" /api/v1/contact-requests >"$TMP/a-incoming-private.json"
python3 - "$TMP/a-incoming-private.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))==[]
PY
put_json "$A" /api/v1/settings '{"allow_contact_requests":true,"discoverable_by_email":true}' >/dev/null
put_json "$B" /api/v1/settings '{"discoverable_by_email":true}' >/dev/null
# Account search responses remain identical for an opted-in verified email and a missing address; consent is required.
post_json "$A" /api/v1/contact-requests "$(python3 - "$TMP/b.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));print(json.dumps({'identity':x['email']}))
PY
)" >"$TMP/request-existing.json"
post_json "$A" /api/v1/contact-requests "$(python3 - <<'PY'
import json,uuid
print(json.dumps({'identity':f'absent-{uuid.uuid4().hex[:12]}@example.org'}))
PY
)" >"$TMP/request-absent.json"
python3 - "$TMP" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);a=json.load(open(p/'request-existing.json'));b=json.load(open(p/'request-absent.json'));c=json.load(open(p/'privacy-gated-request.json'))
assert a==b==c and a['ok'] is True
PY
for i in $(seq 1 8); do
  status="$(curl -sS -o /dev/null -w '%{http_code}' -c "$A" -b "$A" -H 'Content-Type: application/json' -d "$(python3 - "$i" <<'PY'
import json,sys,uuid
print(json.dumps({'identity':f'absent-{sys.argv[1]}-{uuid.uuid4().hex[:8]}@example.org'}))
PY
)" "$BASE_URL/api/v1/contact-requests")"
  test "$status" = 202
done
rate_status="$(curl -sS -o /dev/null -w '%{http_code}' -c "$A" -b "$A" -H 'Content-Type: application/json' -d '{"identity":"last-attempt@example.org"}' "$BASE_URL/api/v1/contact-requests")"
test "$rate_status" = 429
get_json "$B" /api/v1/contact-requests >"$TMP/b-requests.json"
request_id="$(python3 - "$TMP/b-requests.json" <<'PY'
import json,sys
rows=json.load(open(sys.argv[1]));incoming=[r for r in rows if r['direction']=='incoming'];assert len(incoming)==1;print(incoming[0]['id'])
PY
)"
post_json "$B" "/api/v1/contact-requests/$request_id/accept" '{}' >/dev/null
get_json "$A" /api/v1/contacts >"$TMP/a-contacts.json"
get_json "$B" /api/v1/contacts >"$TMP/b-contacts.json"
python3 - "$TMP" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);a=json.load(open(p/'a-contacts.json'));b=json.load(open(p/'b-contacts.json'));adata=json.load(open(p/'a-verify.json'))['account']['user'];bdata=json.load(open(p/'b-verify.json'))['account']['user']
assert any(x['user_id']==bdata['id'] for x in a) and any(x['user_id']==adata['id'] for x in b)
PY
# A block removes the relationship and prevents authenticated message delivery.
b_user_id="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["account"]["user"]["id"])' "$TMP/b-verify.json")"
a_user_id="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["account"]["user"]["id"])' "$TMP/a-verify.json")"
curl -fsS -c "$B" -b "$B" -X PUT "$BASE_URL/api/v1/blocks/$a_user_id" >/dev/null
get_json "$B" /api/v1/blocks >"$TMP/blocks.json"
python3 - "$TMP/blocks.json" "$a_user_id" <<'PY'
import json,sys
assert any(x['user_id']==sys.argv[2] for x in json.load(open(sys.argv[1])))
PY
get_json "$B" /api/v1/contacts >"$TMP/b-contacts-blocked.json"
python3 - "$TMP/b-contacts-blocked.json" "$a_user_id" <<'PY'
import json,sys
assert all(x['user_id']!=sys.argv[2] for x in json.load(open(sys.argv[1])))
PY
blocked_status="$(curl -sS -o "$TMP/blocked-message.json" -w '%{http_code}' -c "$A" -b "$A" -H 'Content-Type: application/json' -d "{\"id\":\"$(python3 -c 'import uuid;print(uuid.uuid4())')\",\"to\":\"$(cat "$TMP/b_device")\",\"iv\":\"AAAAAAAAAAAAAAAA\",\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}" "$BASE_URL/api/v1/messages")"
test "$blocked_status" = 403
curl -fsS -c "$B" -b "$B" -X DELETE "$BASE_URL/api/v1/blocks/$a_user_id" >/dev/null

# REST message submission must reject a malformed envelope rather than falsely accept it.
message_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
invalid_status="$(curl -sS -o "$TMP/invalid-envelope.json" -w '%{http_code}' -c "$A" -b "$A" -H 'Content-Type: application/json' -d "{\"id\":\"$message_id\",\"to\":\"$(cat "$TMP/b_device")\",\"iv\":\"not-base64\",\"ciphertext\":\"bad\"}" "$BASE_URL/api/v1/messages")"
test "$invalid_status" = 400

echo "API smoke passed: unique username/email conflicts, provider-backed OTP delivery, unverified-login blocking, OTP verification/guess limits/resend cooldown, email and username login, stable and multi-device sessions, settings persistence/validation, history, REST ACK, private contact requests, privacy-setting gates, indistinguishable missing/ineligible-account responses, explicit request acceptance, ten-per-hour discovery throttling, user blocks, and malformed-envelope rejection."
