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

BACKEND_DIR="$(cd "$(dirname "$0")/.." && pwd)"
(cd "$BACKEND_DIR" && cargo run --quiet --manifest-path "$BACKEND_DIR/Cargo.toml") >"$TMP/server.log" 2>&1 &
PID=$!
ready=0
for _ in $(seq 1 60); do
  if curl -fsS "$BASE_URL/healthz" >"$TMP/health.json" 2>/dev/null; then ready=1; break; fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then cat "$TMP/server.log"; echo "API did not become ready" >&2; exit 1; fi

# Exact web-origin allowlisting is browser policy, not native-client authentication.
curl -fsS -D "$TMP/allowed-origin.headers" -H 'Origin: http://127.0.0.1:8080' "$BASE_URL/healthz" >/dev/null
grep -qi '^access-control-allow-origin: http://127.0.0.1:8080' "$TMP/allowed-origin.headers"
preflight_status="$(curl -sS -D "$TMP/preflight.headers" -o /dev/null -w '%{http_code}' -X OPTIONS -H 'Origin: http://127.0.0.1:8080' -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: content-type,x-chunk-sha256' "$BASE_URL/api/v1/auth/register")"
[[ "$preflight_status" == 200 || "$preflight_status" == 204 ]]
grep -qi '^access-control-allow-credentials: true' "$TMP/preflight.headers"
grep -qi '^access-control-allow-headers:.*content-type' "$TMP/preflight.headers"
grep -qi '^access-control-allow-headers:.*x-chunk-sha256' "$TMP/preflight.headers"
blocked_origin_status="$(curl -sS -o "$TMP/blocked-origin.json" -w '%{http_code}' -H 'Origin: https://not-allowlisted.example' "$BASE_URL/healthz")"
test "$blocked_origin_status" = 403
curl -fsS "$BASE_URL/healthz" >/dev/null
curl -fsS "$BASE_URL/api/v1/security/capabilities" >"$TMP/security-capabilities.json"
python3 - "$TMP/security-capabilities.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));assert x['messaging_enabled'] is True
assert x['shared_core']['status']=='partial' and x['shared_core']['android_native'] is False and x['shared_core']['ios_native'] is False
assert x['e2ee']['protocol']=='independent_device_bound_layer2_v2' and x['e2ee']['protocol_status']=='in_development_unreviewed'
assert x['e2ee']['device_key_registry']=='dual_public_key_source_implemented_unverified' and x['e2ee']['web_device_key_enrollment']=='web_android_ios_source_implemented_unverified'
assert x['e2ee']['client_encrypt_decrypt']=='web_android_ios_source_implemented_unverified' and x['e2ee']['message_delivery']=='enabled' and x['e2ee']['independent_review']=='not_started'
assert x['file_transfers']['web_client']=='source_implemented_unverified' and x['file_transfers']['native_clients']=='not_implemented'
assert 'permission_preflight' not in x['calls'] and x['calls']['quic_media_transport']=='not_implemented'
PY
unknown_resend_status="$(curl -sS -D "$TMP/resend-accepted.headers" -o "$TMP/resend-accepted.json" -w '%{http_code}' -H 'Content-Type: application/json' -d '{"identity":"unknown-account@example.test"}' "$BASE_URL/api/v1/auth/resend-verification")"
test "$unknown_resend_status" = 202
python3 - "$TMP/resend-accepted.json" "$TMP/resend-accepted.headers" <<'PY'
import json,sys
body=json.load(open(sys.argv[1]));headers=open(sys.argv[2]).read().lower()
assert body['retry_after_seconds']==60
assert 'retry-after: 60' in headers
assert body['message']=='If the account exists, a code may be sent.'
PY

python3 - "$TMP" "$SMOKE_EMAIL_A" "$SMOKE_EMAIL_B" <<'PY'
import json, pathlib, sys, uuid
p=pathlib.Path(sys.argv[1]); emails=sys.argv[2:4]
suffix=uuid.uuid4().hex[:8]
data={
  'a': {'username':f'testa{suffix}','email':emails[0],'display_name':'Test Account A','password':'Serein123','device_name':'Smoke browser A','device_id':str(uuid.uuid4())},
  'b': {'username':f'testb{suffix}','email':emails[1],'display_name':'Test Account B','password':'Test-password-67890','device_name':'Smoke browser B','device_id':str(uuid.uuid4())},
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
repeat_status="$(curl -sS -o "$TMP/a-register-repeat.json" -w '%{http_code}' -H 'Content-Type: application/json' -d "$(cat "$TMP/a.json")" "$BASE_URL/api/v1/auth/register")"
test "$repeat_status" = 202
python3 - "$TMP/a-register-repeat.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));assert x['verification']['required'] is True and x['verification']['email']
PY
unverified_status="$(curl -sS -o "$TMP/unverified-login.json" -w '%{http_code}' -H 'Content-Type: application/json' -d "$(python3 - "$TMP/a.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));print(json.dumps({'identity':x['email'],'password':x['password']}))
PY
)" "$BASE_URL/api/v1/auth/login")"
test "$unverified_status" = 403
python3 - "$TMP/unverified-login.json" "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["email"])' "$TMP/a.json")" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));assert x['verification']['required'] is True and x['verification']['email']==sys.argv[2]
PY
resend_status="$(curl -sS -D "$TMP/resend-cooldown.headers" -o "$TMP/resend-cooldown.json" -w '%{http_code}' -H 'Content-Type: application/json' -d "$(python3 - "$TMP/a.json" <<'PY'
import json,sys
print(json.dumps({'identity':json.load(open(sys.argv[1]))['email']}))
PY
)" "$BASE_URL/api/v1/auth/resend-verification")"
test "$resend_status" = 429
python3 - "$TMP/resend-cooldown.json" "$TMP/resend-cooldown.headers" <<'PY'
import json,sys
body=json.load(open(sys.argv[1]));headers=open(sys.argv[2]).read().lower()
assert 1<=body['retry_after_seconds']<=60
assert f"retry-after: {body['retry_after_seconds']}" in headers
PY
otp_for(){
  local who="$1" email="$2" value
  if [[ "$who" == "a" && -n "${OTP_A:-}" ]]; then value="$OTP_A"
  elif [[ "$who" == "b" && -n "${OTP_B:-}" ]]; then value="$OTP_B"
  else read -r -p "Enter the six-digit code received by ${email}: " value
  fi
  [[ "$value" =~ ^[0-9]{6}$ ]] || { echo "OTP must be six digits" >&2; return 1; }
  printf '%s' "$value"
}
otp_login_for(){
  local who="$1" email="$2" stage="$3" var="OTP_${who^^}_${stage}" value
  value="${!var:-}"
  if [[ -z "$value" ]]; then read -r -p "Enter the six-digit sign-in code received by ${email} (${stage}): " value; fi
  [[ "$value" =~ ^[0-9]{6}$ ]] || { echo "Sign-in OTP must be six digits" >&2; return 1; }
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
x=json.load(open(sys.argv[1]));print(json.dumps({'identity':x['email'],'password':x['password'],'code':sys.argv[2],'device_name':x['device_name'],'device_id':x['device_id']}))
PY
)"
  post_json "$TMP/$who.jar" /api/v1/auth/verify-email "$payload" >"$TMP/$who-verify.json"
done
python3 - "$TMP" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);a=json.loads((p/'a-verify.json').read_text());b=json.loads((p/'b-verify.json').read_text())
assert a['account']['user']['email_verified'] is True and a['verification']['verified'] is True and a['verification']['required'] is False
assert a['account']['device']['id']==(p/'a_device').read_text()
assert b['account']['user']['email_verified'] is True and b['verification']['verified'] is True and b['verification']['required'] is False
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
login_payload="$(python3 - "$TMP/a.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));print(json.dumps({'identity':x['email'],'password':x['password']}))
PY
)"
login_status="$(curl -sS -c "$A" -b "$A" -H 'Content-Type: application/json' -d "$login_payload" -o "$TMP/a-login-challenge.json" -w '%{http_code}' "$BASE_URL/api/v1/auth/login")"
test "$login_status" = 403
python3 - "$TMP/a-login-challenge.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));assert x['verification']['required'] is True and x['verification']['purpose']=='login' and 'account' not in x
PY
login_code="$(otp_login_for a "$SMOKE_EMAIL_A" LOGIN)"
wrong_login_code="$(python3 - "$login_code" <<'PY'
import sys
code=sys.argv[1];print(('0' if code[0]!='0' else '1')+code[1:])
PY
)"
wrong_login_payload="$(python3 - "$TMP/a.json" "$wrong_login_code" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));print(json.dumps({'identity':x['email'],'password':x['password'],'code':sys.argv[2],'device_name':x['device_name'],'device_id':x['device_id']}))
PY
)"
wrong_login_status="$(curl -sS -o "$TMP/a-login-wrong-code.json" -w '%{http_code}' -H 'Content-Type: application/json' -d "$wrong_login_payload" "$BASE_URL/api/v1/auth/verify-login")"
test "$wrong_login_status" = 400
login_verify="$(python3 - "$TMP/a.json" "$login_code" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));print(json.dumps({'identity':x['email'],'password':x['password'],'code':sys.argv[2],'device_name':x['device_name'],'device_id':x['device_id']}))
PY
)"
post_json "$A" /api/v1/auth/verify-login "$login_verify" >"$TMP/a-login.json"
python3 - "$TMP" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);x=json.loads((p/'a-login.json').read_text());assert x['account']['device']['id']==(p/'a_device').read_text();assert x['verification']['required'] is False and x['verification']['verified'] is True
PY
python3 - "$TMP" <<'PY'
import json,pathlib,sys,uuid
p=pathlib.Path(sys.argv[1]);x=json.load(open(p/'a.json'));x['device_id']=str(uuid.uuid4());(p/'a-second-device-login.json').write_text(json.dumps({'identity':x['username'],'password':x['password'],'device_name':'Second web device','device_id':x['device_id']}));(p/'a_second_device').write_text(x['device_id'])
PY
second_login_request="$(python3 - "$TMP/a-second-device-login.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));print(json.dumps({'identity':x['identity'],'password':x['password']}))
PY
)"
second_login_status="$(curl -sS -c "$A" -b "$A" -H 'Content-Type: application/json' -d "$second_login_request" -o "$TMP/a-second-device-challenge.json" -w '%{http_code}' "$BASE_URL/api/v1/auth/login")"
test "$second_login_status" = 403
second_login_code="$(otp_login_for a "$SMOKE_EMAIL_A" SECOND_LOGIN)"
second_login_payload="$(python3 - "$TMP/a.json" "$TMP/a-second-device-login.json" "$second_login_code" <<'PY'
import json,sys
account=json.load(open(sys.argv[1]));device=json.load(open(sys.argv[2]));print(json.dumps({'identity':account['email'],'password':account['password'],'code':sys.argv[3],'device_name':device['device_name'],'device_id':device['device_id']}))
PY
)"
post_json "$A" /api/v1/auth/verify-login "$second_login_payload" >/dev/null
get_json "$A" /api/v1/settings >"$TMP/settings-after-login.json"
get_json "$A" /api/v1/devices >"$TMP/devices.json"
python3 - "$TMP" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);settings=json.load(open(p/'settings-after-login.json'));devices=json.load(open(p/'devices.json'));ids={d['id'] for d in devices}
assert settings['theme']=='dark' and settings['font_scale']=='large' and settings['reduce_motion'] is True and settings['presence_visibility']=='nobody' and settings['allow_contact_requests'] is False and settings['discoverable_by_email'] is False
assert (p/'a_device').read_text() in ids and (p/'a_second_device').read_text() in ids
assert any(d['id']==(p/'a_second_device').read_text() and d['current'] for d in devices)
PY
python3 - "$TMP" <<'PY'
import base64,json,pathlib,sys
p=pathlib.Path(sys.argv[1])
def b64(h): return base64.urlsafe_b64encode(bytes.fromhex(h)).decode().rstrip('=')
# Public points for private scalars 1 and 2 on the standard NIST P-256 curve.
points=[('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296','4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'),('7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978','07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1')]
layer2_points=[('5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c','8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032'),('e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852','e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6')]
for name,(point,layer2_point) in zip(('key-a.json','key-b.json'),zip(points,layer2_points)):
    x,y=point; x2,y2=layer2_point
    jwk=lambda a,b:{'kty':'EC','crv':'P-256','x':b64(a),'y':b64(b)}
    (p/name).write_text(json.dumps({'algorithm':'ECDH-P256','public_key':jwk(x,y),'layer2_public_key':jwk(x2,y2)}))
PY
put_json "$A" /api/v1/device-key "$(cat "$TMP/key-a.json")" >"$TMP/key-a-result.json"
post_json "$B" /api/v1/device-key "$(cat "$TMP/key-b.json")" >"$TMP/key-b-result.json"
python3 - "$TMP" <<'PY'
import base64,hashlib,json,pathlib,re,sys
p=pathlib.Path(sys.argv[1])
for name,source in (('key-a-result.json','key-a.json'),('key-b-result.json','key-b.json')):
    x=json.load(open(p/name));bundle=json.load(open(p/source));assert x['registered'] is True and x['algorithm']=='ECDH-P256' and re.fullmatch(r'[0-9a-f]{64}',x['fingerprint'])
    coords=lambda jwk:base64.urlsafe_b64decode(jwk['x']+'==')+base64.urlsafe_b64decode(jwk['y']+'==')
    expected=hashlib.sha256(b'Serein ECDH P-256 device key bundle v2\0'+coords(bundle['public_key'])+coords(bundle['layer2_public_key'])).hexdigest()
    assert x['fingerprint']==expected
PY
key_change_status="$(curl -sS -o "$TMP/key-change.json" -w '%{http_code}' -c "$A" -b "$A" -H 'Content-Type: application/json' -X PUT -d "$(cat "$TMP/key-b.json")" "$BASE_URL/api/v1/device-key")"
test "$key_change_status" = 409
private_field_status="$(curl -sS -o "$TMP/private-key-rejected.json" -w '%{http_code}' -c "$A" -b "$A" -H 'Content-Type: application/json' -X PUT -d "$(python3 - "$TMP/key-a.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]));x['public_key']['d']='must-never-be-uploaded';print(json.dumps(x))
PY
)" "$BASE_URL/api/v1/device-key")"
test "$private_field_status" = 422
curl -fsS -c "$A" -b "$A" -X DELETE "$BASE_URL/api/v1/devices/$(cat "$TMP/a_device")" >/dev/null
get_json "$A" /api/v1/devices >"$TMP/devices-after-revoke.json"
python3 - "$TMP" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);ids={d['id'] for d in json.load(open(p/'devices-after-revoke.json'))}
assert (p/'a_device').read_text() not in ids and (p/'a_second_device').read_text() in ids
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
b_user_id="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["account"]["user"]["id"])' "$TMP/b-verify.json")"
get_json "$A" "/api/v1/contacts/$b_user_id/device-keys" >"$TMP/b-device-keys.json"
python3 - "$TMP/b-device-keys.json" "$TMP" <<'PY'
import json,pathlib,sys
result=json.load(open(sys.argv[1]));p=pathlib.Path(sys.argv[2]);rows=result['devices']
account=json.load(open(p/'b-verify.json'))['account']['user']
assert result['user_id']==account['id'] and result['username']==account['username']
assert any(row['device_id']==(p/'b_device').read_text() and row['fingerprint']==json.load(open(p/'key-b-result.json'))['fingerprint'] and row['key_version']==2 and row['layer2_public_key'] for row in rows)
assert all('d' not in row['public_key'] and row.get('layer2_public_key') is not None and 'd' not in row['layer2_public_key'] for row in rows)
PY
message_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
recipient_device="$(python3 - "$TMP/b-verify.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['account']['device']['id'])
PY
)"
post_json "$A" /api/v1/messages "$(python3 - "$message_id" "$recipient_device" <<'PY'
import json,sys
print(json.dumps({'id':sys.argv[1],'to':sys.argv[2],'crypto_version':2,'iv':'AAAAAAAAAAAAAAAA','ciphertext':'AAAAAAAAAAAAAAAAAAAAAA=='}))
PY
)" >"$TMP/message-accepted.json"
get_json "$B" /api/v1/messages?limit=10 >"$TMP/message-history.json"
python3 - "$TMP/message-accepted.json" "$TMP/message-history.json" "$message_id" <<'PY'
import json,sys
accepted=json.load(open(sys.argv[1]));history=json.load(open(sys.argv[2]));message_id=sys.argv[3]
assert accepted['id']==message_id and accepted['type']=='accepted'
item=next(row for row in history['items'] if row['id']==message_id)
payload=item['payload']
assert payload['type']=='message' and payload['id']==message_id and payload['crypto_version']==2
assert payload['iv']=='AAAAAAAAAAAAAAAA' and payload['ciphertext']=='AAAAAAAAAAAAAAAAAAAAAA=='
assert 'plaintext' not in payload
PY
ack_status="$(curl -sS -o "$TMP/ack.json" -w '%{http_code}' -c "$B" -b "$B" -H 'Content-Type: application/json' -d '{}' "$BASE_URL/api/v1/messages/$message_id/ack")"
test "$ack_status" = 200
python3 - "$TMP/ack.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['ok'] is True
PY

# Opaque file-transfer API transport smoke: create, upload, complete, list, download, and ACK.
transfer_id="$(python3 -c 'import uuid;print(uuid.uuid4())')"
post_json "$A" /api/v1/transfers "$(python3 - "$transfer_id" "$b_user_id" "$(cat "$TMP/a_second_device")" "$(cat "$TMP/b_device")" <<'PY'
import json,sys
print(json.dumps({'id':sys.argv[1],'recipient_user_id':sys.argv[2],'chunk_count':1,'total_ciphertext_bytes':16,'device_envelopes':[{'device_id':sys.argv[3],'iv':'AAAAAAAAAAAAAAAA','ciphertext':'AAAAAAAAAAAAAAAAAAAAAA=='},{'device_id':sys.argv[4],'iv':'AAAAAAAAAAAAAAAA','ciphertext':'AAAAAAAAAAAAAAAAAAAAAA=='}]}))
PY
)" >"$TMP/transfer-created.json"
printf '0123456789abcdef' >"$TMP/transfer-chunk.bin"
chunk_hash="$(sha256sum "$TMP/transfer-chunk.bin" | cut -d' ' -f1)"
curl -fsS -c "$A" -b "$A" -X PUT -H 'Content-Type: application/octet-stream' -H "X-Chunk-SHA256: $chunk_hash" --data-binary @"$TMP/transfer-chunk.bin" "$BASE_URL/api/v1/transfers/$transfer_id/chunks/0" >"$TMP/transfer-upload.json"
get_json "$B" /api/v1/transfers >"$TMP/transfer-list.json"
python3 - "$TMP/transfer-created.json" "$TMP/transfer-upload.json" "$TMP/transfer-list.json" "$transfer_id" <<'PY'
import json,sys
created=json.load(open(sys.argv[1]));uploaded=json.load(open(sys.argv[2]));items=json.load(open(sys.argv[3]));transfer=next(x for x in items if x['id']==sys.argv[4])
assert created['id']==sys.argv[4] and created['server_can_decrypt'] is False
assert uploaded['complete'] is True and uploaded['received_bytes']==16
assert transfer['ready_at'] and transfer['received_chunks']==1 and transfer['total_ciphertext_bytes']==16
assert 'manifest_ciphertext' in transfer and 'plaintext' not in transfer
PY
curl -fsS -D "$TMP/transfer-download.headers" -c "$B" -b "$B" -H 'Origin: http://127.0.0.1:8080' "$BASE_URL/api/v1/transfers/$transfer_id/chunks/0" -o "$TMP/transfer-downloaded.bin"
cmp "$TMP/transfer-chunk.bin" "$TMP/transfer-downloaded.bin"
grep -qi "^x-chunk-sha256: $chunk_hash" "$TMP/transfer-download.headers"
grep -qi '^access-control-expose-headers:.*x-chunk-sha256' "$TMP/transfer-download.headers"
post_json "$B" "/api/v1/transfers/$transfer_id/ack" '{}' >"$TMP/transfer-ack.json"
python3 - "$TMP/transfer-ack.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['ok'] is True
PY

# Block state is tested independently after encrypted-message delivery.
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
blocked_key_status="$(curl -sS -o "$TMP/blocked-key-directory.json" -w '%{http_code}' -c "$B" -b "$B" "$BASE_URL/api/v1/contacts/$a_user_id/device-keys")"
test "$blocked_key_status" = 404
curl -fsS -c "$B" -b "$B" -X DELETE "$BASE_URL/api/v1/blocks/$a_user_id" >/dev/null

echo "API smoke passed: account registration/verification/login, settings, contacts/privacy/blocks, public device-key registration/directory and key-change rejection, opaque message submit/history/ACK, and encrypted-transfer create/chunk/list/download/ACK transport behavior."
