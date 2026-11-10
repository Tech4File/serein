const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const web = read('frontend/web/app.js');
const backend = read('backend/src/main.rs');
const android = read('apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java');
const androidMain = read('apps/android/app/src/main/java/io/serein/chat/MainActivity.java');
const iosView = read('apps/ios/SereinChat/SereinProductView.swift');
const iosApi = read('apps/ios/SereinChat/SereinAPI.swift');
const experienceCss = read('frontend/web/experience.css');

test('web inserts a bubble and metadata for every ordinary timeline row before attaching the row', () => {
  const render = web.slice(web.indexOf('function renderSelectedConversation('), web.indexOf('function rememberMessage('));
  const paint = web.slice(web.indexOf('function paintMessage('), web.indexOf('function rememberMessage('));
  assert.match(render, /if\(item\.system\)paintSystemEvent\(item\.text,item\.createdAt\);else paintMessage\(item/);
  const remember = web.slice(web.indexOf('function rememberMessage('), web.indexOf('function safeAttachmentName('));
  const send = web.slice(web.indexOf('async function sendMessage('), web.indexOf('async function encryptAndUploadAttachment('));
  const receive = web.slice(web.indexOf('async function processPacket('), web.indexOf('async function handlePacket('));
  assert.match(remember, /paintMessage\(item\)/);
  assert.match(send, /rememberMessage\(contact,text,true/);
  assert.match(receive, /rememberMessage\(contact,content\.text,false/);
  assert.match(paint, /bubble\.className='bubble'/);
  assert.match(paint, /const meta=document\.createElement\('small'\);meta\.className='bubble-meta'/);
  assert.match(paint, /bubble\.append\(meta\)/);
  assert.match(paint, /row\.append\(bubble\)/);
  assert.ok(paint.indexOf('bubble.append(meta)') < paint.indexOf('row.append(bubble)'), 'message content and metadata must be attached to the row');
  assert.ok(paint.indexOf('row.append(bubble)') < paint.indexOf('el.messageList.append(row)'), 'the complete bubble row must be attached before it is published');
  assert.match(paint, /if\(!item\.mine\)row\.append\(avatar\(item\.sender,'sm','message-avatar'\)\)/);
});

test('Android and iOS render message body, bubble surface, and timestamp/delivery state independently of Web', () => {
  const androidRender = android.slice(android.indexOf('private void renderMessage(JSONObject row)'), android.indexOf('private String deliverySummary('));
  assert.match(androidRender, /SereinUi\.chatBubble\(this,mine\)/);
  assert.match(androidRender, /TextView body=SereinUi\.text\(this,row\.optString\("text"\)/);
  assert.match(androidRender, /bubble\.addView\(meta\)/);
  assert.match(androidRender, /line\.addView\(bubble,bubbleParams\)/);
  const iosTimeline = iosView.slice(iosView.indexOf('private var timeline:'), iosView.indexOf('private func deliverySummary('));
  assert.match(iosTimeline, /engine\.messages\.map/);
  const iosRender = iosView.slice(iosView.indexOf('if let message=item\.message'), iosView.indexOf('}.onChange\(of: engine\.messages\.count\)'));
  assert.match(iosRender, /Text\(message\.text\)/);
  assert.match(iosRender, /Text\(message\.mine \? deliverySummary\(message\) :/);
  assert.match(iosRender, /\.background\(message\.mine \? outgoingBubble : incomingBubble/);
});

test('web refreshes keys and composer readiness when the selected contact gains or loses devices', () => {
  assert.match(web, /function sameContactDeviceSet\(left,right\)/);
  assert.match(web, /deviceSetChanged=!!next&&!sameContactDeviceSet\(old,next\)/);
  assert.match(web, /if\(deviceSetChanged&&!next\.deleted&&!next\.historyOnly\)refreshSelectedPeerKeys\(next\)/);
  const refresh = web.slice(web.indexOf('async function refreshSelectedPeerKeys('), web.indexOf('async function refreshContacts('));
  assert.match(refresh, /for\(const key of state\.conversationKeys\.keys\(\)\)if\(key\.startsWith\(`\$\{contact\.id\}:`\)\)state\.conversationKeys\.delete\(key\)/);
  assert.match(refresh, /deriveCandidateConversationKeys\(contact\)/);
  assert.match(refresh, /renderPeerKeyControls\(contact,result\.devices,result\.missingDevices\)/);
  assert.match(refresh, /setConnected\(\)/);
});

test('emoji and GIF picker remains centered inside the conversation at desktop and mobile widths', () => {
  const finalRules = experienceCss.slice(experienceCss.lastIndexOf('/* Preserve the established conversation-centered modal'));
  assert.match(finalRules, /\.emoji-picker \{ top: 50%; left: 50%; right: auto; bottom: auto;[\s\S]*?transform: translate\(-50%, -50%\); \}/);
  assert.match(finalRules, /@media \(max-width: 680px\) \{\s*\.emoji-picker \{ top: 50%; left: 50%; right: auto; bottom: auto;/);
  assert.match(finalRules, /@media \(max-width: 370px\) \{\s*\.emoji-picker \{ top: 50%; left: 50%; right: auto; bottom: auto;/);
  assert.doesNotMatch(finalRules, /\.emoji-picker \{ left: max\(8px, calc\(\(100% - 900px\) \/ 2\)\)/);
});

test('native clients refresh selected-contact keys on their own foreground cadence', () => {
  const androidEngine = read('apps/android/app/src/main/java/io/serein/chat/SereinChatEngine.java');
  const androidActivity = read('apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java');
  const iosEngine = read('apps/ios/SereinChat/SereinChatEngine.swift');
  const iosUi = read('apps/ios/SereinChat/SereinProductView.swift');
  assert.match(androidActivity, /pollCounter%12==0\)engine\.refreshPeers\(\)/);
  assert.match(androidEngine, /contact\.put\("devices",latest\.optJSONArray\("devices"\)/);
  assert.match(androidEngine, /synchronized\(this\)\{peers\.clear\(\);peers\.putAll\(next\);\}status=peerStatus\(\);notifyUi\(\)/);
  assert.match(iosUi, /cycles % 12 == 0 \{ try\? await engine\.refreshPeerKeys\(\) \}/);
  assert.match(iosEngine, /activeDevices = latestDevices\s*peerKeys = next\s*status = peerStatus/);
});

test('Online now is based on visible, recent WebSocket presence and not on device-session listing', () => {
  const contactHandler = backend.slice(backend.indexOf('async fn list_contacts('), backend.indexOf('async fn get_settings('));
  const devicesHandler = backend.slice(backend.indexOf('async fn list_devices('), backend.indexOf('async fn revoke_device('));
  assert.match(contactHandler, /contact\.online\|=presence_visible&&recently_active\.unwrap_or\(false\)&&state\.peers\.contains_key\(&device_id\)/);
  assert.match(devicesHandler, /online:recently_active&&state\.peers\.contains_key\(&id\)/);
  assert.match(web, /async function refreshContacts\(\)[\s\S]*?api\('\/api\/v1\/contacts'\)/);
  assert.match(iosApi, /func refreshContactPresence\(\) async[\s\S]*?request\("\/api\/v1\/contacts"\)/);
  assert.match(android, /private void refreshContactPresence\(\)[\s\S]*?api\.contacts\(/);
});

test('device-session SQL safely maps a missing designated main to false and logs SQLx details server-side', () => {
  const handler = backend.slice(backend.indexOf('async fn list_devices('), backend.indexOf('async fn revoke_device('));
  assert.match(handler, /query_as::<_,\(Uuid,String,String,String,String,bool,bool,bool\)>/);
  assert.match(handler, /COALESCE\(d\.id=a\.main_device_id,FALSE\)/);
  assert.match(handler, /Err\(error\)=>\{warn!\(error=%error,"device session query failed"\)/);
  assert.match(handler, /api_error\(StatusCode::SERVICE_UNAVAILABLE,"device sessions unavailable"\)/);
  assert.match(read('backend/migrations/0020_main_device_history_sync.sql'), /main_device_id UUID NULL/);
});

test('Web and Android keep device-list errors in the device-management UI without unhandled rejection', () => {
  assert.match(web, /if\(section==='devices'\)refreshDevices\(\)\.catch\(\(\)=>\{\}\)/);
  assert.match(web, /catch\(error\)\{if\(list\)list\.textContent=error\.message;throw error;\}/);
  const deviceLoader = androidMain.slice(androidMain.indexOf('private void loadSignedInDevices('), androidMain.indexOf('private void showDeleteAccountDialog('));
  assert.match(deviceLoader, /Signed-in device sessions are unavailable:/);
  assert.match(deviceLoader, /Presence and messaging status are separate/);
  assert.match(deviceLoader, /Button retry=SereinUi\.button\(this,"Retry device list"/);
  assert.match(deviceLoader, /retry\.setOnClickListener\(v->loadSignedInDevices\(deviceCard\)\)/);
});

test('iOS device-list failure is isolated from contacts/settings and offers its own retry', () => {
  const refresh = iosApi.slice(iosApi.indexOf('func refreshAccountData() async'), iosApi.indexOf('func contactsData()'));
  assert.match(refresh, /async let contactsResponse = refreshResponse\("\/api\/v1\/contacts"\)/);
  assert.match(refresh, /async let devicesResponse = refreshResponse\("\/api\/v1\/devices"\)/);
  assert.match(refresh, /if let data = c\.data[\s\S]*?if let data = d\.data/);
  assert.match(refresh, /deviceSessionsError = "Signed-in device sessions are unavailable:/);
  assert.doesNotMatch(refresh, /let \(c, r, b, d, s\) = try await/);
  assert.match(iosView, /if let error = api\.deviceSessionsError[\s\S]*?Button\("Retry device list"\) \{ Task \{ await api\.refreshDeviceSessions\(\) \} \}/);
});
