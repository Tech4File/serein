(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const DEFAULT_API_BASE = String(window.SEREIN_CONFIG?.apiBase || location.origin).replace(/\/$/, '');
  const APP_VERSION = String(window.SEREIN_CONFIG?.version || 'unknown');
  const MESSAGING_ENABLED = true;
  const messageLimits = window.SereinMessageLimits;
  if (!messageLimits) throw new Error('Serein message-limit policy did not load.');
  const el = {
    login:$('login'), app:$('app'), authForm:$('authForm'),
    contactDialog:$('contactDialog'), contactForm:$('contactForm'), contactUsername:$('contactUsername'),
    contactList:$('contactList'), messageList:$('messageList'), messageInput:$('messageInput'),
    sendButton:$('sendButton'), toast:$('toast'),
  };
  const enc = new TextEncoder(), dec = new TextDecoder();
  const state = { socket:null, user:null, device:null, name:'', identity:'', relay:'', contacts:[], devices:[], contactRequests:[], blocks:[], selected:null, authMode:'signin', filter:'all', messages:{}, verificationEmail:'', verificationBusy:false, resendUntil:0, resendTimer:0, connectionCheckOrigin:'', connectionReachable:false, connectionStatus:'Not checked', toastTimer:0, localDb:null, localKey:null, deviceKeyPair:null, deviceKeyFingerprint:'', peerKeyState:'', conversationKeys:new Map(), drafts:{}, seenIds:new Set(), pendingSends:new Map(), processingIds:new Set(), heartbeatTimer:0, reconnectTimer:0, reconnectAttempt:0, signingOut:false, settings:{theme:'system',font_scale:'system',reduce_motion:false,notifications:false,presence_visibility:'contacts',allow_contact_requests:true,discoverable_by_email:false}, syncingSettings:false };
  const MAX_TRANSFER_CHUNK_BYTES=256*1024, TRANSFER_CHUNK_PLAINTEXT=MAX_TRANSFER_CHUNK_BYTES-16, MAX_TRANSFER_CHUNKS=512, MAX_TRANSFER_CIPHERTEXT_BYTES=64*1024*1024;
  const THEME_KEY='serein.theme.v1';
  const b64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));
  const fromB64 = (value) => Uint8Array.from(atob(value), ch => ch.charCodeAt(0));
  const clean = (value, max=120) => String(value||'').trim().slice(0,max);
  const validLabel = (value, max) => max===32&&window.SereinCore?window.SereinCore.validUsername(value):new RegExp(`^[A-Za-z0-9_.-]{1,${max}}$`).test(value);
  const palette=['#3c7767','#59689a','#936177','#4b7396','#8b754d','#557d72'];
  function colorFor(value=''){let n=0;for(const c of value)n=(n*31+c.charCodeAt(0))>>>0;return palette[n%palette.length];}
  function toast(message){el.toast.textContent=message;el.toast.classList.add('show');clearTimeout(state.toastTimer);state.toastTimer=setTimeout(()=>el.toast.classList.remove('show'),3200);}
  function persistSettings(patch){Object.assign(state.settings,patch);try{localStorage.setItem(THEME_KEY,state.settings.theme);}catch{}if(state.user&&!state.syncingSettings)api('/api/v1/settings',{method:'PUT',body:JSON.stringify(patch)}).catch(error=>toast(`Settings are saved on this device; server sync failed: ${error.message}`));}
  function setTheme(theme){document.documentElement.dataset.theme=theme;try{localStorage.setItem(THEME_KEY,theme);}catch{}state.settings.theme=theme;const auth=$('authTheme');if(auth)auth.value=theme;document.querySelectorAll('[data-theme-choice]').forEach(b=>b.classList.toggle('selected',b.dataset.themeChoice===theme));if(state.user&&!state.syncingSettings)persistSettings({theme});}
  function setPrivacySwitch(id,value){const button=$(id);if(!button)return;button.classList.toggle('on',!!value);button.setAttribute('aria-pressed',String(!!value));}
  async function loadAccountSettings(){if(!state.user)return;try{const remote=await api('/api/v1/settings');state.syncingSettings=true;state.settings={theme:['system','light','dark'].includes(remote.theme)?remote.theme:'system',font_scale:['system','standard','large','extra_large'].includes(remote.font_scale)?(remote.font_scale==='standard'?'system':remote.font_scale):'system',reduce_motion:!!remote.reduce_motion,notifications:!!remote.notifications,presence_visibility:['contacts','nobody'].includes(remote.presence_visibility)?remote.presence_visibility:'contacts',allow_contact_requests:remote.allow_contact_requests!==false,discoverable_by_email:remote.discoverable_by_email!==false};setTheme(state.settings.theme);document.documentElement.dataset.fontScale=state.settings.font_scale;document.documentElement.classList.toggle('reduce-motion',state.settings.reduce_motion);$('fontScale').value=state.settings.font_scale;$('motionToggle').classList.toggle('on',state.settings.reduce_motion);$('notificationToggle').classList.toggle('on',state.settings.notifications);$('presenceVisibility').value=state.settings.presence_visibility;setPrivacySwitch('allowContactRequests',state.settings.allow_contact_requests);setPrivacySwitch('discoverableByEmail',state.settings.discoverable_by_email);state.syncingSettings=false;}catch(error){state.syncingSettings=false;console.warn('Account settings unavailable',error);}}
  function loadTheme(){const saved=localStorage.getItem(THEME_KEY)||'system';setTheme(['system','light','dark'].includes(saved)?saved:'system');}
  function initials(value){return clean(value,48).split(/\s+/).filter(Boolean).slice(0,2).map(x=>x[0].toUpperCase()).join('')||'?';}
  function avatar(label,size='md',className=''){const node=document.createElement('serein-avatar');node.className=className;node.setAttribute('label',label);node.setAttribute('size',size);node.setAttribute('tone',colorFor(label));return node;}
  function metaKey(){return `serein.contact-meta.${state.user?.id||'none'}`;}
  function contactMeta(){try{const key=metaKey(),stored=JSON.parse(localStorage.getItem(key)||'{}'),safe={};for(const [id,value] of Object.entries(stored)){safe[id]={favorite:!!value?.favorite,unread:Number(value?.unread)||0};}localStorage.setItem(key,JSON.stringify(safe));return safe;}catch{return {};}}
  function saveContacts(){const meta={};for(const c of state.contacts)meta[c.user_id]={favorite:!!c.favorite,unread:c.unread||0};localStorage.setItem(metaKey(),JSON.stringify(meta));renderContacts($('search').value);}
  function persistentDeviceId(){
    const key='serein.stable-device-id.v1';let id='';try{id=localStorage.getItem(key)||'';}catch{}
    if(!/^[0-9a-f-]{36}$/i.test(id)){id=crypto.randomUUID();try{localStorage.setItem(key,id);}catch{throw new Error('This browser cannot persist a stable device identity.');}}
    return id;
  }
  function idbRequest(request){return new Promise((resolve,reject)=>{request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error||new Error('Local database request failed'));});}
  function idbDone(transaction){return new Promise((resolve,reject)=>{transaction.oncomplete=()=>resolve();transaction.onabort=transaction.onerror=()=>reject(transaction.error||new Error('Local database transaction failed'));});}
  async function initializeLocalStore(){
    if(!('indexedDB'in window)||!crypto?.subtle)throw new Error('Encrypted local storage requires IndexedDB and Web Crypto in a secure browser context.');
    if(!state.localDb){state.localDb=await new Promise((resolve,reject)=>{const request=indexedDB.open('serein-local-v1',1);request.onupgradeneeded=()=>{const db=request.result;if(!db.objectStoreNames.contains('keys'))db.createObjectStore('keys',{keyPath:'key'});if(!db.objectStoreNames.contains('messages')){const store=db.createObjectStore('messages',{keyPath:'key'});store.createIndex('accountKey','accountKey');store.createIndex('conversationKey','conversationKey');}if(!db.objectStoreNames.contains('meta'))db.createObjectStore('meta',{keyPath:'key'});};request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error||new Error('Cannot open encrypted local database'));request.onblocked=()=>reject(new Error('Close older Serein tabs to upgrade local storage'));});}
    const keyId=state.user.id;const readTx=state.localDb.transaction('keys','readonly');const row=await idbRequest(readTx.objectStore('keys').get(keyId));await idbDone(readTx);
    if(row?.cryptoKey){state.localKey=row.cryptoKey;return;}
    const cryptoKey=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);const writeTx=state.localDb.transaction('keys','readwrite');writeTx.objectStore('keys').put({key:keyId,cryptoKey});await idbDone(writeTx);state.localKey=cryptoKey;
  }
  async function ensureDeviceKeyEnrollment(){
    if(!state.localDb||!state.user||!state.device)throw new Error('Device-local secure storage is unavailable.');
    const storageKey=`serein:ecdh-p256:v1:${state.user.id}:${state.device.id}`;const readTx=state.localDb.transaction('keys','readonly');let row=await idbRequest(readTx.objectStore('keys').get(storageKey));await idbDone(readTx);
    if(!row?.privateKey||!row?.publicJwk){const pair=await window.SereinDeviceCrypto.generateDeviceKeyPair();row={key:storageKey,privateKey:pair.privateKey,publicJwk:pair.publicJwk};const writeTx=state.localDb.transaction('keys','readwrite');writeTx.objectStore('keys').put(row);await idbDone(writeTx);}
    if(row.privateKey.type!=='private'||row.privateKey.algorithm?.name!=='ECDH'||row.privateKey.extractable!==false)throw new Error('Stored device private key is not protected as expected.');
    const expectedFingerprint=await window.SereinDeviceCrypto.fingerprintP256(row.publicJwk);const publicKey={kty:row.publicJwk.kty,crv:row.publicJwk.crv,x:row.publicJwk.x,y:row.publicJwk.y};
    const reply=await api('/api/v1/device-key',{method:'PUT',body:JSON.stringify({algorithm:'ECDH-P256',public_key:publicKey})});
    if(reply.fingerprint!==expectedFingerprint)throw new Error('The server key fingerprint did not match this device key.');
    state.deviceKeyPair={privateKey:row.privateKey,publicJwk:row.publicJwk};state.deviceKeyFingerprint=expectedFingerprint;return state.deviceKeyPair;
  }
  async function deriveCandidateConversationKeys(contact){
    if(!state.deviceKeyPair)throw new Error('This browser has no enrolled device key.');
    const directory=await api(`/api/v1/contacts/${encodeURIComponent(contact.id)}/device-keys`);if(directory.user_id!==contact.id||directory.username!==contact.username)throw new Error('The key directory returned a different account identity.');
    const remote=Array.isArray(directory.devices)?directory.devices:[],active=contact.devices.filter(device=>device.id!==state.device.id),activeIds=new Set(active.map(device=>device.id));if(remote.some(item=>!activeIds.has(item.device_id)))throw new Error('The contact device list changed; refresh contacts and retry.');const byId=new Map(remote.map(item=>[item.device_id,item]));let missing=0;const keys=[];
    for(const device of active){const entry=byId.get(device.id);if(!entry){missing++;continue;}const fingerprint=await window.SereinDeviceCrypto.fingerprintP256(entry.public_key);if(fingerprint!==entry.fingerprint)throw new Error('A contact device key fingerprint is inconsistent.');const key=await window.SereinDeviceCrypto.deriveCandidateConversationKey(state.deviceKeyPair.privateKey,state.user.id,state.device.id,contact.id,device.id,entry.public_key);const trust=await getLocalMeta(`trusted-peer:${contact.id}:${device.id}`);keys.push({deviceId:device.id,deviceName:device.name||'Device',fingerprint,previousFingerprint:trust?.fingerprint||'',trusted:trust?.fingerprint===fingerprint,key});}
    for(const item of keys)state.conversationKeys.set(`${contact.id}:${item.deviceId}`,item);
    return {derived:keys.length,missing,total:active.length,devices:keys};
  }
  function renderPeerKeyControls(contact,devices){
    const container=$('peerKeyControls');container.replaceChildren();
    if(!devices.length){const empty=document.createElement('small');empty.textContent='No public device keys are available for this contact.';container.append(empty);return;}
    for(const item of devices){const row=document.createElement('div');row.className='peer-key-row';const title=document.createElement('b');title.textContent=`${contact.name} · ${item.deviceName}`;const fingerprint=document.createElement('code');fingerprint.textContent=item.fingerprint.match(/.{1,4}/g).join(' ');const status=document.createElement('span');status.className=item.trusted?'peer-key-trusted':'peer-key-unverified';status.textContent=item.trusted?'Verified on this device':item.previousFingerprint&&item.previousFingerprint!==item.fingerprint?'Key changed · re-verify before sending':'Not verified · compare this fingerprint directly with your contact';row.append(title,fingerprint,status);
      if(!item.trusted){const trust=document.createElement('button');trust.type='button';trust.className='text-button peer-key-confirm';trust.textContent='I compared this fingerprint';trust.addEventListener('click',async()=>{const change=item.previousFingerprint&&item.previousFingerprint!==item.fingerprint;const message=`Compare this complete fingerprint with ${contact.name} through a separate trusted channel.\n\n${item.fingerprint.match(/.{1,4}/g).join(' ')}\n\n${change?`The key changed since the previously trusted fingerprint. Previous: ${item.previousFingerprint.match(/.{1,4}/g).join(' ')}`:'This browser has not previously trusted this device key.'}\n\nTrust only if the fingerprints match exactly.`;if(!confirm(message))return;try{await setLocalMeta(`trusted-peer:${contact.id}:${item.deviceId}`,{fingerprint:item.fingerprint,verifiedAt:new Date().toISOString()});}catch(error){toast(`Fingerprint trust could not be saved on this device: ${error.message}`);return;}item.trusted=true;state.conversationKeys.set(`${contact.id}:${item.deviceId}`,item);renderPeerKeyControls(contact,devices);const trustedCount=devices.filter(device=>device.trusted).length;state.peerKeyState=trustedCount===devices.length?`All ${trustedCount} recipient device fingerprints are verified on this browser.`:`Verify ${devices.length-trustedCount} recipient device fingerprint(s) before sending.`;$('e2eeProgressText').textContent=`${state.peerKeyState} Compare full fingerprints through a separate trusted channel. This web message path is not independently reviewed.`;setConnected();toast('Device fingerprint trusted on this browser.');});row.append(trust);}
      container.append(row);
    }
  }
  function localMessageKey(id){return `${state.user.id}:${id}`;}
  function localMetaKey(name){return `${state.user.id}:${state.device.id}:${name}`;}
  async function storeLocalMessage(contactId,id,payload,status='received',createdAt=new Date().toISOString()){
    if(!state.localDb||!state.localKey)throw new Error('Encrypted local storage is not initialized');
    const iv=crypto.getRandomValues(new Uint8Array(12));const sealed=await crypto.subtle.encrypt({name:'AES-GCM',iv},state.localKey,enc.encode(JSON.stringify(payload)));
    const tx=state.localDb.transaction('messages','readwrite');tx.objectStore('messages').put({key:localMessageKey(id),accountKey:state.user.id,conversationKey:`${state.user.id}:${contactId}`,accountId:state.user.id,deviceId:state.device.id,conversationId:contactId,id,createdAt,status,iv:b64(iv),ciphertext:b64(sealed)});await idbDone(tx);
  }
  async function readLocalRecord(record){const clear=await crypto.subtle.decrypt({name:'AES-GCM',iv:fromB64(record.iv)},state.localKey,fromB64(record.ciphertext));return {...JSON.parse(dec.decode(clear)),id:record.id,createdAt:record.createdAt,status:record.status,conversationId:record.conversationId};}
  async function loadLocalConversation(contactId){if(!state.localDb||!state.localKey)return[];const tx=state.localDb.transaction('messages','readonly');const rows=await idbRequest(tx.objectStore('messages').index('conversationKey').getAll(`${state.user.id}:${contactId}`));await idbDone(tx);const items=[];for(const row of rows){try{items.push(await readLocalRecord(row));}catch(error){console.warn('Local message could not be opened',error);}}return items.sort((a,b)=>a.createdAt.localeCompare(b.createdAt));}
  async function loadAccountLocalMessages(){if(!state.localDb||!state.localKey)return[];const tx=state.localDb.transaction('messages','readonly');const rows=await idbRequest(tx.objectStore('messages').index('accountKey').getAll(state.user.id));await idbDone(tx);const items=[];for(const row of rows){try{items.push(await readLocalRecord(row));}catch(error){console.warn('A local message could not be opened',error);}}return items.sort((a,b)=>a.createdAt.localeCompare(b.createdAt));}
  async function loadPendingLocalMessages(){return (await loadAccountLocalMessages()).filter(item=>item.status==='pending');}
  async function updateLocalMessageStatus(id,status){if(!state.localDb)return;const tx=state.localDb.transaction('messages','readwrite');const store=tx.objectStore('messages');const key=localMessageKey(id);const row=await idbRequest(store.get(key));if(row){row.status=status;store.put(row);}await idbDone(tx);}
  async function getLocalMeta(name){if(!state.localDb)return null;const tx=state.localDb.transaction('meta','readonly');const row=await idbRequest(tx.objectStore('meta').get(localMetaKey(name)));await idbDone(tx);return row?.value??null;}
  async function setLocalMeta(name,value){if(!state.localDb)return;const tx=state.localDb.transaction('meta','readwrite');tx.objectStore('meta').put({key:localMetaKey(name),value});await idbDone(tx);}
  async function api(path,options={}){
    const headers=new Headers(options.headers||{});if(options.body&&!headers.has('Content-Type'))headers.set('Content-Type','application/json');
    const url=secureApiUrl(path);let response;try{response=await fetch(url,{...options,headers,credentials:'include',redirect:'error'});}catch{throw new Error('Could not reach the account service. If the web app and API use different origins, ALLOWED_WEB_ORIGINS must include this page’s exact origin (scheme, host, and port).');}
    const body=await response.json().catch(()=>({}));if(!response.ok){const error=new Error(body.error||`API request failed (${response.status}).`);error.status=response.status;error.verification=body.verification;error.retryAfterSeconds=Number(body.retry_after_seconds||response.headers.get('Retry-After'))||0;throw error;}return body;
  }
  async function transferRequest(path,options={}){
    const headers=new Headers(options.headers||{});const url=secureApiUrl(path);let response;try{response=await fetch(url,{...options,headers,credentials:'include',redirect:'error'});}catch{throw new Error('Could not reach the encrypted-transfer service.');}
    if(!response.ok){const body=await response.json().catch(()=>({}));throw new Error(body.error||`Transfer request failed (${response.status}).`);}return response;
  }
  function safeHealthText(payload){
    const components=payload?.components||{};const names=['api','database','frontend','email_delivery'];const allowed=new Set(['ready','ok','available','unavailable','degraded','disabled','configured','not_configured','unknown']);
    return names.map(name=>{const value=String(components[name]||'unknown').toLowerCase();return `${name}: ${allowed.has(value)?value:'unknown'}`;}).join(' · ');
  }
  function connectionStatusSummary(){return state.connectionStatus==='Not checked'?state.connectionStatus:`${state.connectionStatus} · checked ${state.connectionCheckOrigin||configuredApiBase()}`;}
  async function checkServerConnection(){
    let origin;try{origin=normalizeApiOrigin($('connectionUrl').value);}catch(error){$('connectionStatus').textContent=error.message;$('connectionStatus').className='connection-status error';return;}
    const button=$('checkConnection'),saveButton=$('saveConnection');button.disabled=true;saveButton.disabled=true;button.textContent='Checking…';$('connectionStatus').textContent='Checking secure connection…';$('connectionStatus').className='connection-status pending';
    state.connectionReachable=false;state.connectionCheckOrigin=origin;
    try{
      const response=await fetch(new URL('/healthz',origin),{method:'GET',cache:'no-store',redirect:'error'});
      const payload=await response.json();
      if(!response.ok&&response.status!==503)throw new Error(`Server returned HTTP ${response.status}.`);
      if(!payload||!['ready','degraded'].includes(payload.status)||!payload.components||typeof payload.components!=='object')throw new Error('Unexpected health response.');
      const ready=payload.status==='ready'&&response.ok;state.connectionReachable=true;state.connectionCheckOrigin=origin;
      state.connectionStatus=ready?'Connected · all reported components ready':'Server reachable · some components need attention';
      $('connectionStatus').textContent=`${state.connectionStatus}. ${safeHealthText(payload)}`;$('connectionStatus').className=`connection-status ${ready?'success':'warning'}`;
    }catch(error){state.connectionStatus='Not connected';const hint=origin!==location.origin?' Check that the server’s ALLOWED_WEB_ORIGINS includes this page’s exact origin.':'';$('connectionStatus').textContent=`Could not read a valid health response. Check the HTTPS origin and server availability.${hint}`;$('connectionStatus').className='connection-status error';}
    finally{button.disabled=false;saveButton.disabled=false;button.textContent='Check connection';$('connectionCurrentOrigin').textContent=configuredApiBase();$('connectionCurrentStatus').textContent=connectionStatusSummary();}
  }
  function openConnectionSettings(){
    $('connectionUrl').value=configuredApiBase();$('connectionStatus').textContent=state.connectionStatus;$('connectionStatus').className='connection-status';
    $('connectionCurrentOrigin').textContent=configuredApiBase();$('connectionCurrentStatus').textContent=connectionStatusSummary();
    $('connectionDialog').showModal();
  }
  async function saveConnection(event){
    event.preventDefault();let origin;try{origin=normalizeApiOrigin($('connectionUrl').value);}catch(error){$('connectionStatus').textContent=error.message;$('connectionStatus').className='connection-status error';return;}
    if(state.connectionCheckOrigin!==origin||!state.connectionReachable){await checkServerConnection();if(state.connectionCheckOrigin!==origin||!state.connectionReachable)return;}
    const previous=configuredApiBase();if(origin===previous){$('connectionDialog').close();return;}
    if(state.user){if(!confirm('Changing servers signs you out of the current server. Continue?'))return;const revoked=await disconnect({requireServerRevocation:true});if(!revoked){$('connectionStatus').textContent='Could not confirm sign-out from the current server. The connection choice was not changed; try again when it is reachable.';$('connectionStatus').className='connection-status error';return;}}
    try{localStorage.setItem('serein.api-origin.v1',origin);}catch{$('connectionStatus').textContent='This browser could not save the server choice.';$('connectionStatus').className='connection-status error';return;}
    $('connectionDialog').close();location.reload();
  }
  function showWhatsNewIfNeeded(){
    if($('whatsNewDialog').open)return;
    let seen='';try{seen=localStorage.getItem('serein.whats-new.version')||'';}catch{}
    if(seen===APP_VERSION)return;
    $('whatsNewTitle').textContent=seen?'What’s new in Serein':'Welcome to Serein';$('whatsNewVersion').textContent=`Version ${APP_VERSION}`;
    const entries=['Email verification and stronger registration safeguards are available.','Manage contacts, privacy choices, and registered devices from your account.','Server connection can be checked and changed from the account menu or sign-in screen.','Web text messaging now uses device keys; compare each fingerprint before sending.'];
    const list=$('whatsNewItems');list.replaceChildren();for(const item of entries){const li=document.createElement('li');li.textContent=item;list.append(li);}
    $('whatsNewDialog').dataset.versionToRemember=APP_VERSION;$('whatsNewDialog').showModal();
  }
  function closeWhatsNew(){const dialog=$('whatsNewDialog');const version=dialog.dataset.versionToRemember;if(version)try{localStorage.setItem('serein.whats-new.version',version);}catch{}dialog.close();}
  async function refreshContacts(){
    const rows=await api('/api/v1/contacts');const meta=contactMeta();
    state.contacts=(Array.isArray(rows)?rows:[]).map(c=>({id:c.user_id,user_id:c.user_id,username:c.username,name:c.display_name,verified:c.email_verified,online:!!c.online,devices:c.devices||[],favorite:!!meta[c.user_id]?.favorite,unread:meta[c.user_id]?.unread||0,lastPreview:meta[c.user_id]?.lastPreview||''}));
    if(state.selected)state.selected=state.contacts.find(contact=>contact.id===state.selected.id)||null;
    renderContacts($('search').value);
  }
  async function refreshContactRequests(){
    const rows=await api('/api/v1/contact-requests');state.contactRequests=Array.isArray(rows)?rows:[];const count=$('requestCount');if(count)count.textContent=state.contactRequests.length?`· ${state.contactRequests.length}`:'';const list=$('requestList');if(!list)return;list.replaceChildren();
    if(!state.contactRequests.length){const empty=document.createElement('p');empty.className='muted';empty.textContent='No incoming requests.';list.append(empty);return;}
    for(const request of state.contactRequests){const row=document.createElement('div');row.className='request-row';const info=document.createElement('div');const name=document.createElement('b');name.textContent=request.display_name;const detail=document.createElement('span');detail.textContent=`@${request.username} wants to connect`;info.append(name,detail);row.append(info);const actions=document.createElement('div');actions.className='request-actions';
      const accept=document.createElement('button');accept.className='btn btn-small btn-primary';accept.textContent='Accept';accept.addEventListener('click',async()=>{try{await api(`/api/v1/contact-requests/${request.id}/accept`,{method:'POST',body:'{}'});await Promise.all([refreshContacts(),refreshContactRequests()]);toast('Contact request accepted.');}catch(e){toast(e.message);}});actions.append(accept);
      const dismiss=document.createElement('button');dismiss.className='btn btn-small btn-outline';dismiss.textContent='Decline';dismiss.addEventListener('click',async()=>{try{await api(`/api/v1/contact-requests/${request.id}`,{method:'DELETE'});await refreshContactRequests();}catch(e){toast(e.message);}});actions.append(dismiss);row.append(actions);list.append(row);
    }
  }
  async function refreshBlocks(){const rows=await api('/api/v1/blocks');state.blocks=Array.isArray(rows)?rows:[];const list=$('blockList');if(!list)return;list.replaceChildren();if(!state.blocks.length){const empty=document.createElement('p');empty.className='muted';empty.textContent='No blocked accounts.';list.append(empty);return;}for(const user of state.blocks){const row=document.createElement('div');row.className='request-row';const info=document.createElement('div');const name=document.createElement('b');name.textContent=user.display_name;const handle=document.createElement('span');handle.textContent=`@${user.username}`;info.append(name,handle);const unblock=document.createElement('button');unblock.className='btn btn-small btn-outline';unblock.textContent='Unblock';unblock.addEventListener('click',async()=>{try{await api(`/api/v1/blocks/${user.user_id}`,{method:'DELETE'});await refreshBlocks();toast('Account unblocked.');}catch(e){toast(e.message);}});row.append(info,unblock);list.append(row);}}
  function filteredContacts(query=''){
    const q=query.toLowerCase();return state.contacts.filter(c=>`${c.name} ${c.username}`.toLowerCase().includes(q)).filter(c=>state.filter==='favorites'?c.favorite:state.filter==='unread'?c.unread>0:true);
  }
  function renderContacts(query=''){
    const list=el.contactList;list.replaceChildren();const contacts=filteredContacts(query);
    if(!contacts.length){const empty=document.createElement('div');empty.className='no-contacts';empty.textContent=state.contacts.length?'Nothing in this filter yet.':'No contacts yet. Add someone by Serein username.';list.append(empty);return;}
    for(const c of contacts){const row=document.createElement('button');row.type='button';row.className=`contact-row${state.selected?.id===c.id?' selected':''}`;row.setAttribute('aria-label',`Open chat with ${c.name}`);
      row.append(avatar(c.name,'md','contact-avatar'));const info=document.createElement('span');info.className='contact-info';const title=document.createElement('b');title.textContent=c.name;const preview=document.createElement('span');preview.textContent=c.lastPreview||(c.online?'Online':`@${c.username} · ${c.devices.length} device${c.devices.length===1?'':'s'}`);info.append(title,preview);
      const tail=document.createElement('span');tail.className='contact-tail';tail.textContent=c.favorite?'★':'';if(c.unread)tail.textContent=String(c.unread);row.append(info,tail);row.addEventListener('click',()=>openContact(c));list.append(row);}
  }
  function configuredApiBase(){try{return localStorage.getItem('serein.api-origin.v1')||DEFAULT_API_BASE||location.origin;}catch{return DEFAULT_API_BASE||location.origin;}}
  function normalizeApiOrigin(value){let parsed;try{parsed=new URL(String(value||'').trim());}catch{throw new Error('Enter a valid server URL.');}const local=parsed.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(parsed.hostname);if((parsed.protocol!=='https:'&&!local)||parsed.username||parsed.password||parsed.pathname!=='/'||parsed.search||parsed.hash)throw new Error('Use an HTTPS server origin with no path, credentials, or query values (localhost HTTP is for development).');return parsed.origin;}
  function secureApiUrl(path){let base;try{base=new URL(configuredApiBase(),location.href);}catch{throw new Error('Enter a valid API URL.');}const local=base.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(base.hostname);if((base.protocol!=='https:'&&!local)||base.username||base.password||base.search||base.hash)throw new Error('API URL must use HTTPS and must not contain credentials or query values (localhost HTTP is for development only).');return new URL(path,base);}
  function websocketUrl(input){let u;try{u=new URL(input);}catch{throw new Error('Enter a valid relay URL.');}const local=['localhost','127.0.0.1','[::1]'].includes(u.hostname);if(u.username||u.password||u.search||u.hash)throw new Error('Relay URL must not contain credentials or query values.');if(u.protocol==='https:')u.protocol='wss:';else if(u.protocol==='http:'&&local)u.protocol='ws:';else if(u.protocol==='ws:'&&!local)throw new Error('Relay connections must use WSS (WS is allowed only on localhost).');else if(u.protocol!=='wss:'&&u.protocol!=='ws:')throw new Error('Relay URL must use HTTPS/WSS (or localhost for development).');u.pathname='/v1/ws';return u.toString();}
  function openSocket(input){return new Promise((resolve,reject)=>{const ws=new WebSocket(websocketUrl(input));const timer=setTimeout(()=>{ws.close();reject(new Error('Relay connection timed out.'));},10000);ws.onopen=()=>{clearTimeout(timer);resolve(ws);};ws.onerror=()=>{clearTimeout(timer);reject(new Error('Unable to connect to the authenticated relay.'));};});}
  function setConnected(){const active=MESSAGING_ENABLED&&state.socket?.readyState===WebSocket.OPEN;const canType=!!state.user&&!!state.selected;const peers=state.selected?.devices||[];const keysTrusted=peers.length>0&&peers.every(device=>state.conversationKeys.get(`${state.selected.id}:${device.id}`)?.trusted);const canSend=MESSAGING_ENABLED&&canType&&!!state.localKey&&keysTrusted&&!!el.messageInput.value.trim();el.messageInput.disabled=!canType;el.sendButton.disabled=!canSend;el.sendButton.title=canSend?'Send encrypted message':!state.localKey?'Encrypted local storage is unavailable':!keysTrusted?'Verify every recipient-device fingerprint before sending':'Enter a message to send';if($('chatState'))$('chatState').textContent=state.peerKeyState|| (active?'Encrypted delivery ready':'Connecting to the secure message service…');}
  function paintMessage(item){const row=document.createElement('div');row.className=`message-row${item.mine?' mine':''}`;if(!item.mine)row.append(avatar(item.sender,'sm','message-avatar'));const bubble=document.createElement('div');bubble.className='bubble';if(item.attachment){const card=document.createElement('div');card.className='attachment-card';const icon=document.createElement('span');icon.className='attachment-icon';icon.textContent=item.attachment.contentType.startsWith('video/')?'▣':item.attachment.contentType.startsWith('audio/')?'♫':'↧';const info=document.createElement('div');info.className='attachment-label';const name=document.createElement('b');name.textContent=item.attachment.filename;info.append(name);const open=document.createElement('button');open.type='button';open.className='attachment-open';open.textContent='Download';open.addEventListener('click',()=>openEncryptedAttachment(item).catch(error=>toast(`Attachment could not be decrypted: ${error.message}`)));const details=document.createElement('small');details.textContent=`${item.attachment.contentType||'file'} · ${formatBytes(item.attachment.size)}`;info.append(details);card.append(icon,info,open);bubble.append(card);}else bubble.textContent=item.text;const meta=document.createElement('small');meta.className='bubble-meta';const stateText=item.mine?(item.status==='accepted'?'stored on server':'waiting for server confirmation'):'received on this device';meta.textContent=`${item.time} · ${stateText}`;bubble.append(meta);row.append(bubble);el.messageList.append(row);el.messageList.scrollTop=el.messageList.scrollHeight;}
  function rememberMessage(contact,text,mine,sender,id,createdAt,status,attachment=null){const item={id,text,mine,sender,status,createdAt,time:new Date(createdAt).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}),attachment};state.messages[contact.id] ||= [];if(!state.messages[contact.id].some(existing=>existing.id===id))state.messages[contact.id].push(item);if(state.selected?.id===contact.id)paintMessage(item);return item;}
  function safeAttachmentName(value){const name=String(value||'file').replaceAll('/','_').replaceAll('\\','_').replace(/[\u0000-\u001f\u007f]/g,'_').slice(0,180).trim();return name||'file';}
  function validateAttachmentDescriptor(value,senderDeviceId){if(!value||typeof value!=='object'||!/^([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/i.test(String(value.transfer_id||''))||typeof value.filename!=='string'||value.filename.length>255||typeof value.content_type!=='string'||value.content_type.length>128||!Number.isSafeInteger(value.size)||value.size<0||value.size>MAX_TRANSFER_CIPHERTEXT_BYTES)throw new Error('Encrypted attachment notice is malformed.');return{transferId:String(value.transfer_id),filename:safeAttachmentName(value.filename),contentType:value.content_type,size:value.size,senderDeviceId};}
  function formatBytes(value){if(value<1024)return`${value} B`;if(value<1024*1024)return`${(value/1024).toFixed(1)} KB`;return`${(value/1024/1024).toFixed(1)} MB`;}
  async function acknowledgeMessage(id){
    if(state.socket?.readyState===WebSocket.OPEN){state.socket.send(JSON.stringify({type:'ack',id}));return;}
    await api(`/api/v1/messages/${encodeURIComponent(id)}/ack`,{method:'POST',body:'{}'});
  }
  async function processPacket(packet,serverCreatedAt){
    if(packet.type==='accepted'){const pending=state.pendingSends.get(packet.id);if(pending){pending.accepted.add(packet.to);if(pending.accepted.size>=pending.expected){state.pendingSends.delete(packet.id);await updateLocalMessageStatus(packet.id,'accepted');const item=(state.messages[pending.contactId]||[]).find(value=>value.id===packet.id);if(item)item.status='accepted';}}return true;}
    if(packet.type==='error'){toast(packet.message||'Message was rejected.');return true;}
    if(packet.type!=='message'||typeof packet.from!=='string'||typeof packet.id!=='string')return true;
    if(state.seenIds.has(packet.id)){await acknowledgeMessage(packet.id);return true;}
    if(state.processingIds.has(packet.id))return false;state.processingIds.add(packet.id);
    try{
      const contact=state.contacts.find(item=>item.devices.some(device=>device.id===packet.from));
      if(!contact){toast('A stored message is waiting for its contact or active device to be restored.');return false;}
      let peer=state.conversationKeys.get(`${contact.id}:${packet.from}`);
      if(!peer){await deriveCandidateConversationKeys(contact);peer=state.conversationKeys.get(`${contact.id}:${packet.from}`);}
      if(!peer?.trusted){if(state.selected?.id===contact.id)state.peerKeyState='Verify the sender-device fingerprint before decrypting messages.';toast(`Message from ${contact.name} is held until its device fingerprint is verified.`);return false;}
      const metadata={conversationId:contact.id,messageId:packet.id,senderUserId:contact.id,senderDeviceId:packet.from,recipientUserId:state.user.id,recipientDeviceId:state.device.id};
      const cleartext=await window.SereinDeviceCrypto.decryptMessage(peer.key,{version:1,algorithm:'AES-256-GCM',iv:packet.iv,ciphertext:packet.ciphertext},metadata);
      const content=JSON.parse(cleartext);
      if(content?.version!==1||typeof content.text!=='string'||content.conversation_id!==contact.id||content.sender_user_id!==contact.id||content.sender_device_id!==packet.from||content.recipient_user_id!==state.user.id||content.recipient_device_id!==state.device.id)throw new Error('Encrypted message routing metadata did not match this conversation.');
      if(messageLimits.characterCount(content.text)>messageLimits.maxCharacters())throw new Error('Decrypted message exceeds the shared message-size limit.');
      const attachment=content.attachment==null?null:validateAttachmentDescriptor(content.attachment,packet.from);
      const createdAt=serverCreatedAt||new Date().toISOString();await storeLocalMessage(contact.id,packet.id,{text:content.text,sender:contact.name,mine:false,attachment},'received',createdAt);state.seenIds.add(packet.id);
      rememberMessage(contact,content.text,false,contact.name,packet.id,createdAt,'received',attachment);contact.lastPreview=attachment?`📎 ${attachment.filename}`:content.text.slice(0,50);if(state.selected?.id===contact.id)contact.unread=0;else{contact.unread++;toast(`New encrypted ${attachment?'file':'message'} from ${contact.name}`);}saveContacts();await acknowledgeMessage(packet.id);return true;
    }finally{state.processingIds.delete(packet.id);}
  }
  async function handlePacket(event){try{await processPacket(JSON.parse(event.data));}catch(error){console.warn('Message processing failed; no delivery ACK was sent',error);toast('Message was not acknowledged because local save or decryption failed. It will retry.');}}
  async function loadLocalTimeline(){state.messages={};state.seenIds.clear();for(const item of await loadAccountLocalMessages()){state.seenIds.add(item.id);state.messages[item.conversationId] ||= [];state.messages[item.conversationId].push({...item,time:new Date(item.createdAt).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})});}}
  async function syncServerHistory(){
    let cursor=await getLocalMeta('historyCursor');let pages=0;
    while(pages++<1000){const params=new URLSearchParams({limit:'100'});if(cursor?.after_created_at&&cursor?.after_id){params.set('after_created_at',cursor.after_created_at);params.set('after_id',cursor.after_id);}const page=await api(`/api/v1/messages?${params}`);const items=Array.isArray(page.items)?page.items:[];if(!items.length)break;
      for(const item of items){const stored=await processPacket(item.payload,item.created_at);if(!stored)return;cursor={after_created_at:item.created_at,after_id:item.id};await setLocalMeta('historyCursor',cursor);}
      if(!page.has_more)break;
    }
  }
  async function resendPendingMessages(){
    if(!state.user||!state.deviceKeyPair)return;
    for(const item of await loadPendingLocalMessages()){
      const envelopes=Array.isArray(item.envelopes)?item.envelopes:[];if(!envelopes.length)continue;
      const pending={expected:envelopes.length,accepted:new Set(),contactId:item.conversationId};state.pendingSends.set(item.id,pending);
      try{for(const envelope of envelopes){await api('/api/v1/messages',{method:'POST',body:JSON.stringify({id:item.id,to:envelope.to,iv:envelope.iv,ciphertext:envelope.ciphertext})});pending.accepted.add(envelope.to);}}
      catch(error){console.info('Pending encrypted message will retry later.',error);continue;}
      if(pending.accepted.size===pending.expected){await updateLocalMessageStatus(item.id,'accepted');state.pendingSends.delete(item.id);const message=(state.messages[item.conversationId]||[]).find(value=>value.id===item.id);if(message)message.status='accepted';}
    }
  }
  async function connectMessaging(){
    if(!state.user)return;state.relay=configuredApiBase();
    try{const socket=await openSocket(state.relay);state.reconnectAttempt=0;attachSocket(socket);await syncServerHistory();await resendPendingMessages();}
    catch(error){console.info('Realtime message socket unavailable; durable HTTP delivery and polling remain active.',error);scheduleReconnect();}
  }
  function attachSocket(socket){state.socket=socket;socket.onmessage=handlePacket;socket.onclose=()=>{if(state.socket===socket)state.socket=null;setConnected();if(!state.signingOut){toast('Connection lost. Reconnecting…');scheduleReconnect();}};clearInterval(state.heartbeatTimer);state.heartbeatTimer=setInterval(()=>{if(state.socket?.readyState===WebSocket.OPEN)state.socket.send(JSON.stringify({type:'heartbeat'}));},25000);setConnected();}
  function scheduleReconnect(){if(state.reconnectTimer||state.signingOut||!state.user||!state.relay)return;const delay=Math.min(30000,1000*(2**Math.min(state.reconnectAttempt++,5)));state.reconnectTimer=setTimeout(async()=>{state.reconnectTimer=0;try{const socket=await openSocket(state.relay);state.reconnectAttempt=0;attachSocket(socket);await refreshContacts();await refreshContactRequests();await refreshBlocks();await refreshDevices();await loadLocalTimeline();await syncServerHistory();await resendPendingMessages();toast('Reconnected and synced stored messages.');}catch(error){console.warn('Reconnect attempt failed',error);scheduleReconnect();}},delay);}
  function registrationPasswordRequirements(password){
    const shared=window.SereinCore?.registrationPasswordRequirements(password);
    return shared||{length:[...password].length>=8,upper:/[A-Z]/.test(password),lower:/[a-z]/.test(password),digit:/[0-9]/.test(password),bytes:enc.encode(password).length<=1024};
  }
  function updateAuthValidation(){
    const reg=state.authMode==='register',password=$('accountPassword').value,confirm=$('confirmPassword').value;
    const {length:lengthOk,upper:upperOk,lower:lowerOk,digit:digitOk,bytes:bytesOk}=registrationPasswordRequirements(password);
    $('passwordRequirements').classList.toggle('visible',reg);
    for(const [rule,ok] of Object.entries({length:lengthOk,upper:upperOk,lower:lowerOk,digit:digitOk,bytes:bytesOk}))$('passwordRequirements').querySelector(`[data-password-rule="${rule}"]`).classList.toggle('satisfied',ok);
    const feedback=$('confirmPasswordFeedback');feedback.classList.remove('match','mismatch');
    if(reg&&confirm){const matches=password===confirm;feedback.textContent=matches?'Passwords match':'Passwords do not match';feedback.classList.add(matches?'match':'mismatch');}
    else feedback.textContent='';
    $('accountPassword').autocomplete=reg?'new-password':'current-password';
    const identity=clean($('loginIdentity').value,120),username=$('regHandle').value.trim(),name=$('regName').value.trim(),email=$('regEmail');
    const signinFeedback=$('signinFeedback');signinFeedback.textContent=reg?'':(!identity||!password?'Enter both your email or username and password.':'Ready to sign in. Credentials are checked when you submit.');
    const usernameOk=/^[a-z0-9_.-]{3,32}$/.test(username.toLowerCase());
    const regValid=!!name&&usernameOk&&!!email.value.trim()&&email.validity.valid&&lengthOk&&upperOk&&lowerOk&&digitOk&&bytesOk&&!!confirm&&confirm===password;
    $('authSubmit').disabled=!!$('authSubmit').dataset.busy||!(reg?regValid:(!!identity&&password.length>0));
    $('accountPassword').setAttribute('aria-invalid',String(reg&&password.length>0&&(!lengthOk||!upperOk||!lowerOk||!digitOk||!bytesOk)));
    $('confirmPassword').setAttribute('aria-invalid',String(reg&&confirm.length>0&&confirm!==password));
  }
  function authMode(mode){state.authMode=mode;const reg=mode==='register';$('signinTab').classList.toggle('active',!reg);$('registerTab').classList.toggle('active',reg);$('registerFields').classList.toggle('hidden',!reg);$('signinFields').classList.toggle('hidden',reg);$('confirmPasswordWrap').classList.toggle('hidden',!reg);$('authTitle').textContent=reg?'Create your account':'Sign in';$('authSubtitle').textContent=reg?'A profile for the people you choose.':'Continue to your conversations.';$('authSubmit').innerHTML=reg?'Create account <span>→</span>':'Sign in <span>→</span>';updateAuthValidation();}
  function maskedEmail(email){
    const [local,domain='']=(email||'').split('@');
    if(!local||!domain)return 'your email address';
    return `${local.slice(0,1)}${'•'.repeat(Math.min(4,Math.max(2,local.length-1)))}@${domain}`;
  }
  function verificationCode(){return [...document.querySelectorAll('.otp-digit')].map(input=>input.value).join('');}
  function verificationMessage(text='',kind=''){
    const node=$('verificationMessage');node.textContent=text;node.classList.remove('error','success');if(kind)node.classList.add(kind);
  }
  function updateVerificationButton(){
    const button=$('verifySubmit'),code=verificationCode(),busy=state.verificationBusy;
    button.disabled=busy||code.length!==6;button.classList.toggle('loading',busy);button.setAttribute('aria-busy',String(busy));
    $('verifySpinner').classList.toggle('hidden',!busy);
    $('verifySubmitLabel').textContent=busy?'Verifying…':code.length===6?'Verify email':'Enter the six-digit code';
  }
  function showVerification(email,message='',kind='success'){
    const nextEmail=clean(email,120).toLowerCase();
    if(nextEmail!==state.verificationEmail){clearInterval(state.resendTimer);state.resendTimer=0;state.resendUntil=0;const resend=$('resendCode');if(resend){resend.disabled=false;resend.textContent='Resend code';}}
    state.verificationEmail=nextEmail;state.verificationBusy=false;
    $('authTitle').textContent='Verify your email';$('authSubtitle').textContent='Enter the six-digit code sent to your inbox.';
    $('authForm').classList.add('hidden');$('authTabs').classList.add('hidden');$('authNotice').classList.add('hidden');
    $('verificationPanel').classList.remove('hidden');$('verificationAddress').textContent=maskedEmail(state.verificationEmail);
    document.querySelectorAll('.otp-digit').forEach(input=>{input.value='';input.removeAttribute('aria-invalid');});
    verificationMessage(message,message?kind:'');updateVerificationButton();
    document.querySelector('.otp-digit')?.focus();
  }
  function handleOtpKeydown(event){
    const inputs=[...document.querySelectorAll('.otp-digit')],index=inputs.indexOf(event.currentTarget);
    if((event.key==='Backspace'&&!event.currentTarget.value&&index>0)||event.key==='ArrowLeft'&&index>0){event.preventDefault();inputs[index-1].focus();}
    else if(event.key==='ArrowRight'&&index<inputs.length-1){event.preventDefault();inputs[index+1].focus();}
  }
  function handleOtpInput(event){
    const inputs=[...document.querySelectorAll('.otp-digit')],input=event.currentTarget,index=inputs.indexOf(input);
    const digits=input.value.replace(/[^0-9]/g,'').slice(0,6);
    if(digits.length>1){inputs.forEach((field,i)=>{field.value=digits[i]||'';});inputs[Math.min(digits.length,5)]?.focus();}
    else{input.value=digits.slice(0,1);if(digits&&index<inputs.length-1)inputs[index+1].focus();}
    if(digits)verificationMessage('');updateVerificationButton();
    if(verificationCode().length===6)verifyOtp();
  }
  async function verifyOtp(){
    if(state.verificationBusy||$('verificationPanel').classList.contains('hidden'))return;
    const email=state.verificationEmail,code=verificationCode();
    if(!email){verificationMessage('The account email is missing. Return to sign-in and try again.','error');return;}
    if(code.length!==6)return;
    state.verificationBusy=true;updateVerificationButton();verificationMessage('Checking your code securely…');
    try{
      const result=await api('/api/v1/auth/verify-email',{method:'POST',body:JSON.stringify({email,code,device_name:'Serein Web',device_id:persistentDeviceId()})});
      await acceptAccount(result);
    }catch(error){verificationMessage(error.message,'error');document.querySelector('.otp-digit')?.focus();}
    finally{state.verificationBusy=false;if(!$('verificationPanel').classList.contains('hidden'))updateVerificationButton();}
  }
  function backToAuth(){state.authMode='signin';state.verificationEmail='';state.verificationBusy=false;$('verificationPanel').classList.add('hidden');$('authForm').classList.remove('hidden');$('authTabs').classList.remove('hidden');$('authNotice').classList.remove('hidden');authMode(state.authMode);$('loginIdentity').focus();}
  async function showAccountApp(){
    clearInterval(state.resendTimer);state.resendTimer=0;state.resendUntil=0;
    state.verificationEmail='';state.relay='';state.selected=null;
    $('authForm').classList.add('hidden');$('authTabs').classList.add('hidden');$('authNotice').classList.add('hidden');$('verificationPanel').classList.add('hidden');
    el.login.classList.add('hidden');el.app.classList.remove('hidden');el.app.classList.remove('chat-open');
    $('emptyState').classList.remove('hidden');$('conversation').classList.add('hidden');$('settings').classList.add('hidden');
    $('meName').textContent=state.name;$('avatar').setAttribute('label',state.name);$('avatar').setAttribute('tone',colorFor(state.name));
    $('settingsAvatar').setAttribute('label',state.name);$('settingsAvatar').setAttribute('tone',colorFor(state.name));$('settingsName').textContent=state.name;
    $('settingsHandle').textContent=`@${state.user.username}`;$('settingDevice').textContent=state.device.name;
    $('settingUsername').textContent=`@${state.user.username}`;$('settingVerification').textContent=state.user.email_verified?'Verified':'Not verified';if($('settingKeyFingerprint'))$('settingKeyFingerprint').textContent=state.deviceKeyFingerprint?state.deviceKeyFingerprint.match(/.{1,4}/g).join(' '):'Not enrolled';
    $('connectionCurrentOrigin').textContent=configuredApiBase();$('connectionCurrentStatus').textContent=connectionStatusSummary();$('settingRelay').textContent='Not available yet';setConnected();
    const results=await Promise.allSettled([refreshContacts(),refreshContactRequests(),refreshBlocks(),refreshDevices(),loadLocalTimeline()]);
    const failed=results.find(result=>result.status==='rejected');if(failed)toast(`Account loaded; some details could not be refreshed: ${failed.reason?.message||'service unavailable'}`);connectMessaging().catch(error=>console.warn('Message service connection failed',error));setTimeout(showWhatsNewIfNeeded,250);
  }
  async function acceptAccount(result){
    state.signingOut=false;const account=result.account;if(!account?.user||!account?.device)throw new Error('Account service returned an incomplete session.');
    state.user=account.user;state.device=account.device;localStorage.setItem('serein.stable-device-id.v1',account.device.id);state.name=account.user.display_name;state.identity=account.user.username;
    try{await initializeLocalStore();}catch(storageError){state.localKey=null;toast(`Local encrypted storage unavailable: ${storageError.message}`);}
    try{await ensureDeviceKeyEnrollment();}catch(keyError){state.deviceKeyPair=null;state.deviceKeyFingerprint='';toast(`Device key setup is incomplete; encrypted sending is unavailable: ${keyError.message}`);}
    await loadAccountSettings();await showAccountApp();toast('Account ready. Verify each contact-device fingerprint before sending an encrypted message.');
  }
  async function handleAuthSubmit(event){event.preventDefault();const password=$('accountPassword').value;const button=$('authSubmit');button.dataset.busy='true';button.disabled=true;button.textContent='Please wait…';let registrationEmail='';
    try{let result;if(state.authMode==='register'){
        const name=clean($('regName').value,48),username=clean($('regHandle').value,32).toLowerCase(),email=clean($('regEmail').value,120).toLowerCase(),confirm=$('confirmPassword').value;registrationEmail=email;
        if(!name||!username||!email){toast('Complete your name, username, and email.');return;}await window.SereinCore?.ready;const passwordRules=registrationPasswordRequirements(password);if(!passwordRules.length){toast('Use at least 8 characters for your password.');return;}if(!passwordRules.bytes){toast('Password must be no more than 1024 UTF-8 bytes.');return;}if(!passwordRules.upper||!passwordRules.lower||!passwordRules.digit){toast('Add at least one uppercase letter, one lowercase letter, and one number.');return;}if(window.SereinCore&&!window.SereinCore.validUsername(username)){toast('Use 3–32 lowercase letters, numbers, dots, dashes, or underscores for the username.');return;}if(password!==confirm){toast('Passwords do not match.');return;}
        result=await api('/api/v1/auth/register',{method:'POST',body:JSON.stringify({username,email,display_name:name,password})});
        showVerification(result.verification?.email||email,result.message||'A verification code was sent to your inbox.');return;
      }
      const identity=clean($('loginIdentity').value,120);if(!identity){toast('Enter your email or username.');return;}result=await api('/api/v1/auth/login',{method:'POST',body:JSON.stringify({identity,password,device_name:'Serein Web',device_id:persistentDeviceId()})});await acceptAccount(result);
    }catch(error){if(error.verification?.required){showVerification(error.verification.email||registrationEmail,error.message,'error');}else if(error.status===403){const identity=clean($('loginIdentity').value,120);showVerification(identity.includes('@')?identity:'',error.message,'error');}else toast(error.message);}finally{button.dataset.busy='';button.innerHTML=state.authMode==='register'?'Create account <span>→</span>':'Sign in <span>→</span>';updateAuthValidation();}}
  async function handleVerificationSubmit(event){event.preventDefault();await verifyOtp();}
  function startResendCooldown(seconds){
    clearInterval(state.resendTimer);state.resendUntil=Date.now()+Math.max(1,seconds)*1000;
    const button=$('resendCode');
    const tick=()=>{const remaining=Math.max(0,Math.ceil((state.resendUntil-Date.now())/1000));if(remaining===0){clearInterval(state.resendTimer);state.resendTimer=0;button.disabled=false;button.textContent='Resend code';return;}button.disabled=true;button.textContent=`Resend in ${String(Math.floor(remaining/60)).padStart(2,'0')}:${String(remaining%60).padStart(2,'0')}`;};
    tick();state.resendTimer=setInterval(tick,250);
  }
  async function handleResendCode(){
    if(!state.verificationEmail){verificationMessage('The account email is missing. Return to sign-in and try again.','error');return;}
    const button=$('resendCode');button.disabled=true;button.textContent='Sending…';verificationMessage('Requesting a new code…');
    try{const result=await api('/api/v1/auth/resend-verification',{method:'POST',body:JSON.stringify({identity:state.verificationEmail})});verificationMessage(result.message||'If this account needs verification, a code will be sent.', 'success');startResendCooldown(Number(result.retry_after_seconds)||60);}
    catch(error){verificationMessage(error.message,'error');if(error.retryAfterSeconds>0)startResendCooldown(error.retryAfterSeconds);}
    finally{if(Date.now()>=state.resendUntil){button.disabled=false;button.textContent='Resend code';}}
  }
  function updateComposerCounter({normalize=true}={}){
    const input=el.messageInput,limit=messageLimits.maxCharacters();
    if(normalize){const bounded=messageLimits.truncate(input.value,limit);if(bounded!==input.value){const cursor=input.selectionStart??bounded.length;input.value=bounded;try{input.setSelectionRange(Math.min(cursor,bounded.length),Math.min(cursor,bounded.length));}catch{}}}
    const status=messageLimits.counter(input.value),counter=$('charCount');counter.textContent=status.text;counter.hidden=!status.visible;counter.classList.toggle('warning',status.warning);counter.classList.toggle('critical',status.critical);counter.setAttribute('aria-label',status.visible?`${status.remaining} characters remaining of ${limit}`:`${status.count} of ${limit} characters`);
  }
  function handleComposerInput(event){
    updateComposerCounter({normalize:!event.isComposing});el.messageInput.style.height='auto';el.messageInput.style.height=`${Math.min(el.messageInput.scrollHeight,130)}px`;setConnected();
  }
  async function openContact(contact){if(state.selected?.id)state.drafts[state.selected.id]=el.messageInput.value;state.selected=contact;contact.unread=0;state.conversationKeys.clear();state.peerKeyState='Loading contact device keys…';$('peerKeyControls').replaceChildren();saveContacts();$('emptyState').classList.add('hidden');$('settings').classList.add('hidden');$('conversation').classList.remove('hidden');if(matchMedia('(max-width: 650px)').matches)el.app.classList.add('chat-open');
    $('chatName').textContent=contact.name;$('chatAvatar').setAttribute('label',contact.name);$('chatAvatar').setAttribute('tone',colorFor(contact.name));el.messageList.replaceChildren();const sep=document.createElement('div');sep.className='day-separator';const tag=document.createElement('span');tag.textContent=`${contact.devices.length} registered device${contact.devices.length===1?'':'s'}`;sep.append(tag);el.messageList.append(sep);(state.messages[contact.id]||[]).forEach(paintMessage);el.messageInput.value=state.drafts[contact.id]||'';updateComposerCounter();setConnected();
    try{const result=await deriveCandidateConversationKeys(contact);if(state.selected?.id!==contact.id)return;renderPeerKeyControls(contact,result.devices);const trusted=result.devices.filter(item=>item.trusted).length;state.peerKeyState=result.missing?`${result.missing} active device(s) have no published public key.`:trusted===result.total&&result.total>0?`All ${trusted} recipient device fingerprints are verified on this browser.`:`Verify ${result.total-trusted} recipient device fingerprint(s) before sending.`;$('e2eeProgressText').textContent=`${state.peerKeyState} Compare the full fingerprints through a separate trusted channel. This web message path is not independently reviewed.`;setConnected();}catch(error){state.peerKeyState=`Key agreement unavailable: ${error.message}`;$('e2eeProgressText').textContent=state.peerKeyState;$('peerKeyControls').replaceChildren();}if(state.selected?.id===contact.id)$('chatState').textContent=state.peerKeyState;
  }
  async function sendMessage(event,attachment=null,contactOverride=null){
    event?.preventDefault();
    const contact=contactOverride||state.selected,text=attachment?`📎 ${attachment.filename}`:el.messageInput.value.trim();
    if(messageLimits.characterCount(text)>messageLimits.maxCharacters()){toast(`Messages are limited to ${messageLimits.maxCharacters()} characters.`);updateComposerCounter();return;}
    if(!text||!contact||!state.user||!state.deviceKeyPair||!state.localKey){toast('This device is not ready to send encrypted messages.');return;}
    const targets=contact.devices.filter(device=>device.id!==state.device.id);
    if(!targets.length){toast('No active recipient devices are available.');return;}
    el.sendButton.disabled=true;let persisted=false;
    try{
      const keyStatus=await deriveCandidateConversationKeys(contact);renderPeerKeyControls(contact,keyStatus.devices);
      if(keyStatus.missing||targets.some(device=>!state.conversationKeys.get(`${contact.id}:${device.id}`)?.trusted)){setConnected();throw new Error('A recipient device key is missing, changed, or not fingerprint-verified. Compare and confirm every current fingerprint before sending.');}
      const id=crypto.randomUUID(),createdAt=new Date().toISOString(),envelopes=[];
      for(const device of targets){
        const peer=state.conversationKeys.get(`${contact.id}:${device.id}`);
        const metadata={conversationId:contact.id,messageId:id,senderUserId:state.user.id,senderDeviceId:state.device.id,recipientUserId:contact.id,recipientDeviceId:device.id};
        const content={version:1,text,conversation_id:contact.id,sender_user_id:state.user.id,sender_device_id:state.device.id,recipient_user_id:contact.id,recipient_device_id:device.id};if(attachment)content.attachment={transfer_id:attachment.transferId,filename:attachment.filename,content_type:attachment.contentType,size:attachment.size};const encrypted=await window.SereinDeviceCrypto.encryptMessage(peer.key,JSON.stringify(content),metadata);
        envelopes.push({to:device.id,iv:encrypted.iv,ciphertext:encrypted.ciphertext});
      }
      await storeLocalMessage(contact.id,id,{text,sender:state.name,mine:true,envelopes,attachment},'pending',createdAt);persisted=true;state.seenIds.add(id);rememberMessage(contact,text,true,state.name,id,createdAt,'pending',attachment);contact.lastPreview=attachment?`📎 ${attachment.filename}`:`You: ${text.slice(0,48)}`;saveContacts();if(!attachment){el.messageInput.value='';state.drafts[contact.id]='';updateComposerCounter();}
      state.pendingSends.set(id,{expected:envelopes.length,accepted:new Set(),contactId:contact.id});
      let accepted=0;
      for(const envelope of envelopes){
        await api('/api/v1/messages',{method:'POST',body:JSON.stringify({id,to:envelope.to,iv:envelope.iv,ciphertext:envelope.ciphertext})});
        accepted++;state.pendingSends.get(id)?.accepted.add(envelope.to);
      }
      await updateLocalMessageStatus(id,'accepted');state.pendingSends.delete(id);const item=(state.messages[contact.id]||[]).find(value=>value.id===id);if(item)item.status='accepted';if(state.selected?.id===contact.id){el.messageList.replaceChildren();(state.messages[contact.id]||[]).forEach(paintMessage);}toast(`Encrypted message accepted by ${accepted} recipient device${accepted===1?'':'s'}.`);return true;
    }catch(error){if(persisted)toast(`Encrypted message saved locally; delivery will retry: ${error.message}`);else toast(`Message was not sent: ${error.message}`);return false;}
    finally{setConnected();el.messageInput.focus();}
  }
  async function encryptAndUploadAttachment(file){
    const contact=state.selected;if(!contact||!state.user||!state.deviceKeyPair||!state.localKey)throw new Error('Select a contact and finish device-key setup before attaching a file.');
    if(!file||file.size<0)throw new Error('The selected file is unavailable.');
    const transferId=crypto.randomUUID(),chunkCount=Math.max(1,Math.ceil(file.size/TRANSFER_CHUNK_PLAINTEXT)),cipherBytes=file.size+chunkCount*16;
    if(chunkCount>MAX_TRANSFER_CHUNKS||cipherBytes>MAX_TRANSFER_CIPHERTEXT_BYTES)throw new Error('This file exceeds the encrypted-transfer limit (about 64 MiB).');
    const keyStatus=await deriveCandidateConversationKeys(contact);if(keyStatus.missing||!keyStatus.total)throw new Error('Every active recipient device must publish a public key before receiving encrypted files.');
    const targets=contact.devices.filter(device=>device.id!==state.device.id);
    if(!targets.length||targets.some(device=>!state.conversationKeys.get(`${contact.id}:${device.id}`)?.trusted))throw new Error('Compare and verify every recipient-device fingerprint before sending a file.');
    const envelopeKeys=[];const selfKey=await window.SereinDeviceCrypto.deriveCandidateConversationKey(state.deviceKeyPair.privateKey,state.user.id,state.device.id,state.user.id,state.device.id,state.deviceKeyPair.publicJwk);
    envelopeKeys.push({deviceId:state.device.id,userId:state.user.id,key:selfKey});
    for(const device of targets)envelopeKeys.push({deviceId:device.id,userId:contact.id,key:state.conversationKeys.get(`${contact.id}:${device.id}`).key});
    const metadata={transferId,senderUserId:state.user.id,senderDeviceId:state.device.id,recipientUserId:contact.id,recipientDeviceId:state.device.id};
    const contentKey=await window.SereinDeviceCrypto.generateTransferKey(),noncePrefix=crypto.getRandomValues(new Uint8Array(4));
    const filename=safeAttachmentName(file.name),contentType=(file.type||'application/octet-stream').slice(0,128),manifest={version:1,transfer_id:transferId,filename,content_type:contentType,size:file.size,chunk_count:chunkCount,content_key:window.SereinDeviceCrypto.encodeBase64(contentKey.rawKey),nonce_prefix:window.SereinDeviceCrypto.encodeBase64(noncePrefix)};
    const deviceEnvelopes=[];try{for(const target of envelopeKeys){const envelope=await window.SereinDeviceCrypto.encryptTransferManifest(target.key,manifest,{...metadata,recipientDeviceId:target.deviceId});deviceEnvelopes.push({device_id:target.deviceId,iv:envelope.iv,ciphertext:envelope.ciphertext});}}finally{contentKey.rawKey.fill(0);}
    let created=false,complete=false;const attachButton=$('attachBtn');attachButton.disabled=true;attachButton.textContent='…';
    try{
      await api('/api/v1/transfers',{method:'POST',body:JSON.stringify({id:transferId,recipient_user_id:contact.id,chunk_count:chunkCount,total_ciphertext_bytes:cipherBytes,device_envelopes:deviceEnvelopes})});created=true;
      const chunkMetadata={transferId,senderUserId:state.user.id,senderDeviceId:state.device.id,recipientUserId:contact.id,recipientDeviceId:targets[0].id};
      for(let index=0;index<chunkCount;index++){
        const start=index*TRANSFER_CHUNK_PLAINTEXT,end=Math.min(file.size,start+TRANSFER_CHUNK_PLAINTEXT),plain=new Uint8Array(await file.slice(start,end).arrayBuffer()),iv=window.SereinDeviceCrypto.transferChunkIv(noncePrefix,index),encrypted=await window.SereinDeviceCrypto.encryptTransferChunk(contentKey.key,plain,chunkMetadata,index,chunkCount,iv),digest=await window.SereinDeviceCrypto.sha256Hex(encrypted.ciphertext);
        const uploaded=await transferRequest(`/api/v1/transfers/${encodeURIComponent(transferId)}/chunks/${index}`,{method:'PUT',headers:{'Content-Type':'application/octet-stream','X-Chunk-SHA256':digest},body:encrypted.ciphertext});await uploaded.arrayBuffer();
        const progress=Math.min(100,Math.round((index+1)*100/chunkCount));attachButton.title=`Encrypted upload ${progress}%`;attachButton.setAttribute('aria-label',`Encrypted file upload ${progress}%`);
      }
      complete=true;contentKey.rawKey.fill(0);const attachment={transferId,filename,contentType,size:file.size,senderDeviceId:state.device.id};const sent=await sendMessage(null,attachment,contact);
      if(!sent){toast('Encrypted transfer completed, but its chat notice was not accepted. The recipient has not been notified.');return;}
      toast(`Encrypted file sent to ${targets.length} recipient device${targets.length===1?'':'s'}.`);
    }catch(error){if(created&&!complete){try{await api(`/api/v1/transfers/${encodeURIComponent(transferId)}`,{method:'DELETE'});}catch{}}throw error;}
    finally{attachButton.disabled=false;attachButton.textContent='＋';attachButton.title='Send an encrypted file';attachButton.setAttribute('aria-label','Send an encrypted file');}
  }
  async function openEncryptedAttachment(item){
    const attachment=item.attachment;if(!attachment||!state.user||!state.device)throw new Error('This encrypted file is not ready on the current session.');
    const records=await api('/api/v1/transfers');const transfer=Array.isArray(records)?records.find(row=>row.id===attachment.transferId):null;if(!transfer||!transfer.ready_at)throw new Error('The encrypted transfer is not complete or is no longer available.');
    if(transfer.recipient_user_id!==state.user.id&&transfer.sender_user_id!==state.user.id)throw new Error('Transfer account binding did not match this session.');
    let key;if(transfer.sender_user_id===state.user.id){if(transfer.sender_device_id!==state.device.id)throw new Error('This transfer belongs to a different sending device.');key=await window.SereinDeviceCrypto.deriveCandidateConversationKey(state.deviceKeyPair.privateKey,state.user.id,state.device.id,state.user.id,state.device.id,state.deviceKeyPair.publicJwk);}else{
      const contact=state.contacts.find(row=>row.id===transfer.sender_user_id);if(!contact)throw new Error('The sender must be an accepted contact.');let peer=state.conversationKeys.get(`${contact.id}:${transfer.sender_device_id}`);if(!peer){await deriveCandidateConversationKeys(contact);peer=state.conversationKeys.get(`${contact.id}:${transfer.sender_device_id}`);}if(!peer?.trusted)throw new Error('Verify the sending device fingerprint before decrypting this attachment.');key=peer.key;
    }
    const routing={transferId:transfer.id,senderUserId:transfer.sender_user_id,senderDeviceId:transfer.sender_device_id,recipientUserId:transfer.recipient_user_id,recipientDeviceId:state.device.id};
    const manifest=await window.SereinDeviceCrypto.decryptTransferManifest(key,{version:1,algorithm:'AES-256-GCM',iv:transfer.manifest_iv,ciphertext:transfer.manifest_ciphertext},routing);
    if(manifest?.version!==1||manifest.transfer_id!==transfer.id||!Number.isSafeInteger(manifest.size)||manifest.size<0||manifest.size>MAX_TRANSFER_CIPHERTEXT_BYTES||!Number.isInteger(manifest.chunk_count)||manifest.chunk_count<1||manifest.chunk_count>MAX_TRANSFER_CHUNKS||manifest.chunk_count!==transfer.chunk_count||manifest.filename!==attachment.filename||manifest.content_type!==attachment.contentType||manifest.size!==attachment.size)throw new Error('Encrypted manifest did not match the signed-in chat notice or transfer limits.');
    const rawKey=window.SereinDeviceCrypto.decodeStandardBase64(manifest.content_key),prefix=window.SereinDeviceCrypto.decodeStandardBase64(manifest.nonce_prefix);if(rawKey.length!==32||prefix.length!==4)throw new Error('Encrypted manifest has an invalid content key or nonce prefix.');const fileKey=await window.SereinDeviceCrypto.importTransferKey(rawKey);rawKey.fill(0);
    const chunkMetadata={transferId:transfer.id,senderUserId:transfer.sender_user_id,senderDeviceId:transfer.sender_device_id,recipientUserId:transfer.recipient_user_id,recipientDeviceId:state.device.id},parts=[];let clearBytes=0;
    for(let index=0;index<manifest.chunk_count;index++){
      const response=await transferRequest(`/api/v1/transfers/${encodeURIComponent(transfer.id)}/chunks/${index}`),ciphertext=new Uint8Array(await response.arrayBuffer()),expected=response.headers.get('X-Chunk-SHA256');if(!expected||await window.SereinDeviceCrypto.sha256Hex(ciphertext)!==expected.toLowerCase())throw new Error(`Encrypted chunk ${index+1} failed its transport checksum.`);
      const iv=window.SereinDeviceCrypto.transferChunkIv(prefix,index),plaintext=new Uint8Array(await window.SereinDeviceCrypto.decryptTransferChunk(fileKey,iv,ciphertext,chunkMetadata,index,manifest.chunk_count));clearBytes+=plaintext.length;if(clearBytes>manifest.size)throw new Error('Decrypted file exceeds its authenticated manifest size.');parts.push(plaintext);
    }
    if(clearBytes!==manifest.size)throw new Error('Decrypted file size did not match its authenticated manifest.');const blob=new Blob(parts,{type:manifest.content_type||'application/octet-stream'});triggerBrowserDownload(blob,manifest.filename);await api(`/api/v1/transfers/${encodeURIComponent(transfer.id)}/ack`,{method:'POST',body:'{}'});return true;
  }
  function triggerBrowserDownload(blob,filename){const url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=filename;link.hidden=true;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),60_000);}
  async function addContact(event){event.preventDefault();event.preventDefault();const identity=clean(el.contactUsername.value,254).toLowerCase(),email=identity.includes('@');await window.SereinCore?.ready;if(!identity||(!email&&!validLabel(identity,32))||(email&&!/^[a-z0-9_%+-]+(?:\.[a-z0-9_%+-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(identity))){toast('Enter a valid username or email address.');return;}try{const result=await api('/api/v1/contact-requests',{method:'POST',body:JSON.stringify({identity})});await refreshContactRequests();el.contactDialog.close();toast(result.message||'Request received. Check Pending requests.');}catch(error){toast(error.message);}}
  async function blockSelectedAccount(){const contact=state.selected;if(!contact||!confirm(`Block @${contact.username}? This removes the contact link and prevents requests, messages, and transfers. Existing encrypted history is retained.`))return;try{await api(`/api/v1/blocks/${contact.id}`,{method:'PUT'});state.selected=null;state.messages[contact.id]=state.messages[contact.id]||[];$('conversation').classList.add('hidden');$('emptyState').classList.remove('hidden');el.app.classList.remove('chat-open');await Promise.all([refreshContacts(),refreshContactRequests(),refreshBlocks()]);toast('Account blocked. New requests and message delivery are denied.');}catch(e){toast(e.message);}}
  function showSettings(section='profile'){ $('conversation').classList.add('hidden');$('emptyState').classList.add('hidden');$('settings').classList.remove('hidden');if(matchMedia('(max-width: 650px)').matches)el.app.classList.add('chat-open');selectSettings(section);if(section==='devices')refreshDevices();}
  function selectSettings(section){document.querySelectorAll('.settings-nav button[data-section]').forEach(b=>b.classList.toggle('selected',b.dataset.section===section));document.querySelectorAll('.settings-section[data-panel]').forEach(p=>{const active=p.dataset.panel===section;p.classList.toggle('hidden',!active);p.classList.toggle('active',active);});}
  function relativeTime(value){const seconds=Math.max(0,Math.floor((Date.now()-new Date(value).getTime())/1000));if(seconds<60)return `${seconds} seconds ago`;const minutes=Math.floor(seconds/60);if(minutes<60)return `${minutes} minute${minutes===1?'':'s'} ago`;const hours=Math.floor(minutes/60);if(hours<24)return `${hours} hour${hours===1?'':'s'} ago`;const days=Math.floor(hours/24);return `${days} day${days===1?'':'s'} ago`;}
  async function refreshDevices(){const list=$('deviceList');if(list)list.replaceChildren();try{const devices=await api('/api/v1/devices');state.devices=Array.isArray(devices)?devices:[];for(const d of state.devices){if(!list)continue;const row=document.createElement('div');row.className='device-item';const glyph=document.createElement('div');glyph.className='device-glyph';glyph.textContent='▣';const info=document.createElement('div');const name=document.createElement('b');name.textContent=d.name;const seen=document.createElement('span');seen.textContent=d.online?'Online now':`${d.current?'This device · last active':'Last active'} ${relativeTime(d.last_seen_at)}`;info.append(name,seen);row.append(glyph,info);if(d.current){const badge=document.createElement('span');badge.className='current-badge';badge.textContent='CURRENT';row.append(badge);}else{const revoke=document.createElement('button');revoke.className='btn btn-small btn-danger-outline';revoke.textContent='Revoke';revoke.addEventListener('click',async()=>{try{await api(`/api/v1/devices/${d.id}`,{method:'DELETE'});await refreshDevices();toast('Device access revoked.');}catch(e){toast(e.message);}});row.append(revoke);}list.append(row);}return state.devices;}catch(error){if(list)list.textContent=error.message;throw error;}}
  async function terminateOthers(){try{await api('/api/v1/devices/revoke-others',{method:'POST',body:'{}'});await refreshDevices();toast('Other device sessions were revoked.');}catch(error){toast(error.message);}}
  async function disconnect({requireServerRevocation=false}={}){
    if(state.signingOut)return false;
    state.signingOut=true;clearInterval(state.resendTimer);state.resendTimer=0;state.resendUntil=0;state.authMode='signin';
    clearTimeout(state.reconnectTimer);state.reconnectTimer=0;clearInterval(state.heartbeatTimer);
    let serverRevoked=false;try{await api('/api/v1/auth/logout',{method:'POST',body:'{}'});serverRevoked=true;}catch{}
    if(requireServerRevocation&&!serverRevoked){state.signingOut=false;return false;}
    state.socket?.close(1000,'user sign out');state.socket=null;state.user=null;state.device=null;state.localKey=null;state.deviceKeyPair=null;state.deviceKeyFingerprint='';state.conversationKeys.clear();state.peerKeyState='';state.selected=null;state.contacts=[];state.contactRequests=[];state.blocks=[];state.devices=[];state.messages={};state.drafts={};el.messageInput.value='';updateComposerCounter();state.seenIds.clear();state.pendingSends.clear();
    el.login.classList.remove('hidden');el.app.classList.add('hidden');el.app.classList.remove('chat-open');$('authForm').classList.remove('hidden');$('authTabs').classList.remove('hidden');$('authNotice').classList.remove('hidden');$('verificationPanel').classList.add('hidden');authMode('signin');$('conversation').classList.add('hidden');$('settings').classList.add('hidden');
    toast(serverRevoked?'Signed out. Local encrypted message history remains on this device.':'Signed out locally; server session revocation could not be confirmed.');return serverRevoked;
  }
  async function restoreSession(){try{const account=await api('/api/v1/me');state.user=account.user;state.device=account.device;localStorage.setItem('serein.stable-device-id.v1',account.device.id);state.name=account.user.display_name;state.identity=account.user.username;try{await initializeLocalStore();}catch(error){toast(`Local encrypted storage unavailable: ${error.message}`);}try{await ensureDeviceKeyEnrollment();}catch(keyError){state.deviceKeyPair=null;state.deviceKeyFingerprint='';toast(`Device key setup is incomplete; encrypted sending is unavailable: ${keyError.message}`);}await loadAccountSettings();await showAccountApp();}catch{/* No valid session; show sign-in. */}}
  async function startCallPermissionCheck(){const dialog=$('callDialog'),mode=dialog.dataset.mode||'audio';const constraints={audio:true,video:mode==='video'};$('callStatus').textContent=`Requesting ${mode==='video'?'microphone and camera':'microphone'} permission…`;try{if(!navigator.mediaDevices?.getUserMedia)throw new Error('This browser does not expose media permissions. Use a supported browser over HTTPS.');const stream=await navigator.mediaDevices.getUserMedia(constraints);for(const track of stream.getTracks())track.stop();$('callStatus').textContent=`Required permission granted. No call connected: encrypted QUIC media transport and signaling are not integrated.`;}catch(error){const reason=error?.name==='NotAllowedError'||error?.name==='PermissionDeniedError'?'Permission was denied or blocked. Enable the required access in your browser’s site settings, then retry.':error?.name==='NotFoundError'?'A required microphone or camera was not found. Connect or enable the device, then retry.':`Permission check failed: ${error.message||'browser media access unavailable'}. Ensure this page is served over HTTPS, then retry.`;$('callStatus').textContent=reason;}}
  function openCallSetup(mode){if(!state.selected){toast('Select a contact before preparing a call.');return;}const dialog=$('callDialog');dialog.dataset.mode=mode;$('callTitle').textContent=`${mode==='video'?'Video':'Audio'} call · ${state.selected.display_name}`;$('callStatus').textContent=`This device needs ${mode==='video'?'microphone and camera':'microphone'} permission. Retry to continue permission checking.`;dialog.showModal();}
  function init(){loadTheme();$('authTheme').addEventListener('change',e=>setTheme(e.target.value));$('signinTab').addEventListener('click',()=>authMode('signin'));$('registerTab').addEventListener('click',()=>authMode('register'));el.authForm.addEventListener('submit',handleAuthSubmit);['accountPassword','confirmPassword','regName','regHandle','regEmail','loginIdentity'].forEach(id=>$(id).addEventListener('input',updateAuthValidation));document.querySelectorAll('[data-toggle-password]').forEach(button=>button.addEventListener('click',()=>{const input=$(button.dataset.togglePassword),revealed=input.type==='password';input.type=revealed?'text':'password';button.setAttribute('aria-pressed',String(revealed));button.setAttribute('aria-label',`${revealed?'Hide':'Show'} ${button.dataset.togglePassword==='confirmPassword'?'confirmation password':'password'}`);input.focus();}));updateAuthValidation();window.SereinCore?.ready.then(updateAuthValidation);document.querySelectorAll('.otp-digit').forEach(input=>{input.addEventListener('input',handleOtpInput);input.addEventListener('keydown',handleOtpKeydown);input.addEventListener('focus',()=>input.select());});
    $('verificationForm').addEventListener('submit',handleVerificationSubmit);$('resendCode').addEventListener('click',handleResendCode);$('backToVerificationAuth').addEventListener('click',backToAuth);$('authConnectionOpen').addEventListener('click',openConnectionSettings);$('connectionOpen').addEventListener('click',openConnectionSettings);$('connectionSettingsOpen').addEventListener('click',openConnectionSettings);$('connectionClose').addEventListener('click',()=>$('connectionDialog').close());$('connectionForm').addEventListener('submit',saveConnection);$('checkConnection').addEventListener('click',checkServerConnection);$('whatsNewClose').addEventListener('click',closeWhatsNew);$('whatsNewDialog').addEventListener('close',()=>{const version=$('whatsNewDialog').dataset.versionToRemember;if(version)try{localStorage.setItem('serein.whats-new.version',version);}catch{}});
    $('addContact').addEventListener('click',()=>{el.contactForm.reset();el.contactDialog.showModal();});$('emptyAdd').addEventListener('click',()=>{el.contactForm.reset();el.contactDialog.showModal();});$('newChat').addEventListener('click',()=>{el.contactForm.reset();el.contactDialog.showModal();});el.contactForm.addEventListener('submit',addContact);$('requestsOpen').addEventListener('click',()=>{ $('requestDialog').showModal();refreshContactRequests().catch(e=>toast(e.message)); });$('requestClose').addEventListener('click',()=> $('requestDialog').close());$('manageBlocks').addEventListener('click',()=>{ $('blockDialog').showModal();refreshBlocks().catch(e=>toast(e.message)); });$('blockClose').addEventListener('click',()=> $('blockDialog').close());$('blockContact').addEventListener('click',blockSelectedAccount);
    $('search').addEventListener('input',e=>renderContacts(e.target.value));document.querySelectorAll('.filter-chip').forEach(b=>b.addEventListener('click',()=>{state.filter=b.dataset.filter;document.querySelectorAll('.filter-chip').forEach(x=>x.classList.toggle('active',x===b));renderContacts($('search').value);}));
    $('messageForm').addEventListener('submit',sendMessage);el.messageInput.addEventListener('input',handleComposerInput);el.messageInput.addEventListener('compositionend',()=>handleComposerInput({isComposing:false}));el.messageInput.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey&&MESSAGING_ENABLED){e.preventDefault();$('messageForm').requestSubmit();}});
    $('settingsOpen').addEventListener('click',()=>showSettings());$('settingsBack').addEventListener('click',()=>{$('settings').classList.add('hidden');if(state.selected){$('conversation').classList.remove('hidden');el.app.classList.add('chat-open');}else{$('emptyState').classList.remove('hidden');el.app.classList.remove('chat-open');}});document.querySelectorAll('.settings-nav button[data-section]').forEach(b=>b.addEventListener('click',()=>showSettings(b.dataset.section)));
    document.querySelectorAll('[data-theme-choice]').forEach(b=>b.addEventListener('click',()=>setTheme(b.dataset.themeChoice)));$('fontScale').addEventListener('change',e=>{document.documentElement.dataset.fontScale=e.target.value;persistSettings({font_scale:e.target.value});});$('presenceVisibility').addEventListener('change',e=>persistSettings({presence_visibility:e.target.value}));$('allowContactRequests').addEventListener('click',e=>{const enabled=e.currentTarget.getAttribute('aria-pressed')!=='true';setPrivacySwitch('allowContactRequests',enabled);persistSettings({allow_contact_requests:enabled});});$('discoverableByEmail').addEventListener('click',e=>{const enabled=e.currentTarget.getAttribute('aria-pressed')!=='true';setPrivacySwitch('discoverableByEmail',enabled);persistSettings({discoverable_by_email:enabled});});$('motionToggle').addEventListener('click',e=>{const on=e.currentTarget.classList.toggle('on');document.documentElement.classList.toggle('reduce-motion',on);persistSettings({reduce_motion:on});});$('notificationToggle').addEventListener('click',async(e)=>{const toggle=e.currentTarget;if(!('Notification'in window)){toast('Browser notifications are unavailable.');return;}const p=await Notification.requestPermission();const enabled=p==='granted';toggle.classList.toggle('on',enabled);persistSettings({notifications:enabled});toast(enabled?'Notification preference saved; push delivery is not configured.':'Notification permission not granted.');});
    $('logout').addEventListener('click',disconnect);$('disconnectDevice').addEventListener('click',disconnect);$('revokeOthers').addEventListener('click',terminateOthers);$('chatInfo').addEventListener('click',()=>state.selected&&toast(`@${state.selected.username} · email ${state.selected.verified?'verified':'unverified'}`));$('chatMenu').addEventListener('click',()=>{if(!state.selected)return;state.selected.favorite=!state.selected.favorite;saveContacts();toast(state.selected.favorite?'Added to favorites.':'Removed from favorites.');});$('dismissBanner').addEventListener('click',()=>document.querySelector('.security-banner').classList.add('hidden'));$('attachBtn').addEventListener('click',()=>{if(!state.selected){toast('Open a conversation before attaching a file.');return;}if(!state.deviceKeyPair||!state.localKey){toast('This device is not ready for encrypted file transfers.');return;}$('filePicker').click();});$('filePicker').addEventListener('change',async event=>{const file=event.target.files?.[0];event.target.value='';if(!file)return;try{await encryptAndUploadAttachment(file);}catch(error){toast(`Encrypted upload failed: ${error.message}`);}});for(const b of document.querySelectorAll('.call-btn'))b.addEventListener('click',()=>openCallSetup(b.dataset.callMode));$('callRetry').addEventListener('click',startCallPermissionCheck);$('callClose').addEventListener('click',()=>$('callDialog').close());$('callCancel').addEventListener('click',()=>$('callDialog').close());$('mobileBack').addEventListener('click',()=>{el.app.classList.remove('chat-open');$('conversation').classList.add('hidden');$('emptyState').classList.remove('hidden');});$('clearContacts').addEventListener('click',async()=>{if(!confirm('Remove all contacts? This removes contact entries from both accounts but does not delete stored message history.'))return;for(const c of [...state.contacts]){try{await api(`/api/v1/contacts/${c.user_id}`,{method:'DELETE'});}catch{}}state.contacts=[];saveContacts();toast('All contact entries removed from both accounts; message history was retained.');});
    $('authNotice').classList.add('visible');renderContacts();setTimeout(showWhatsNewIfNeeded,350);restoreSession();setInterval(()=>{if(state.user){refreshContacts().catch(()=>{});refreshContactRequests().catch(()=>{});refreshDevices().catch(()=>{});syncServerHistory().catch(()=>{});resendPendingMessages().catch(()=>{});}},30000);
  }
  init();
})();
