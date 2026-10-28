"""WristGPT personal local bridge. OAuth tokens never leave this computer."""
from __future__ import annotations
import base64, ctypes, datetime, hashlib, hmac, http.server, ipaddress, json
import os, pathlib, secrets, socket, ssl, sys, threading, time, urllib.error
import urllib.parse, urllib.request, uuid, webbrowser
from ctypes import wintypes
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import jwt

ROOT = pathlib.Path(__file__).resolve().parent
STATE = pathlib.Path(os.environ.get('WRISTGPT_STATE', str(ROOT / '.private')))
API = 'https://api.openai.com/v1'
ISSUER = 'https://auth.openai.com'
TOKEN = ISSUER + '/api/accounts/oauth/token'
SCOPES = 'openid profile email offline_access resource.invoke chatgpt.tokens.use.direct'
AUTH_LOCK = threading.RLock()
ASK_LOCK = threading.Lock()
ATTEMPTS = {}
CSRF = secrets.token_urlsafe(32)
ADMIN_PORT = int(os.environ.get('WRISTGPT_ADMIN_PORT', '8765'))
WATCH_PORT = int(os.environ.get('WRISTGPT_WATCH_PORT', '8443'))
REDIRECT = f'http://127.0.0.1:{ADMIN_PORT}/auth/callback'
MAX_BODY = 65536

def pack(data):
    return json.dumps(data, ensure_ascii=False).encode('utf-8')

def atomic(path, data):
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_bytes(data)
    if os.name != 'nt': temp.chmod(0o600)
    os.replace(temp, path)

class Blob(ctypes.Structure):
    _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_ubyte))]

def dpapi(data, protect):
    if os.name != 'nt':
        raise RuntimeError('Этот мост использует Windows DPAPI. Запустите его на Windows.')
    buffer = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    result = Blob()
    lib = ctypes.WinDLL('crypt32', use_last_error=True)
    if protect:
        ok = lib.CryptProtectData(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(result))
    else:
        ok = lib.CryptUnprotectData(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(result))
    if not ok: raise ctypes.WinError(ctypes.get_last_error())
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    try: return ctypes.string_at(result.pbData, result.cbData)
    finally: kernel.LocalFree(result.pbData)

def read_auth():
    path = STATE / 'accounts.enc'
    return json.loads(dpapi(path.read_bytes(), False)) if path.exists() else {'profiles': {}, 'active': None}

def save_auth(data): atomic(STATE / 'accounts.enc', dpapi(pack(data), True))

def request_json(url, data=None, bearer=None, form=False):
    headers = {'Accept': 'application/json', 'User-Agent': 'WristGPT/1.0'}
    if bearer: headers['Authorization'] = 'Bearer ' + bearer
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode() if form else pack(data)
        headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers), timeout=90) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        # Never include response bodies or credentials in logs/UI.
        if e.code == 401: raise RuntimeError('Сеанс истёк. Войдите в ChatGPT ещё раз.') from None
        if e.code == 429: raise RuntimeError('Достигнут лимит. Проверьте использование подписки в ChatGPT.') from None
        raise RuntimeError(f'OpenAI вернул HTTP {e.code}. Проверьте доступ к интеграции и повторите вход.') from None

def session_info():
    with AUTH_LOCK:
        auth = read_auth()
        active = auth['profiles'].get(auth['active'], {})
        return {'connected': bool(active.get('access_token')),
                'sharing': 'chatgpt.tokens.use.direct' in active.get('scopes', []),
                'email': active.get('email', ''), 'active': auth['active'],
                'profiles': [{'id': key, 'email': value.get('email', 'ChatGPT'),
                              'connected': bool(value.get('access_token'))}
                             for key, value in auth['profiles'].items()]}

def start_login(new=False):
    with AUTH_LOCK:
        auth = read_auth()
        selected = None if new else auth['active']
        profile = auth['profiles'].get(selected, {})
        verifier = secrets.token_urlsafe(64)
        state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        for key in list(ATTEMPTS):
            if time.time() - ATTEMPTS[key]['time'] > 600: ATTEMPTS.pop(key)
        if len(ATTEMPTS) > 8: raise RuntimeError('Завершите открытые попытки входа.')
        ATTEMPTS[state] = {'verifier': verifier, 'nonce': nonce, 'time': time.time(),
                           'selected': selected, 'client': profile.get('client_id')}
        params = {'client_id': profile.get('client_id', 'dynamic_agent_client'),
                  'ext_agent_host_id': META['host_id'], 'response_type': 'code',
                  'redirect_uri': REDIRECT, 'scope': SCOPES, 'resource': API,
                  'state': state, 'nonce': nonce, 'code_challenge_method': 'S256',
                  'code_challenge': challenge}
        if not profile.get('client_id'): params['agent_name_hint'] = 'WristGPT'
        if profile.get('id_token'): params['id_token_hint'] = profile['id_token']
        if profile.get('email'): params['login_hint'] = profile['email']
        return ISSUER + '/api/accounts/authorize?' + urllib.parse.urlencode(params)

def finish_login(query):
    state = query.get('state', [''])[0]
    with AUTH_LOCK:
        attempt = ATTEMPTS.pop(state, None)
        if not attempt or time.time() - attempt['time'] > 600:
            raise RuntimeError('Попытка входа истекла или state не совпал. Начните заново.')
        if query.get('error'): raise RuntimeError('Вход отменён или разрешение не предоставлено.')
        client = query.get('client_id', [attempt['client']])[0]
        if not client or client == 'dynamic_agent_client': raise RuntimeError('Регистрация не вернула client_id.')
        if attempt['client'] and client != attempt['client']: raise RuntimeError('client_id не совпал.')
        code = query.get('code', [''])[0]
        if not code: raise RuntimeError('Не получен код авторизации.')
        auth = read_auth()
        old = auth['profiles'].get(client, {})
        # Retain issued registration even if exchange/validation fails.
        auth['profiles'][client] = {**old, 'client_id': client}
        if not auth['active']: auth['active'] = client
        save_auth(auth)
        tokens = request_json(TOKEN, {'grant_type': 'authorization_code', 'client_id': client,
                    'code': code, 'code_verifier': attempt['verifier'], 'redirect_uri': REDIRECT,
                    'resource': API}, form=True)
        discovery = request_json(ISSUER + '/.well-known/openid-configuration')
        if discovery.get('issuer') != ISSUER: raise RuntimeError('Неожиданный issuer.')
        jwks_url = discovery['jwks_uri']
        if urllib.parse.urlsplit(jwks_url).hostname != 'auth.openai.com': raise RuntimeError('Неожиданный JWKS host.')
        signing_key = jwt.PyJWKClient(jwks_url).get_signing_key_from_jwt(tokens['id_token'])
        claims = jwt.decode(tokens['id_token'], signing_key.key, algorithms=['RS256','ES256'],
                            audience=client, issuer=ISSUER, options={'require': ['exp','iat','sub','nonce']})
        if not hmac.compare_digest(str(claims['nonce']), attempt['nonce']): raise RuntimeError('Nonce не совпал.')
        if old.get('subject') and old['subject'] != claims['sub']: raise RuntimeError('Это другой аккаунт. Добавьте его отдельно.')
        profile = {'client_id': client, 'subject': claims['sub'], 'issuer': claims['iss'],
                   'email': claims.get('email', 'ChatGPT'), 'access_token': tokens.get('access_token'),
                   'refresh_token': tokens.get('refresh_token'), 'id_token': tokens['id_token'],
                   'expires_at': time.time() + int(tokens.get('expires_in', 3600)),
                   'scopes': tokens.get('scope', '').split()}
        auth['profiles'][client] = profile
        auth['active'] = client
        save_auth(auth)

def access_token():
    with AUTH_LOCK:
        auth = read_auth()
        p = auth['profiles'].get(auth['active'], {})
        if not p.get('access_token'): raise RuntimeError('Сначала войдите в ChatGPT на компьютере.')
        if 'chatgpt.tokens.use.direct' not in p.get('scopes', []):
            raise RuntimeError('Разрешите использование подписки при входе в ChatGPT.')
        if time.time() > p.get('expires_at', 0) - 90:
            if not p.get('refresh_token'): raise RuntimeError('Войдите в ChatGPT повторно.')
            t = request_json(TOKEN, {'grant_type':'refresh_token', 'client_id':p['client_id'],
                             'refresh_token':p['refresh_token'], 'resource':API}, form=True)
            p.update(access_token=t['access_token'], refresh_token=t.get('refresh_token', p['refresh_token']),
                     expires_at=time.time() + int(t.get('expires_in',3600)),
                     scopes=t.get('scope',' '.join(p['scopes'])).split())
            if t.get('id_token'): p['id_token'] = t['id_token']
            save_auth(auth)
        return p['access_token']

def models(bearer=None):
    result = request_json(API + '/models', bearer=bearer or access_token())
    return [{'id':m['slug'], 'name':m.get('display_name',m['slug'])}
            for m in result.get('models', []) if m.get('visibility') == 'list' and m.get('slug')]

def parse_stream(lines):
    chunks, answer, completed = [], [], False
    def event(raw):
        nonlocal completed, answer
        if not raw or raw == '[DONE]': return
        data = json.loads(raw)
        kind = data.get('type')
        if kind == 'response.output_text.delta': answer.append(data.get('delta',''))
        if kind == 'response.completed':
            completed = True
            if not answer:
                for item in data.get('response',{}).get('output',[]):
                    for part in item.get('content',[]):
                        if part.get('type') == 'output_text': answer.append(part.get('text',''))
        if kind in ('error','response.failed','response.incomplete'):
            error = data.get('response',{}).get('error') or data.get('error') or {}
            code = error.get('code','') if isinstance(error,dict) else ''
            if 'usage' in code or 'limit' in code:
                raise RuntimeError('Лимит подписки. Откройте ChatGPT → Настройки → Использование.')
            raise RuntimeError('Ответ прерван или отклонён. Повторите запрос.')
    for line in lines:
        line = line.decode('utf-8').rstrip('\r\n') if isinstance(line, bytes) else line.rstrip('\r\n')
        if not line:
            event('\n'.join(chunks)); chunks = []
        elif line.startswith('data:'): chunks.append(line[5:].lstrip())
    if chunks: event('\n'.join(chunks))
    if not completed: raise RuntimeError('Соединение прервалось до завершения ответа.')
    text = ''.join(answer).strip()
    if not text: raise RuntimeError('Модель вернула пустой ответ.')
    return text

def ask(data):
    if not ASK_LOCK.acquire(blocking=False): raise RuntimeError('Другой вопрос ещё обрабатывается.')
    try:
        history = data.get('messages', [])
        if not isinstance(history,list) or not history or len(history)>24:
            raise RuntimeError('Некорректная история. Начните новый диалог.')
        for message in history:
            if not isinstance(message,dict) or message.get('role') not in ('user','assistant') or not isinstance(message.get('content'),str):
                raise RuntimeError('Некорректное сообщение.')
            if len(message['content'])>12000: raise RuntimeError('Слишком длинное сообщение.')
        bearer = access_token()
        available = models(bearer)
        selected = data.get('model') or (available[0]['id'] if available else None)
        if selected not in [m['id'] for m in available]: raise RuntimeError('Выберите доступную модель в настройках.')
        payload = {'model':selected,'input':history,'store':False,'stream':True,
                   'instructions':'Отвечай на языке пользователя. Ответ читают на Apple Watch: будь краток, обычно до 100 слов. Если просят подробно, ответь подробно. Не выдумывай факты.'}
        req = urllib.request.Request(API+'/responses', data=pack(payload), headers={
            'Authorization':'Bearer '+bearer,'Content-Type':'application/json','Accept':'text/event-stream'})
        try:
            with urllib.request.urlopen(req,timeout=150) as response: text = parse_stream(response)
        except urllib.error.HTTPError as e:
            if e.code == 429: raise RuntimeError('Лимит подписки. Проверьте использование в ChatGPT.') from None
            if e.code == 401: raise RuntimeError('Войдите в ChatGPT повторно на компьютере.') from None
            raise RuntimeError(f'OpenAI вернул HTTP {e.code}.') from None
        return {'text':text,'model':selected}
    finally: ASK_LOCK.release()

def sign_out():
    confirmed = True
    with AUTH_LOCK:
        auth = read_auth(); p = auth['profiles'].get(auth['active'],{})
        if p.get('refresh_token'):
            try:
                discovery = request_json(ISSUER+'/.well-known/openid-configuration')
                endpoint = discovery['revocation_endpoint']
                if urllib.parse.urlsplit(endpoint).hostname != 'auth.openai.com': raise RuntimeError('Issuer')
                request_json(endpoint,{'token':p['refresh_token'],'token_type_hint':'refresh_token','client_id':p['client_id']},form=True)
            except Exception: confirmed = False
        for key in ('access_token','refresh_token','id_token','expires_at','scopes'): p.pop(key,None)
        save_auth(auth)
    return {'revoked':confirmed}

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'WristGPT'
    def log_message(self,*args): pass
    def send(self,code,data,kind='application/json; charset=utf-8'):
        raw = data.encode() if isinstance(data,str) else pack(data)
        self.send_response(code); self.send_header('Content-Type',kind)
        self.send_header('Content-Length',str(len(raw))); self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
        self.end_headers()
        try: self.wfile.write(raw)
        except (BrokenPipeError,ConnectionResetError): pass
    def body(self):
        n=int(self.headers.get('Content-Length','0'))
        if n<1 or n>MAX_BODY: raise RuntimeError('Недопустимый размер запроса.')
        data=json.loads(self.rfile.read(n))
        if not isinstance(data,dict): raise RuntimeError('Ожидается JSON object.')
        return data
    def allowed(self):
        if self.server.admin:
            if self.headers.get('Host') != f'127.0.0.1:{ADMIN_PORT}': return False
            origin=self.headers.get('Origin')
            if origin and origin != f'http://127.0.0.1:{ADMIN_PORT}': return False
            return self.command=='GET' and self.path in ('/','/favicon.ico') or hmac.compare_digest(self.headers.get('X-Wrist-CSRF',''),CSRF)
        return hmac.compare_digest(self.headers.get('Authorization',''), 'Bearer '+META['pair_token'])
    def do_GET(self):
        path=urllib.parse.urlsplit(self.path)
        if self.server.admin and path.path=='/auth/callback':
            if self.headers.get('Host')!=f'127.0.0.1:{ADMIN_PORT}': return self.send(403,{'error':'Host'})
            try: finish_login(urllib.parse.parse_qs(path.query)); self.send(200,'<meta charset="utf-8"><p>WristGPT: вход завершён. Вернитесь в приложение.</p><a href="/">Открыть WristGPT</a>','text/html; charset=utf-8')
            except Exception as e: self.send(400,'<meta charset="utf-8"><p>Вход не завершён. Вернитесь в WristGPT и повторите вход.</p><a href="/">WristGPT</a>','text/html; charset=utf-8')
            return
        if not self.allowed(): return self.send(403,{'error':'Доступ запрещён.'})
        try:
            if path.path=='/' and self.server.admin:
                return self.send(200,(ROOT/'dashboard.html').read_text(encoding='utf-8').replace('__CSRF__',CSRF),'text/html; charset=utf-8')
            if path.path=='/api/session': return self.send(200,session_info())
            if path.path=='/api/models': return self.send(200,{'models':models()})
            if path.path=='/api/pair' and self.server.admin:
                host=urllib.parse.parse_qs(path.query).get('host',[lan_ip()])[0]
                ipaddress.ip_address(host)
                return self.send(200,{'url':f'https://{host}:{WATCH_PORT}', 'token':META['pair_token'],'fingerprint':FINGERPRINT})
            return self.send(404,{'error':'Не найдено.'})
        except Exception as e: self.send(400,{'error':safe_error(e)})
    def do_POST(self):
        if not self.allowed(): return self.send(403,{'error':'Доступ запрещён.'})
        try:
            data=self.body()
            if self.path=='/api/ask': return self.send(200,ask(data))
            if not self.server.admin: return self.send(404,{'error':'Не найдено.'})
            if self.path=='/api/login': return self.send(200,{'url':start_login(bool(data.get('new')))})
            if self.path=='/api/logout': return self.send(200,sign_out())
            if self.path=='/api/select':
                with AUTH_LOCK:
                    auth=read_auth()
                    if data.get('id') not in auth['profiles']: raise RuntimeError('Неизвестный аккаунт.')
                    auth['active']=data['id']; save_auth(auth)
                return self.send(200,session_info())
            return self.send(404,{'error':'Не найдено.'})
        except Exception as e: self.send(400,{'error':safe_error(e)})

def safe_error(e):
    return str(e) if isinstance(e,RuntimeError) else 'Не удалось выполнить запрос. Проверьте сеть и повторите попытку.'

def lan_ip():
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.connect(('1.1.1.1',80)); return s.getsockname()[0]
    except OSError: return '127.0.0.1'

def initialize():
    global META,FINGERPRINT
    STATE.mkdir(parents=True,exist_ok=True)
    meta_path=STATE/'device.enc'
    if meta_path.exists(): META=json.loads(dpapi(meta_path.read_bytes(),False))
    else:
        META={'host_id':'urn:uuid:'+str(uuid.uuid4()),'pair_token':secrets.token_urlsafe(48)}
        atomic(meta_path,dpapi(pack(META),True))
    cert_path,key_path=STATE/'certificate.pem',STATE/'key.enc'
    if not cert_path.exists() or not key_path.exists():
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'WristGPT Personal Bridge')])
        now=datetime.datetime.now(datetime.timezone.utc)
        cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(now+datetime.timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).sign(key,hashes.SHA256())
        atomic(cert_path,cert.public_bytes(serialization.Encoding.PEM))
        atomic(key_path,dpapi(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),True))
    cert=x509.load_pem_x509_certificate(cert_path.read_bytes())
    FINGERPRINT=cert.fingerprint(hashes.SHA256()).hex()
    # SSLContext requires a filename; remove the transient key immediately after loading.
    transient=STATE/('tls-'+secrets.token_hex(8)+'.tmp')
    atomic(transient,dpapi(key_path.read_bytes(),False))
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    try: ctx.load_cert_chain(str(cert_path),str(transient))
    finally: transient.unlink(missing_ok=True)
    return ctx

def main():
    context=initialize()
    admin=http.server.ThreadingHTTPServer(('127.0.0.1',ADMIN_PORT),Handler); admin.admin=True
    watch=http.server.ThreadingHTTPServer(('0.0.0.0',WATCH_PORT),Handler); watch.admin=False
    watch.socket=context.wrap_socket(watch.socket,server_side=True)
    threading.Thread(target=watch.serve_forever,daemon=True).start()
    print(f'WristGPT: http://127.0.0.1:{ADMIN_PORT}',flush=True)
    print('Для остановки закройте окно или нажмите Ctrl+C.',flush=True)
    if '--no-browser' not in sys.argv: webbrowser.open(f'http://127.0.0.1:{ADMIN_PORT}')
    try: admin.serve_forever()
    except KeyboardInterrupt: pass
    finally: admin.server_close(); watch.shutdown(); watch.server_close()

if __name__=='__main__': main()
