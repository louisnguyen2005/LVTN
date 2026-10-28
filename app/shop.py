"""Deliberately vulnerable training shop. Keep it inside the CTF lab network."""
from contextlib import contextmanager
import hashlib
import hmac
from html import escape
from http import HTTPStatus
from http.cookies import SimpleCookie,CookieError
import json
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
from urllib.parse import parse_qs,urlsplit

VULNERABILITIES=('sqli','captcha_bypass','xss','csrf','brute_force')
WEAK_PASSWORDS=tuple(f'market{i:02d}' for i in range(32))


def password_hash(password,salt):
    return hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),120000).hex()


def create_app(database,password,sandbox_id,service_id='shop01',vulnerabilities=None,merchant_password=None,enforce_owner=False):
    if not sandbox_id or not service_id or not password:raise ValueError('Shop identity and initial customer password required')
    enabled={key:True for key in VULNERABILITIES}
    if vulnerabilities is not None:
        if set(vulnerabilities)-set(enabled) or any(type(v) is not bool for v in vulnerabilities.values()):
            raise ValueError('Unknown vulnerability switch or nonboolean value')
        enabled.update(vulnerabilities)
    path=Path(database);path.parent.mkdir(parents=True,exist_ok=True)
    @contextmanager
    def connect():
        db=sqlite3.connect(path,timeout=5);db.row_factory=sqlite3.Row
        try:
            db.execute('PRAGMA foreign_keys=ON');yield db;db.commit()
        except BaseException:db.rollback();raise
        finally:db.close()
    with connect() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY,salt TEXT,digest TEXT,role TEXT,wallet INTEGER);
        CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,name TEXT,price INTEGER,description TEXT);
        CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY,owner TEXT REFERENCES users(username),product_id INTEGER,
          quantity INTEGER,total INTEGER,private_note TEXT,shipping_address TEXT,shared_with TEXT,status TEXT,
          reference TEXT,created_at REAL,UNIQUE(owner,reference));
        CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY,owner TEXT,content TEXT,reference_url TEXT,created_at REAL);
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,sender TEXT,recipient TEXT,content TEXT,created_at REAL);
        ''')
        db.executemany('INSERT OR IGNORE INTO products VALUES(?,?,?,?)',[
            (1,'Tai nghe Studio One',149000,'Âm thanh trong trẻo cho mỗi ngày sáng tạo'),
            (2,'Balo City Explorer',219000,'Gọn nhẹ, nhiều ngăn, sẵn sàng cho chuyến đi'),
            (3,'Bàn phím Orbit',329000,'Thiết kế tinh gọn cho góc làm việc mới'),
            (4,'Bình giữ nhiệt Flow',99000,'Giữ trọn hương vị trong mọi hành trình'),
            (5,'Đèn bàn Halo',179000,'Ánh sáng ấm áp cho những ý tưởng lớn'),
            (6,'Loa Pocket Beat',259000,'Giai điệu yêu thích luôn bên bạn')])
        for username,candidate,role in [('alice',password,'customer'),('merchant',merchant_password or secrets.choice(WEAK_PASSWORDS),'merchant')]:
            salt=secrets.token_hex(16)
            if username=='merchant' and merchant_password:
                db.execute('INSERT OR REPLACE INTO users VALUES(?,?,?,?,?)',(username,salt,password_hash(candidate,salt),role,10000000))
            else:
                db.execute('INSERT OR IGNORE INTO users VALUES(?,?,?,?,?)',(username,salt,password_hash(candidate,salt),role,10000000))
    sessions={};captchas={};failures={};lock=threading.Lock()
    cookie_name='shop_'+hashlib.sha256((sandbox_id+'/'+service_id).encode()).hexdigest()[:12]
    page=Path(__file__).with_name('shop.html').read_bytes()

    def app(env,start):
        route=env.get('PATH_INFO','/');method=env.get('REQUEST_METHOD','GET');now=time.time()
        def respond(code,payload,html=False,headers=None):
            body=payload if html else json.dumps(payload,ensure_ascii=False).encode()
            start(f'{code} {HTTPStatus(code).phrase}',[
                ('Content-Type','text/html; charset=utf-8' if html else 'application/json; charset=utf-8'),
                ('Content-Length',str(len(body))),('Cache-Control','no-store'),('X-Content-Type-Options','nosniff')]+(headers or []))
            return [body]
        if method not in ('GET','POST'):return respond(405,{'error':'Method not allowed'})
        try:
            query={k:v[0] for k,v in parse_qs(env.get('QUERY_STRING',''),max_num_fields=20).items()}
            data={}
            if method=='POST':
                length=int(env.get('CONTENT_LENGTH') or 0)
                if not 0<=length<=16384:return respond(413,{'error':'Request too large'})
                raw=env['wsgi.input'].read(length)
                if env.get('CONTENT_TYPE','').split(';')[0]=='application/json':
                    data=json.loads(raw)
                    if not isinstance(data,dict):raise ValueError()
                else:data={k:v[0] for k,v in parse_qs(raw.decode(),max_num_fields=20).items()}
        except (ValueError,UnicodeDecodeError):return respond(400,{'error':'Invalid request'})
        if route=='/' and method=='GET':return respond(200,page,True)
        if route=='/health' and method=='GET':
            return respond(200,{'status':'ok','sandbox':sandbox_id,'service':service_id,
                                'capabilities':['shop-v1'],'cookie_name':cookie_name})
        if route=='/api/captcha' and method=='GET':
            a,b=secrets.randbelow(9)+1,secrets.randbelow(9)+1;ident=secrets.token_urlsafe(20)
            with lock:
                for old in list(captchas):
                    if captchas[old][1]<now:captchas.pop(old,None)
                if len(captchas)>=2000:captchas.pop(next(iter(captchas)))
                captchas[ident]=(str(a+b),now+120)
            return respond(200,{'id':ident,'question':f'{a} + {b}'})
        if route=='/api/register' and method=='POST':
            username=data.get('username','');candidate=data.get('password','')
            if not isinstance(username,str) or not re.fullmatch(r'[a-z][a-z0-9_]{3,47}',username) or username in ('alice','merchant') or not isinstance(candidate,str) or not 12<=len(candidate)<=128:
                return respond(400,{'error':'Tài khoản 4–48 ký tự, mật khẩu 12–128 ký tự'})
            salt=secrets.token_hex(16)
            try:
                with connect() as db:db.execute('INSERT INTO users VALUES(?,?,?,?,?)',(username,salt,password_hash(candidate,salt),'customer',10000000))
            except sqlite3.IntegrityError:return respond(409,{'error':'Tài khoản đã tồn tại'})
            return respond(201,{'user':username})
        if route=='/api/login' and method=='POST':
            username=data.get('username','');candidate=data.get('password','')
            if not isinstance(username,str) or not isinstance(candidate,str) or len(candidate)>128:return respond(400,{'error':'Invalid login'})
            key=(username,env.get('REMOTE_ADDR','local'))
            with lock:
                attempts=[t for t in failures.get(key,[]) if t>now-60]
                if not enabled['brute_force'] and len(attempts)>=5:return respond(429,{'error':'Tạm khóa thử đăng nhập trong 60 giây'})
                answer=captchas.pop(str(data.get('captcha_id','')),None)
            bypass=enabled['captcha_bypass'] and str(data.get('captcha_verified',''))=='1'
            if not bypass and (answer is None or answer[1]<now or str(data.get('captcha_answer',''))!=answer[0]):
                return respond(400,{'error':'CAPTCHA không hợp lệ'})
            with connect() as db:user=db.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
            valid=user is not None and hmac.compare_digest(password_hash(candidate,user['salt']),user['digest'])
            if not valid:
                with lock:
                    if len(failures)>5000:failures.clear()
                    failures[key]=attempts+[now]
                return respond(401,{'error':'Sai tài khoản hoặc mật khẩu'})
            session=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(24)
            with lock:
                failures.pop(key,None)
                for old in list(sessions):
                    if sessions[old]['expires']<now:sessions.pop(old,None)
                sessions[session]={'user':username,'role':user['role'],'csrf':csrf,'expires':now+1800}
            return respond(200,{'user':username,'role':user['role'],'csrf_token':csrf},headers=[
                ('Set-Cookie',f'{cookie_name}={session}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1800')])
        if route=='/api/products' and method=='GET':
            text=query.get('q','')[:512]
            with connect() as db:
                deadline=time.monotonic()+.3
                db.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
                try:
                    if enabled['sqli']:
                        # INTENTIONAL SQL injection challenge; only this search uses interpolation.
                        rows=db.execute("SELECT id,name,price,description FROM products WHERE name LIKE '%"+text+"%' ORDER BY id LIMIT 30").fetchall()
                    else:rows=db.execute('SELECT id,name,price,description FROM products WHERE name LIKE ? ORDER BY id LIMIT 30',('%'+text+'%',)).fetchall()
                except sqlite3.DatabaseError:return respond(400,{'error':'Tìm kiếm không hợp lệ'})
                return respond(200,[dict(r) for r in rows])
        if route=='/reviews' and method=='GET':
            with connect() as db:rows=db.execute('SELECT * FROM reviews ORDER BY id DESC LIMIT 30').fetchall()
            articles=[]
            for r in rows:
                content=r['content'] if enabled['xss'] else escape(r['content'])
                link='<a data-promotion href="'+escape(r['reference_url'],quote=True)+'">Xem liên kết ưu đãi</a>' if r['reference_url'] else ''
                articles.append('<article><strong>'+escape(r['owner'])+'</strong><div>'+content+'</div>'+link+'</article>')
            html=('<!doctype html><meta charset="utf-8"><title>Đánh giá Nova Mart</title><style>body{font:15px system-ui;color:#253f3a;margin:14px}article{padding:16px;border-bottom:1px solid #e3e9e6}strong{color:#126d59}a{color:#116d5c}div{margin:8px 0}</style>'+''.join(articles)).encode()
            return respond(200,html,True)
        try:
            cookies=SimpleCookie(env.get('HTTP_COOKIE',''));token=cookies[cookie_name].value if cookie_name in cookies else ''
        except CookieError:token=''
        with lock:session=sessions.get(token)
        if not session or session['expires']<=now:return respond(401,{'error':'Cần đăng nhập'})
        username=session['user'];merchant=session['role']=='merchant'
        if route=='/api/me' and method=='GET':
            with connect() as db:wallet=db.execute('SELECT wallet FROM users WHERE username=?',(username,)).fetchone()[0]
            return respond(200,{'user':username,'role':session['role'],'wallet':wallet,'csrf_token':session['csrf']})
        if method=='POST' and not enabled['csrf']:
            supplied=env.get('HTTP_X_CSRF_TOKEN',data.get('csrf_token',''))
            origin=env.get('HTTP_ORIGIN')
            valid_origin=not origin or urlsplit(origin).netloc.lower()==env.get('HTTP_HOST','').lower()
            if not isinstance(supplied,str) or not hmac.compare_digest(supplied,session['csrf']) or not valid_origin:
                return respond(403,{'error':'CSRF token/origin không hợp lệ'})
        if route=='/api/logout' and method=='POST':
            with lock:sessions.pop(token,None)
            return respond(200,{'status':'ok'},headers=[('Set-Cookie',f'{cookie_name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax')])
        if route=='/api/reviews' and method=='POST':
            content=data.get('content','');link=data.get('reference_url','')
            if not isinstance(content,str) or not 1<=len(content)<=2048 or not isinstance(link,str) or len(link)>512:
                return respond(400,{'error':'Nội dung đánh giá không hợp lệ'})
            parsed=urlsplit(link)
            if link and (not link.startswith('/') or link.startswith('//') or parsed.scheme or parsed.netloc):
                return respond(400,{'error':'Chỉ dùng liên kết ưu đãi trong cửa hàng'})
            with connect() as db:
                db.execute('INSERT INTO reviews(owner,content,reference_url,created_at) VALUES(?,?,?,?)',(username,content,link,now))
                return respond(201,{'status':'published'})
        if route=='/api/messages':
            with connect() as db:
                if method=='GET':return respond(200,[dict(r) for r in db.execute('SELECT sender,content,created_at FROM messages WHERE recipient=? ORDER BY id DESC LIMIT 100',(username,))])
                recipient=data.get('recipient','');content=data.get('content','')
                if not isinstance(recipient,str) or not isinstance(content,str) or not 1<=len(content)<=4096 or not db.execute('SELECT 1 FROM users WHERE username=?',(recipient,)).fetchone():
                    return respond(400,{'error':'Tin nhắn không hợp lệ'})
                db.execute('INSERT INTO messages(sender,recipient,content,created_at) VALUES(?,?,?,?)',(username,recipient,content,now))
                return respond(201,{'status':'sent'})
        if route=='/api/orders/share':
            if method=='GET' and not enabled['csrf']:return respond(405,{'error':'POST with CSRF token required'})
            form=query if method=='GET' else data
            try:ident=int(form.get('order_id',0))
            except (ValueError,TypeError):return respond(400,{'error':'Invalid order'})
            recipient=form.get('recipient','')
            with connect() as db:
                row=db.execute('SELECT owner FROM orders WHERE id=?',(ident,)).fetchone()
                if not row:return respond(404,{'error':'Order not found'})
                if row['owner']!=username and not merchant:return respond(403,{'error':'Forbidden'})
                if not isinstance(recipient,str) or not db.execute('SELECT 1 FROM users WHERE username=?',(recipient,)).fetchone():return respond(400,{'error':'Recipient not found'})
                db.execute('UPDATE orders SET shared_with=? WHERE id=?',(recipient,ident))
                return respond(200,{'status':'shared','order_id':ident})
        if route=='/api/orders':
            with connect() as db:
                if method=='GET':
                    rows=db.execute('SELECT * FROM orders ORDER BY id DESC LIMIT 200') if merchant else db.execute('SELECT * FROM orders WHERE owner=? OR shared_with=? ORDER BY id DESC LIMIT 200',(username,username))
                    return respond(200,[dict(r) for r in rows])
                try:product_id=int(data.get('product_id',0));quantity=int(data.get('quantity',1))
                except (ValueError,TypeError):return respond(400,{'error':'Invalid product'})
                note=data.get('private_note','');address=data.get('shipping_address','');reference=data.get('reference') or secrets.token_hex(16)
                if not all(isinstance(x,str) for x in (note,address,reference)) or len(note)>2048 or not 1<=len(address)<=300 or len(reference)>128 or not 1<=quantity<=5:
                    return respond(400,{'error':'Invalid order fields'})
                db.execute('BEGIN IMMEDIATE')
                old=db.execute('SELECT * FROM orders WHERE owner=? AND reference=?',(username,reference)).fetchone()
                if old:return respond(200,dict(old))
                product=db.execute('SELECT price FROM products WHERE id=?',(product_id,)).fetchone()
                if product is None:return respond(404,{'error':'Product not found'})
                total=product['price']*quantity
                changed=db.execute('UPDATE users SET wallet=wallet-? WHERE username=? AND wallet>=?',(total,username,total))
                if changed.rowcount!=1:return respond(400,{'error':'Số dư không đủ'})
                cursor=db.execute('INSERT INTO orders(owner,product_id,quantity,total,private_note,shipping_address,shared_with,status,reference,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',
                    (username,product_id,quantity,total,note,address,'','paid',reference,now))
                return respond(201,dict(db.execute('SELECT * FROM orders WHERE id=?',(cursor.lastrowid,)).fetchone()))
        if route.startswith('/api/orders/') and method=='GET':
            try:ident=int(route.rsplit('/',1)[-1])
            except ValueError:return respond(404,{'error':'Not found'})
            with connect() as db:row=db.execute('SELECT * FROM orders WHERE id=?',(ident,)).fetchone()
            if row is None:return respond(404,{'error':'Not found'})
            if not merchant and username not in (row['owner'],row['shared_with']):return respond(403,{'error':'Forbidden'})
            return respond(200,dict(row))
        return respond(404,{'error':'Not found'})
    return app
