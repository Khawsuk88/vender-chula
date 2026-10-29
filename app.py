import os, sqlite3, uuid, re, secrets, smtplib, ssl, time, io, hashlib
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from PIL import Image, UnidentifiedImageError
from email.message import EmailMessage
from pathlib import Path
load_dotenv(Path(__file__).resolve().parent / '.env', override=True)
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from werkzeug.security import generate_password_hash, check_password_hash

BASE=Path(__file__).resolve().parent
DB=Path(os.getenv('DATABASE_PATH',str(BASE/'vender.db')))
DB.parent.mkdir(parents=True,exist_ok=True)
UPLOAD=Path(os.getenv('UPLOAD_PATH',str(BASE/'static'/'uploads')))
UPLOAD.mkdir(parents=True,exist_ok=True)
app=Flask(__name__)
app.secret_key=os.getenv('SECRET_KEY') or secrets.token_hex(32)
if os.getenv('APP_ENV')=='production' and not os.getenv('SECRET_KEY'):raise RuntimeError('SECRET_KEY is required in production')
if os.getenv('APP_ENV')=='production' and os.getenv('COOKIE_SECURE')!='1':raise RuntimeError('COOKIE_SECURE=1 required in production')
app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE','0')=='1')
# Local single-process throttling. Use a shared rate-limit store before scaling.
_ATTEMPTS=defaultdict(list)
def throttle(scope, limit, window=3600):
    ip=request.remote_addr or 'unknown'
    key=(scope,ip)
    now=time.monotonic()
    _ATTEMPTS[key]=[t for t in _ATTEMPTS[key] if now-t<window]
    if len(_ATTEMPTS[key])>=limit:abort(429)
    _ATTEMPTS[key].append(now)
@app.before_request
def csrf_protection():
    if request.method=='POST':
        supplied=request.form.get('csrf_token','')
        expected=session.get('_csrf','')
        if not expected or not secrets.compare_digest(supplied,expected):abort(400,'Invalid or missing CSRF token.')
def csrf_token():
    if '_csrf' not in session:session['_csrf']=secrets.token_urlsafe(32)
    return session['_csrf']
app.jinja_env.globals['csrf_token']=csrf_token
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='strict-origin-when-cross-origin'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Content-Security-Policy']="default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; form-action 'self'; base-uri 'self'; object-src 'none'"
    return response

app.config['MAX_CONTENT_LENGTH']=20*1024*1024
ALLOWED={'jpg','jpeg','png','webp'}
CATEGORIES=['Electronics','Textbooks & Study','Uniforms & Clothing','Dorm & Home','Sports & Hobbies','Other']
ALLOWED_DOMAINS={d.strip().lower() for d in os.getenv('ALLOWED_EMAIL_DOMAINS','student.chula.ac.th,chula.ac.th').split(',') if d.strip()}
def valid_chula_email(email):
    return '@' in email and email.rsplit('@',1)[1].lower() in ALLOWED_DOMAINS
def send_email(recipient, subject, content):
    """Send transactional mail using the same Gmail SMTP settings as the successful manual test."""
    host = os.getenv('SMTP_HOST', '').strip()
    username = os.getenv('SMTP_USERNAME', '').strip()
    password = os.getenv('SMTP_PASSWORD', '').replace(' ', '').strip()
    sender = os.getenv('SMTP_FROM', '').strip() or username
    if not host or not sender or not username or not password:
        raise RuntimeError('SMTP_HOST, SMTP_USERNAME and SMTP_PASSWORD must be set in .env')
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient
    msg.set_content(content)
    port = int(os.getenv('SMTP_PORT', '587'))
    with smtplib.SMTP(host, port, timeout=20) as server:
        server.ehlo()
        server.starttls(context=ssl.create_default_context())
        server.ehlo()
        server.login(username, password)
        server.send_message(msg)

def send_verification(email, token):
    base = os.getenv('PUBLIC_BASE_URL', 'http://127.0.0.1:5000').rstrip('/')
    send_email(email, 'Verify your Vender Chula account',
               f'Confirm your university email by opening this link:\n'
               f'{base}/verify/{token}\n\nThe link expires in 24 hours.')

def conn():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    c.execute('PRAGMA busy_timeout=5000')
    return c
def init_db():
    with conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('individual','business')),
          business_name TEXT, logo TEXT, line_id TEXT, phone TEXT, is_admin INTEGER DEFAULT 0, verified INTEGER NOT NULL DEFAULT 0,
          verification_token TEXT, verification_expires TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS listings(
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
          category TEXT NOT NULL, listing_type TEXT NOT NULL DEFAULT 'selling', title TEXT NOT NULL, brand TEXT NOT NULL DEFAULT '',
          model TEXT NOT NULL DEFAULT '', year INTEGER NOT NULL DEFAULT 0, mileage INTEGER NOT NULL DEFAULT 0,
          price INTEGER NOT NULL, location TEXT NOT NULL, description TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','sold')),
          created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS photos(
          id INTEGER PRIMARY KEY, listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
          filename TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS reports(
          id INTEGER PRIMARY KEY, listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
          reporter_id INTEGER REFERENCES users(id), reason TEXT NOT NULL,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        """)
        c.execute('''CREATE TABLE IF NOT EXISTS favorites(
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
          PRIMARY KEY(user_id,listing_id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS password_resets(
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          token_hash TEXT UNIQUE NOT NULL, expires TEXT NOT NULL,
          PRIMARY KEY(user_id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS conversations(
          id INTEGER PRIMARY KEY,
          listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
          buyer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          seller_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(listing_id,buyer_id),
          CHECK(buyer_id != seller_id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS messages(
          id INTEGER PRIMARY KEY,
          conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
          sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 2000),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(conversation_id,id)')
        c.execute('''CREATE TABLE IF NOT EXISTS message_reads(
          conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          last_read_id INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY(conversation_id,user_id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_users(
          blocker_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          blocked_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          PRIMARY KEY(blocker_id,blocked_id))''')
        admin_email=os.getenv('ADMIN_EMAIL','').strip().lower()
        if admin_email: c.execute('UPDATE users SET is_admin=1 WHERE email=?',(admin_email,))
init_db()
def user():
    if not session.get('uid'): return None
    with conn() as c: u=c.execute('SELECT * FROM users WHERE id=?',(session['uid'],)).fetchone()
    return u if u and u['verified'] and valid_chula_email(u['email']) else None
@app.context_processor
def globals_ctx(): return {'me':user(),'categories':CATEGORIES}
def login_required(f):
    @wraps(f)
    def wrapper(*a,**kw):
        if not user(): flash('Please sign in with a verified Chula email first.'); return redirect(url_for('login'))
        return f(*a,**kw)
    return wrapper
def admin_required(f):
    @wraps(f)
    def wrapper(*a,**kw):
        u=user()
        if not u or not u['is_admin']: abort(403)
        return f(*a,**kw)
    return wrapper
@app.route('/')
def home():
    q=request.args.get('q','').strip()
    brand=request.args.get('category','').strip()
    listing_type=request.args.get('listing_type','').strip()
    max_price=request.args.get('max_price','').strip()
    sql="""SELECT l.*,u.name,u.kind,u.business_name,
           (SELECT filename FROM photos p WHERE p.listing_id=l.id ORDER BY id LIMIT 1) photo
           FROM listings l JOIN users u ON u.id=l.user_id WHERE l.status='approved'"""
    args=[]
    if q: sql+=' AND (l.title LIKE ? OR l.brand LIKE ? OR l.model LIKE ? OR l.location LIKE ?)'; args += ['%'+q+'%']*4
    if brand in CATEGORIES: sql+=' AND l.category=?'; args.append(brand)
    if listing_type in ('selling','wanted'): sql+=' AND l.listing_type=?'; args.append(listing_type)
    if max_price.isdigit(): sql+=' AND l.price<=?'; args.append(int(max_price))
    sort=request.args.get('sort','newest')
    if sort=='price_asc':sql+=' ORDER BY l.price ASC,l.id DESC'
    elif sort=='price_desc':sql+=' ORDER BY l.price DESC,l.id DESC'
    else:sql+=' ORDER BY l.created_at DESC,l.id DESC'
    page=max(1,min(10000,int(request.args.get('page','1')) if request.args.get('page','1').isdigit() else 1))
    sql+=' LIMIT 25 OFFSET ?'
    args.append((page-1)*25)
    with conn() as c: listings=c.execute(sql,args).fetchall()
    return render_template('home.html',listings=listings,q=q,brand=brand,max_price=max_price,listing_type=listing_type,sort=sort,page=page)
@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        throttle('register',8)
        name=request.form.get('name','').strip()
        email=request.form.get('email','').strip().lower()
        password=request.form.get('password','')
        if not name or len(name)>100 or not valid_chula_email(email) or len(password)<10 or len(password)>128:
            flash('Use an approved Chula email address and a password of at least 10 characters.')
            return redirect(url_for('register'))
        token=secrets.token_urlsafe(32)
        from datetime import datetime, timedelta, timezone
        expires=(datetime.now(timezone.utc)+timedelta(hours=24)).isoformat()
        try:
            with conn() as c:
                c.execute("""INSERT INTO users(name,email,password,kind,verification_token,verification_expires)
                    VALUES(?,?,?,'individual',?,?)""",
                    (name,email,generate_password_hash(password),token,expires))
            try:
                send_verification(email,token)
            except Exception:
                with conn() as c: c.execute('DELETE FROM users WHERE email=? AND verified=0',(email,))
                app.logger.exception('Verification email failed; check SMTP settings and sender')
                flash('Could not send verification email. Contact the site administrator.')
                return redirect(url_for('register'))
            flash('Check your Chula email for a verification link before logging in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already registered.')
    return render_template('register.html')

@app.route('/verify/<token>')
def verify(token):
    from datetime import datetime, timezone
    with conn() as c:
        u=c.execute('SELECT * FROM users WHERE verification_token=?',(token,)).fetchone()
        if not u or not u['verification_expires'] or datetime.fromisoformat(u['verification_expires'])<datetime.now(timezone.utc):
            flash('Verification link is invalid or expired. Contact the administrator.')
            return redirect(url_for('login'))
        c.execute('UPDATE users SET verified=1,verification_token=NULL,verification_expires=NULL WHERE id=?',(u['id'],))
    flash('Email verified. You can now log in.')
    return redirect(url_for('login'))

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        throttle('login',20,900)
        with conn() as c: u=c.execute('SELECT * FROM users WHERE email=?',(request.form.get('email','').strip().lower(),)).fetchone()
        if u and u['verified'] and valid_chula_email(u['email']) and check_password_hash(u['password'],request.form.get('password','')):
            session.clear();session['uid']=u['id'];return redirect(url_for('dashboard'))
        flash('Invalid email or password.')
    return render_template('login.html')
@app.route('/logout',methods=['POST'])
def logout():session.clear();return redirect(url_for('home'))
def save_photo(f):
    if not f or not f.filename:return None
    if f.filename.rsplit('.',1)[-1].lower() not in ALLOWED:raise ValueError('Upload JPG, PNG or WEBP only.')
    raw=f.read(8*1024*1024+1)
    if len(raw)>8*1024*1024:raise ValueError('Each photo must be under 8 MB.')
    try:
        with Image.open(io.BytesIO(raw)) as im:
            im.verify()
        with Image.open(io.BytesIO(raw)) as im:
            if im.width*im.height>25_000_000:raise ValueError('Image dimensions are too large.')
            rgb=im.convert('RGB')
            rgb.thumbnail((1800,1800))
            out=io.BytesIO()
            rgb.save(out,format='WEBP',quality=83,method=4)
    except (UnidentifiedImageError,OSError,ValueError) as exc:
        raise ValueError('Invalid or unsupported image.') from exc
    name=f'{uuid.uuid4().hex}.webp'
    (UPLOAD/name).write_bytes(out.getvalue())
    return name
@app.route('/dashboard')
@login_required
def dashboard():
    u=user()
    with conn() as c: listings=c.execute('SELECT * FROM listings WHERE user_id=? ORDER BY created_at DESC',(u['id'],)).fetchall()
    return render_template('dashboard.html',listings=listings)
@app.route('/listing/new',methods=['GET','POST'])
@login_required
def new_listing():
    if request.method=='POST':
        throttle('new-listing',25)
        try:
            title=request.form['title'].strip(); category=request.form['category'].strip()
            listing_type=request.form['listing_type'].strip(); price=int(request.form['price'])
            location=request.form['location'].strip(); description=request.form['description'].strip()
            if not all([title,location,description]) or len(title)>120 or len(location)>120 or len(description)>4000 or category not in CATEGORIES or listing_type not in ('selling','wanted') or not 0<=price<=100000000: raise ValueError('Please enter valid listing details.')
            images=[f for f in request.files.getlist('photos') if f.filename]
            if len(images)>6 or (listing_type=='selling' and not images): raise ValueError('Selling listings require 1–6 photos; wanted listings may have none.')
            saved=[]
            try:
                saved=[save_photo(f) for f in images]
            except Exception:
                for name in saved:(UPLOAD/name).unlink(missing_ok=True)
                raise
            with conn() as c:
                cur=c.execute('INSERT INTO listings(user_id,category,listing_type,title,price,location,description) VALUES(?,?,?,?,?,?,?)',
                              (user()['id'],category,listing_type,title,price,location,description))
                c.executemany('INSERT INTO photos(listing_id,filename) VALUES(?,?)',[(cur.lastrowid,n) for n in saved])
            flash('Listing submitted for review.');return redirect(url_for('dashboard'))
        except (ValueError,KeyError) as e: flash(str(e))
    return render_template('listing_form.html',listing=None)
@app.route('/listing/<int:lid>')
def listing(lid):
    with conn() as c:
        l=c.execute('SELECT l.*,u.name,u.kind,u.business_name,u.phone,u.line_id,u.id seller_id FROM listings l JOIN users u ON u.id=l.user_id WHERE l.id=?',(lid,)).fetchone()
        if not l:abort(404)
        u=user()
        if l['status'] not in ('approved','sold') and not (u and (u['id']==l['user_id'] or u['is_admin'])):abort(404)
        photos=c.execute('SELECT filename FROM photos WHERE listing_id=?',(lid,)).fetchall()
    saved=False
    if u:
        with conn() as c:saved=c.execute('SELECT 1 FROM favorites WHERE user_id=? AND listing_id=?',(u['id'],lid)).fetchone() is not None
    return render_template('listing.html',listing=l,photos=photos,saved=saved)
@app.route('/listing/<int:lid>/edit',methods=['GET','POST'])
@login_required
def edit_listing(lid):
    with conn() as c: l=c.execute('SELECT * FROM listings WHERE id=? AND user_id=?',(lid,user()['id'])).fetchone()
    if not l:abort(404)
    if request.method=='POST':
        try:
            fields={k:request.form[k].strip() for k in ('title','category','listing_type','location','description')}
            price=int(request.form['price'])
            if not all(fields.values()) or len(fields['title'])>120 or len(fields['location'])>120 or len(fields['description'])>4000 or fields['category'] not in CATEGORIES or fields['listing_type'] not in ('selling','wanted') or not 0<=price<=100000000:raise ValueError('Invalid details.')
            with conn() as c:
                c.execute("""UPDATE listings SET title=?,category=?,listing_type=?,price=?,location=?,description=?,status='pending' WHERE id=? AND user_id=?""",
                          (fields['title'],fields['category'],fields['listing_type'],price,fields['location'],fields['description'],lid,user()['id']))
            flash('Changes saved; listing awaits review.');return redirect(url_for('dashboard'))
        except (ValueError,KeyError) as e:flash(str(e))
    return render_template('listing_form.html',listing=l)
@app.route('/listing/<int:lid>/delete',methods=['POST'])
@login_required
def delete_listing(lid):
    with conn() as c:
        l=c.execute('SELECT id FROM listings WHERE id=? AND user_id=?',(lid,user()['id'])).fetchone()
        if not l:abort(404)
        photos=c.execute('SELECT filename FROM photos WHERE listing_id=?',(lid,)).fetchall()
        c.execute('DELETE FROM listings WHERE id=?',(lid,))
    for p in photos:(UPLOAD/p['filename']).unlink(missing_ok=True)
    flash('Listing deleted.');return redirect(url_for('dashboard'))
@app.route('/seller/<int:sid>')
def seller(sid):
    with conn() as c:
        s=c.execute('SELECT id,name,kind,business_name,logo,line_id,phone FROM users WHERE id=?',(sid,)).fetchone()
        if not s:abort(404)
        listings=c.execute("""SELECT l.*,(SELECT filename FROM photos p WHERE p.listing_id=l.id LIMIT 1) photo FROM listings l WHERE l.user_id=? AND l.status IN ('approved','sold') ORDER BY l.created_at DESC""",(sid,)).fetchall()
    return render_template('seller.html',seller=s,listings=listings)
@app.route('/profile',methods=['GET','POST'])
@login_required
def profile():
    if request.method=='POST':
        u=user(); logo=u['logo']
        try:
            f=request.files.get('logo')
            if f and f.filename:logo=save_photo(f)
            with conn() as c:
                c.execute('UPDATE users SET name=?,business_name=?,phone=?,line_id=?,logo=? WHERE id=?',
                          (request.form['name'].strip(),request.form.get('business_name','').strip(),request.form.get('phone','').strip(),request.form.get('line_id','').strip(),logo,u['id']))
            flash('Profile updated.');return redirect(url_for('dashboard'))
        except ValueError as e:flash(str(e))
    return render_template('profile.html')
@app.route('/listing/<int:lid>/report',methods=['POST'])
@login_required
def report(lid):
    throttle('report',15)
    reason=request.form.get('reason','').strip()[:500]
    if not reason:abort(400)
    with conn() as c:
        if not c.execute('SELECT id FROM listings WHERE id=?',(lid,)).fetchone():abort(404)
        c.execute('INSERT INTO reports(listing_id,reporter_id,reason) VALUES(?,?,?)',(lid,user()['id'],reason))
    flash('Report sent for review.');return redirect(url_for('listing',lid=lid))
@app.route('/admin')
@admin_required
def admin():
    with conn() as c:
        pending=c.execute("SELECT l.*,u.email FROM listings l JOIN users u ON u.id=l.user_id WHERE status='pending' ORDER BY created_at").fetchall()
        reports=c.execute('SELECT r.*,l.title FROM reports r JOIN listings l ON l.id=r.listing_id ORDER BY r.created_at DESC LIMIT 100').fetchall()
    return render_template('admin.html',pending=pending,reports=reports)
@app.route('/admin/listing/<int:lid>/<action>',methods=['POST'])
@admin_required
def moderate(lid,action):
    if action not in ('approved','rejected'):abort(400)
    with conn() as c:c.execute('UPDATE listings SET status=? WHERE id=?',(action,lid))
    flash('Listing updated.');return redirect(url_for('admin'))
@app.route('/admin/report/<int:rid>/dismiss',methods=['POST'])
@admin_required
def dismiss_report(rid):
    with conn() as c:c.execute('DELETE FROM reports WHERE id=?',(rid,))
    return redirect(url_for('admin'))

@app.route('/listing/<int:lid>/favorite',methods=['POST'])
@login_required
def toggle_favorite(lid):
    uid=user()['id']
    with conn() as c:
        l=c.execute("SELECT id FROM listings WHERE id=? AND status IN ('approved','sold')",(lid,)).fetchone()
        if not l:abort(404)
        exists=c.execute('SELECT 1 FROM favorites WHERE user_id=? AND listing_id=?',(uid,lid)).fetchone()
        if exists:c.execute('DELETE FROM favorites WHERE user_id=? AND listing_id=?',(uid,lid))
        else:c.execute('INSERT INTO favorites(user_id,listing_id) VALUES(?,?)',(uid,lid))
    return redirect(url_for('listing',lid=lid))

@app.route('/favorites')
@login_required
def favorites():
    with conn() as c:
        listings=c.execute('''SELECT l.*,(SELECT filename FROM photos p WHERE p.listing_id=l.id ORDER BY id LIMIT 1) photo
            FROM favorites f JOIN listings l ON l.id=f.listing_id
            WHERE f.user_id=? AND l.status IN ('approved','sold') ORDER BY l.created_at DESC''',(user()['id'],)).fetchall()
    return render_template('favorites.html',listings=listings)

@app.route('/listing/<int:lid>/sold',methods=['POST'])
@login_required
def mark_sold(lid):
    with conn() as c:
        cur=c.execute("UPDATE listings SET status='sold' WHERE id=? AND user_id=? AND status='approved'",(lid,user()['id']))
        if not cur.rowcount:abort(404)
    flash('Marked as sold.')
    return redirect(url_for('dashboard'))

@app.route('/resend-verification',methods=['GET','POST'])
def resend_verification():
    if request.method=='POST':
        throttle('resend-verification',5)
        email=request.form.get('email','').strip().lower()
        if valid_chula_email(email):
            with conn() as c:
                u=c.execute('SELECT id FROM users WHERE email=? AND verified=0',(email,)).fetchone()
                if u:
                    token=secrets.token_urlsafe(32)
                    expires=(datetime.now(timezone.utc)+timedelta(hours=24)).isoformat()
                    c.execute('UPDATE users SET verification_token=?,verification_expires=? WHERE id=?',(token,expires,u['id']))
                    try:send_verification(email,token)
                    except Exception:app.logger.exception('Verification resend failed')
        flash('If this unverified Chula account exists, a new link has been requested.')
        return redirect(url_for('login'))
    return render_template('resend.html')



# V4: private, listing-linked messaging.
@app.route('/listing/<int:lid>/chat',methods=['POST'])
@login_required
def start_chat(lid):
    throttle('start_chat',40,3600)
    me=user()
    with conn() as c:
        listing=c.execute('SELECT id,user_id,status FROM listings WHERE id=?',(lid,)).fetchone()
        if not listing or listing['status']!='approved':abort(404)
        if listing['user_id']==me['id']:abort(400,'You cannot message yourself.')
        blocked=c.execute('SELECT 1 FROM blocked_users WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)',(me['id'],listing['user_id'],listing['user_id'],me['id'])).fetchone()
        if blocked:abort(403)
        c.execute('INSERT OR IGNORE INTO conversations(listing_id,buyer_id,seller_id) VALUES (?,?,?)',(lid,me['id'],listing['user_id']))
        thread=c.execute('SELECT id FROM conversations WHERE listing_id=? AND buyer_id=?',(lid,me['id'])).fetchone()
    return redirect(url_for('conversation',cid=thread['id']))

@app.route('/messages')
@login_required
def inbox():
    me=user()
    with conn() as c:
        threads=c.execute('''SELECT t.*,l.title,l.price,l.status,
            CASE WHEN t.buyer_id=? THEN seller.name ELSE buyer.name END partner,
            (SELECT body FROM messages m WHERE m.conversation_id=t.id ORDER BY m.id DESC LIMIT 1) last_body,
            (SELECT COUNT(*) FROM messages m WHERE m.conversation_id=t.id AND m.sender_id!=?
                AND m.id>COALESCE((SELECT last_read_id FROM message_reads r WHERE r.conversation_id=t.id AND r.user_id=?),0)) unread
            FROM conversations t JOIN listings l ON l.id=t.listing_id
            JOIN users buyer ON buyer.id=t.buyer_id JOIN users seller ON seller.id=t.seller_id
            WHERE t.buyer_id=? OR t.seller_id=?
            ORDER BY COALESCE((SELECT MAX(id) FROM messages m WHERE m.conversation_id=t.id),0) DESC,t.id DESC''',
            (me['id'],me['id'],me['id'],me['id'],me['id'])).fetchall()
    return render_template('inbox.html',threads=threads)

@app.route('/messages/<int:cid>',methods=['GET','POST'])
@login_required
def conversation(cid):
    me=user()
    with conn() as c:
        thread=c.execute('''SELECT t.*,l.title,l.price,l.status,
            CASE WHEN t.buyer_id=? THEN seller.name ELSE buyer.name END partner,
            CASE WHEN t.buyer_id=? THEN t.seller_id ELSE t.buyer_id END partner_id
            FROM conversations t JOIN listings l ON l.id=t.listing_id
            JOIN users buyer ON buyer.id=t.buyer_id JOIN users seller ON seller.id=t.seller_id
            WHERE t.id=? AND (t.buyer_id=? OR t.seller_id=?)''',
            (me['id'],me['id'],cid,me['id'],me['id'])).fetchone()
        if not thread:abort(404)
        blocked=c.execute('SELECT 1 FROM blocked_users WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)',(me['id'],thread['partner_id'],thread['partner_id'],me['id'])).fetchone()
        if request.method=='POST':
            throttle('send_message',120,3600)
            if blocked:abort(403,'Conversation is blocked.')
            body=request.form.get('body','').strip()
            if not 1<=len(body)<=2000:
                flash('Message must be 1–2000 characters.')
            else:
                c.execute('INSERT INTO messages(conversation_id,sender_id,body) VALUES(?,?,?)',(cid,me['id'],body))
                return redirect(url_for('conversation',cid=cid))
        messages=c.execute('SELECT * FROM messages WHERE conversation_id=? ORDER BY id DESC LIMIT 200',(cid,)).fetchall()
        messages=list(reversed(messages))
        last_id=messages[-1]['id'] if messages else 0
        c.execute('''INSERT INTO message_reads(conversation_id,user_id,last_read_id) VALUES(?,?,?)
            ON CONFLICT(conversation_id,user_id) DO UPDATE SET last_read_id=MAX(last_read_id,excluded.last_read_id)''',(cid,me['id'],last_id))
    return render_template('conversation.html',thread=thread,messages=messages,blocked=bool(blocked))

@app.route('/messages/<int:cid>/block',methods=['POST'])
@login_required
def block_chat(cid):
    me=user()
    with conn() as c:
        thread=c.execute('SELECT buyer_id,seller_id FROM conversations WHERE id=? AND (buyer_id=? OR seller_id=?)',(cid,me['id'],me['id'])).fetchone()
        if not thread:abort(404)
        other=thread['seller_id'] if thread['buyer_id']==me['id'] else thread['buyer_id']
        c.execute('INSERT OR IGNORE INTO blocked_users(blocker_id,blocked_id) VALUES (?,?)',(me['id'],other))
    flash('User blocked. You can no longer exchange messages.')
    return redirect(url_for('inbox'))

@app.route('/health')
def health():
    try:
        with conn() as c:c.execute('SELECT 1').fetchone()
        return {'status':'ok'},200
    except sqlite3.Error:
        return {'status':'unavailable'},503

@app.route('/forgot-password',methods=['GET','POST'])
def forgot_password():
    if request.method=='POST':
        throttle('password-reset-request',5)
        email=request.form.get('email','').strip().lower()
        if valid_chula_email(email):
            with conn() as c:
                u=c.execute('SELECT id FROM users WHERE email=? AND verified=1',(email,)).fetchone()
                if u:
                    token=secrets.token_urlsafe(32)
                    digest=hashlib.sha256(token.encode()).hexdigest()
                    expires=(datetime.now(timezone.utc)+timedelta(minutes=30)).isoformat()
                    c.execute('INSERT OR REPLACE INTO password_resets(user_id,token_hash,expires) VALUES(?,?,?)',(u['id'],digest,expires))
                    try:
                        send_password_reset(email,token)
                    except Exception:
                        app.logger.exception('Password reset delivery failed')
                        c.execute('DELETE FROM password_resets WHERE user_id=?',(u['id'],))
        flash('If that verified account exists, a reset email has been requested.')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

def send_password_reset(email, token):
    base = os.getenv('PUBLIC_BASE_URL', 'http://127.0.0.1:5000').rstrip('/')
    send_email(email, 'Reset your Vender Chula password',
               f'Open this link to reset your password (expires in 30 minutes):\n'
               f'{base}/reset-password/{token}\n'
               'If you did not request this, ignore this email.')

@app.route('/reset-password/<token>',methods=['GET','POST'])
def reset_password(token):
    digest=hashlib.sha256(token.encode()).hexdigest()
    with conn() as c:
        row=c.execute('SELECT user_id,expires FROM password_resets WHERE token_hash=?',(digest,)).fetchone()
    if not row or datetime.fromisoformat(row['expires'])<datetime.now(timezone.utc):
        flash('Reset link invalid or expired.')
        return redirect(url_for('forgot_password'))
    if request.method=='POST':
        throttle('password-reset',10,900)
        password=request.form.get('password','')
        if not 10<=len(password)<=128:
            flash('Choose a password between 10 and 128 characters.')
        else:
            with conn() as c:
                current=c.execute('SELECT user_id FROM password_resets WHERE token_hash=? AND expires>?',(digest,datetime.now(timezone.utc).isoformat())).fetchone()
                if not current:abort(400)
                c.execute('UPDATE users SET password=? WHERE id=?',(generate_password_hash(password),current['user_id']))
                c.execute('DELETE FROM password_resets WHERE user_id=?',(current['user_id'],))
            session.clear()
            flash('Password updated. Sign in with your new password.')
            return redirect(url_for('login'))
    return render_template('reset_password.html')

if __name__=='__main__':
    app.run(debug=os.getenv('FLASK_DEBUG','0')=='1')
