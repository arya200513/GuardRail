import os, re, sqlite3, secrets
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

ROOT=os.path.abspath(os.path.dirname(__file__)); DB=os.path.join(ROOT,'guardrail.db')
app=Flask(__name__); app.secret_key=os.environ.get('GUARDRAIL_SECRET',secrets.token_hex(32))
PATTERNS={
 'Email address':re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',re.I),
 'Phone-like number':re.compile(r'(?<!\d)(?:\+?\d{1,3}[- ]?)?[6-9]\d{9}(?!\d)'),
 'Possible Aadhaar-like number':re.compile(r'(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)'),
 'Possible secret':re.compile(r'(?i)\b(api[_ -]?key|secret|password|token)\s*[:=]\s*\S+')}
def dbcon():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def init_db():
 with dbcon() as d:
  d.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password_hash TEXT,role TEXT);
  CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY,username TEXT,activity TEXT,score INTEGER,level TEXT,reason TEXT,action TEXT,created TEXT);
  CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY,log_id INTEGER,title TEXT,details TEXT,status TEXT,created TEXT);''')
  for u,p,r in [('admin','admin123','admin'),('student','student123','user')]:
   if not d.execute('SELECT id FROM users WHERE username=?',(u,)).fetchone(): d.execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)',(u,generate_password_hash(p),r))
def assess(activity,content='',size=0,count=0,destination=''):
 score=0; reasons=[]; found=[]; text=(activity+' '+content+' '+destination).lower()
 for label,pat in PATTERNS.items():
  if pat.search(content or ''): found.append(label)
 if found: score+=min(45,15*len(found)); reasons.append('Sensitive patterns detected: '+', '.join(found))
 if any(x in text for x in ['export','download all','bulk','mass download']): score+=20; reasons.append('Bulk export/download indicator')
 if any(x in text for x in ['external','public link','personal email','unknown destination']): score+=20; reasons.append('Potentially untrusted destination')
 if size>500000: score+=10; reasons.append('Large file size (>500 KB)')
 if count>=100: score+=20; reasons.append(f'High-volume activity ({count} records)')
 if datetime.now().hour<6 or datetime.now().hour>=22: score+=10; reasons.append('Outside usual demo hours')
 score=min(score,100); level='High' if score>=60 else 'Medium' if score>=30 else 'Low'; action='Alert / review' if level=='High' else 'Monitor' if level=='Medium' else 'Allow'
 return score,level,action,'; '.join(reasons) if reasons else 'No configured risk indicators matched',found
def log_event(activity,score,level,action,reason):
 now=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
 with dbcon() as d:
  cur=d.execute('INSERT INTO logs(username,activity,score,level,reason,action,created) VALUES(?,?,?,?,?,?,?)',(session['username'],activity,score,level,reason,action,now)); lid=cur.lastrowid
  if level=='High': d.execute('INSERT INTO alerts(log_id,title,details,status,created) VALUES(?,?,?,?,?)',(lid,'High-risk activity: '+activity[:70],reason,'Open',now))
def login_required(f):
 @wraps(f)
 def w(*a,**k):
  if 'username' not in session:return redirect(url_for('login'))
  return f(*a,**k)
 return w
def admin_required(f):
 @wraps(f)
 def w(*a,**k):
  if 'username' not in session:return redirect(url_for('login'))
  if session.get('role')!='admin': flash('Admin access required.','warning'); return redirect(url_for('dashboard'))
  return f(*a,**k)
 return w
@app.route('/')
def home():return redirect(url_for('dashboard') if 'username' in session else url_for('login'))
@app.route('/login',methods=['GET','POST'])
def login():
 if request.method=='POST':
  u=request.form.get('username','').strip(); p=request.form.get('password','')
  with dbcon() as d:user=d.execute('SELECT * FROM users WHERE username=?',(u,)).fetchone()
  if user and check_password_hash(user['password_hash'],p):
   session.clear();session['username']=user['username'];session['role']=user['role'];return redirect(url_for('dashboard'))
  flash('Invalid username or password.','danger')
 return render_template('login.html')
@app.route('/logout')
def logout():session.clear();return redirect(url_for('login'))
@app.route('/dashboard')
@login_required
def dashboard():
 with dbcon() as d:
  total=d.execute('SELECT COUNT(*) n FROM logs').fetchone()['n']; high=d.execute("SELECT COUNT(*) n FROM logs WHERE level='High'").fetchone()['n']; opened=d.execute("SELECT COUNT(*) n FROM alerts WHERE status='Open'").fetchone()['n']; logs=d.execute('SELECT * FROM logs ORDER BY id DESC LIMIT 10').fetchall(); alerts=d.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 5').fetchall()
 return render_template('dashboard.html',total=total,high=high,opened=opened,logs=logs,alerts=alerts)
@app.route('/scanner',methods=['GET','POST'])
@login_required
def scanner():
 result=None
 if request.method=='POST':
  activity=request.form.get('activity','Text scan')[:180]; content=request.form.get('content','')[:20000]; score,level,action,reason,found=assess(activity,content);log_event(activity,score,level,action,reason);result=dict(score=score,level=level,action=action,reason=reason,found=found)
 return render_template('scanner.html',result=result)
@app.route('/simulate',methods=['GET','POST'])
@login_required
def simulate():
 result=None
 if request.method=='POST':
  activity=request.form.get('activity','File access')[:180];dest=request.form.get('destination','internal')[:80]
  try:size=max(0,min(int(request.form.get('file_size',0)),10000000));count=max(0,min(int(request.form.get('bulk_count',0)),1000000))
  except ValueError:size=count=0
  score,level,action,reason,_=assess(activity,'',size,count,dest);log_event(activity,score,level,action,reason);result=dict(score=score,level=level,action=action,reason=reason)
 return render_template('simulate.html',result=result)
@app.route('/logs')
@login_required
def logs():
 with dbcon() as d:rows=d.execute('SELECT * FROM logs ORDER BY id DESC LIMIT 100').fetchall()
 return render_template('logs.html',logs=rows)
@app.route('/alerts')
@login_required
def alerts():
 with dbcon() as d:rows=d.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 100').fetchall()
 return render_template('alerts.html',alerts=rows)
@app.route('/alerts/<int:aid>/resolve',methods=['POST'])
@admin_required
def resolve(aid):
 with dbcon() as d:d.execute("UPDATE alerts SET status='Reviewed' WHERE id=?",(aid,))
 flash('Alert marked as reviewed.','success');return redirect(url_for('alerts'))
if __name__=='__main__':
 init_db();app.run(debug=os.environ.get('FLASK_DEBUG')=='1',host='127.0.0.1',port=5000)
