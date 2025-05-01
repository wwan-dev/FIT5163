from __future__ import annotations
import os, json, hashlib, sqlite3
from pathlib import Path
from datetime import datetime

from flask import (
    Flask, render_template_string, redirect, url_for,
    flash, abort, request
)
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    current_user, logout_user
)
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, RadioField
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import generate_csrf

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


KEY_DIR = Path("keys")
PUB_FILE, PRIV_FILE = KEY_DIR/"election_pub.pem", KEY_DIR/"election_priv.pem"

def load_keys():
    KEY_DIR.mkdir(exist_ok=True)
    if not (PUB_FILE.exists() and PRIV_FILE.exists()):
        k = RSA.generate(2048)
        PUB_FILE.write_bytes(k.public_key().export_key())
        PRIV_FILE.write_bytes(k.export_key())
    return (
        RSA.import_key(PUB_FILE.read_bytes()),
        RSA.import_key(PRIV_FILE.read_bytes()),
    )

PUBLIC_KEY, PRIVATE_KEY = load_keys()
CIPHER_PUB = PKCS1_OAEP.new(PUBLIC_KEY)
CIPHER_PRIV = PKCS1_OAEP.new(PRIVATE_KEY)

# ───────────────── Flask 基础 ──────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET", os.urandom(24))
csrf = CSRFProtect(app)
login_manager = LoginManager(app); login_manager.login_view = "login"

DB_PATH = "voting_demo2.db"
RECEIPT_FILE = "receipts.log"
CHAIN_FILE = "blockchain.json"

# ──────────────── 区块链辅助函数 ────────────────
def load_chain():
    if not os.path.exists(CHAIN_FILE):
        return []
    with open(CHAIN_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_chain(chain):
    with open(CHAIN_FILE, "w", encoding="utf-8") as f:
        json.dump(chain, f, indent=2, ensure_ascii=False)

def add_block(data: dict):
    chain = load_chain()
    prev_hash = (
        hashlib.sha256(json.dumps(chain[-1], sort_keys=True).encode()).hexdigest()
        if chain else "0"*64
    )
    block = {
        "index": len(chain),
        "timestamp": datetime.utcnow().isoformat(),
        "data": data,
        "previous_hash": prev_hash,
    }
    chain.append(block)
    save_chain(chain)

# ──────────────── 数据库与模型 ────────────────
def init_db():
    with sqlite3.connect(DB_PATH) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE, password_hash TEXT,
            has_voted INTEGER DEFAULT 0, is_admin INTEGER DEFAULT 0)""")
        c.execute("""CREATE TABLE IF NOT EXISTS ballots(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER, encrypted_vote BLOB,
            receipt_hash TEXT, timestamp TEXT)""")

def query_one(sql, p=()):
    with sqlite3.connect(DB_PATH) as c:
        c.row_factory = sqlite3.Row
        return c.execute(sql,p).fetchone()

def execute_sql(sql,p=()):
    with sqlite3.connect(DB_PATH) as c:
        c.execute(sql,p); c.commit()

init_db()

class User(UserMixin):
    def __init__(self, id, username, pw, voted, admin):
        self.id, self.username = id, username
        self.password_hash, self.has_voted, self.is_admin = pw, bool(voted), bool(admin)
    @staticmethod
    def get(uid): row=query_one("SELECT * FROM users WHERE id=?", (uid,)); return User(*row) if row else None
@login_manager.user_loader
def load_user(uid): return User.get(uid)

# ──────────────── 表单 ────────────────
class RegistrationForm(FlaskForm):
    username = StringField("用户名", validators=[DataRequired(), Length(3,30)])
    password = PasswordField("密码", validators=[DataRequired(), Length(6,128)])
    confirm  = PasswordField("确认密码", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("注册")

class LoginForm(FlaskForm):
    username = StringField("用户名", validators=[DataRequired()])
    password = PasswordField("密码", validators=[DataRequired()])
    submit = SubmitField("登录")

class VoteForm(FlaskForm):
    choice = RadioField("请选择候选人", choices=[("Alice","Alice"),("Bob","Bob"),("Charlie","Charlie")],
                        validators=[DataRequired()])
    submit = SubmitField("投票")

# ──────────────── 视图 ────────────────
@app.route("/")
def index():
    html="""<h2>安全投票系统示例</h2>
    {% if current_user.is_authenticated %}
      <p>您好，{{ current_user.username }}。</p>
      <p><a href='{{ url_for("vote") }}'>投票 / 查看投票</a> |
         <a href='{{ url_for("verify_receipt") }}'>验证收据</a> |
         <a href='{{ url_for("logout") }}'>退出</a></p>
      {% if current_user.is_admin %}
        <p><a href='{{ url_for("tally") }}'>查看结果</a> |
           <a href='{{ url_for("receipts_page") }}'>收据列表</a> |
           <a href='{{ url_for("view_chain") }}'>区块链</a></p>
      {% endif %}
    {% else %}
      <p><a href='{{ url_for("login") }}'>登录</a> 或 <a href='{{ url_for("register") }}'>注册</a></p>
    {% endif %}"""
    return render_template_string(html)

# ---- 注册 / 登录 / 登出 ----
@app.route("/register", methods=["GET","POST"])
def register():
    if current_user.is_authenticated: return redirect(url_for("index"))
    form = RegistrationForm()
    if form.validate_on_submit():
        if query_one("SELECT 1 FROM users WHERE username=?", (form.username.data,)):
            flash("用户名已存在","danger")
        else:
            execute_sql("INSERT INTO users(username,password_hash) VALUES(?,?)",
                        (form.username.data, generate_password_hash(form.password.data)))
            flash("注册成功，请登录","success"); return redirect(url_for("login"))
    return render_template_string("""
        <h3>注册</h3><form method='POST'>{{ form.hidden_tag() }}
        {{ form.username.label }} {{ form.username() }}<br>
        {{ form.password.label }} {{ form.password() }}<br>
        {{ form.confirm.label }}  {{ form.confirm() }}<br>
        {{ form.submit() }}</form>""", form=form)

@app.route("/login", methods=["GET","POST"])
def login():
    if current_user.is_authenticated: return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        row = query_one("SELECT * FROM users WHERE username=?", (form.username.data,))
        if row and check_password_hash(row["password_hash"], form.password.data):
            login_user(User(*row)); flash("登录成功","success"); return redirect(url_for("index"))
        flash("用户名或密码错误","danger")
    return render_template_string("""
        <h3>登录</h3><form method='POST'>{{ form.hidden_tag() }}
        {{ form.username.label }} {{ form.username() }}<br>
        {{ form.password.label }} {{ form.password() }}<br>
        {{ form.submit() }}</form>""", form=form)

@app.route("/logout")
@login_required
def logout(): logout_user(); flash("已退出","info"); return redirect(url_for("index"))

@app.route("/vote", methods=["GET","POST"])
@login_required
def vote():
    if current_user.has_voted:
        bal=query_one("SELECT receipt_hash FROM ballots WHERE user_id=?", (current_user.id,))
        return render_template_string(
            "<h3>您已完成投票。</h3><p>收据：<code>{{ r }}</code></p>", r=bal["receipt_hash"])
    form = VoteForm()
    if form.validate_on_submit():
        ciphertext = CIPHER_PUB.encrypt(form.choice.data.encode())
        receipt = hashlib.sha256(ciphertext).hexdigest()

        # 写选票
        execute_sql("INSERT INTO ballots(user_id,encrypted_vote,receipt_hash,timestamp) VALUES(?,?,?,?)",
                    (current_user.id, ciphertext, receipt, datetime.utcnow().isoformat()))
        execute_sql("UPDATE users SET has_voted=1 WHERE id=?", (current_user.id,))
        current_user.has_voted = True

        # 写收据文件（供公开验证）
        with open(RECEIPT_FILE,"a",encoding="utf-8") as f: f.write(receipt+"\n")

        # 写区块链
        add_block({
            "user_id": current_user.id,      # 仍记录，但只有管理员能解密找回
            "receipt": receipt,
            "ciphertext": ciphertext.hex()
        })

        flash("投票成功！请妥善保存收据。","success")
        return redirect(url_for("vote"))
    return render_template_string(
        "<h3>投票</h3><form method='POST'>{{ form.hidden_tag() }}"
        "{% for s in form.choice %}{{s()}}{{s.label.text}}<br>{% endfor %}"
        "{{ form.submit() }}</form>", form=form)


@app.route("/receipts")
@login_required
def receipts_page():
    receipts=[]
    if os.path.exists(RECEIPT_FILE):
        with open(RECEIPT_FILE) as f: receipts=[l.strip() for l in f.readlines()]
    return render_template_string("<h3>收据列表</h3><pre>{{r|join('\\n')}}</pre>", r=receipts)


@csrf.exempt
@app.route("/verify", methods=["GET","POST"])
def verify_receipt():
    msg = ""
    if request.method == "POST":
        rc = request.form.get("receipt", "").strip()
        if rc and os.path.exists(RECEIPT_FILE):
            with open(RECEIPT_FILE) as f:
                valid = set(line.strip() for line in f)
            msg = "您的选票已被计入" if rc in valid else "未找到该收据"
    return render_template_string(
        msg=msg,
        csrf=generate_csrf(),
    )


@app.route("/chain")
@login_required
def view_chain():
    if not current_user.is_admin: abort(403)
    return f"<pre>{json.dumps(load_chain(),indent=2,ensure_ascii=False)}</pre>"

@app.route("/tally")
@login_required
def tally():
    if not current_user.is_admin: abort(403)
    counts={"Alice":0,"Bob":0,"Charlie":0}
    with sqlite3.connect(DB_PATH) as c:
        for (enc,) in c.execute("SELECT encrypted_vote FROM ballots"):
            try:
                choice=CIPHER_PRIV.decrypt(enc).decode()
                if choice in counts: counts[choice]+=1
            except ValueError: pass
    return render_template_string("<h3>计票结果</h3>"+"".join(f"<p>{k}: {v}</p>" for k,v in counts.items()))

if __name__ == "__main__":
    init_db()
    print("1")
    try:
        user_exists = query_one("SELECT 1 FROM users LIMIT 1")
        print("2")
    except sqlite3.OperationalError:
        init_db()
        user_exists = None
    print(user_exists)
    if user_exists is None:
        pwd = "admin1234"
        execute_sql(
            "INSERT INTO users(username,password_hash,is_admin) VALUES(?,?,1)",
            ("admin", generate_password_hash(pwd))
        )
        print("[*] 已创建管理员：admin /", pwd)
    app.run(host="0.0.0.0", port=80, debug=True)