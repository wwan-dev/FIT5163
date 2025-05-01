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

# ─────────────── Flask base ───────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET", os.urandom(24))
csrf = CSRFProtect(app)
login_manager = LoginManager(app); login_manager.login_view = "login"

DB_PATH = "voting_demo2.db"
RECEIPT_FILE = "receipts.log"
CHAIN_FILE = "blockchain.json"

# ─────────────── Blockchain helpers ───────────────
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

# ─────────────── DB models ───────────────
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
        return c.execute(sql, p).fetchone()

def execute_sql(sql, p=()):
    with sqlite3.connect(DB_PATH) as c:
        c.execute(sql, p); c.commit()

init_db()

class User(UserMixin):
    def __init__(self, id, username, pw, voted, admin):
        self.id, self.username = id, username
        self.password_hash, self.has_voted, self.is_admin = pw, bool(voted), bool(admin)
    @staticmethod
    def get(uid): 
        row = query_one("SELECT * FROM users WHERE id=?", (uid,))
        return User(*row) if row else None

@login_manager.user_loader
def load_user(uid): return User.get(uid)

# ─────────────── Forms ───────────────
class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(3,30)])
    password = PasswordField("Password", validators=[DataRequired(), Length(6,128)])
    confirm  = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class VoteForm(FlaskForm):
    choice = RadioField("Please select a candidate", choices=[("Alice","Alice"),("Bob","Bob"),("Charlie","Charlie")],
                        validators=[DataRequired()])
    submit = SubmitField("Submit Vote")

# ─────────────── Views ───────────────
@app.route("/")
def index():
    html="""<h2>Secure Voting System Demo</h2>
    {% if current_user.is_authenticated %}
      <p>Hello, {{ current_user.username }}.</p>
      <p><a href='{{ url_for("vote") }}'>Vote / View Ballot</a> |
         <a href='{{ url_for("verify_receipt") }}'>Verify Receipt</a> |
         <a href='{{ url_for("logout") }}'>Logout</a></p>
      {% if current_user.is_admin %}
        <p><a href='{{ url_for("tally") }}'>View Tally</a> |
           <a href='{{ url_for("receipts_page") }}'>Receipt List</a> |
           <a href='{{ url_for("view_chain") }}'>Blockchain</a></p>
      {% endif %}
    {% else %}
      <p><a href='{{ url_for("login") }}'>Login</a> or <a href='{{ url_for("register") }}'>Register</a></p>
    {% endif %}"""
    return render_template_string(html)

@app.route("/register", methods=["GET","POST"])
def register():
    if current_user.is_authenticated: return redirect(url_for("index"))
    form = RegistrationForm()
    if form.validate_on_submit():
        if query_one("SELECT 1 FROM users WHERE username=?", (form.username.data,)):
            flash("Username already exists", "danger")
        else:
            execute_sql("INSERT INTO users(username,password_hash) VALUES(?,?)",
                        (form.username.data, generate_password_hash(form.password.data)))
            flash("Registration successful, please login", "success")
            return redirect(url_for("login"))
    return render_template_string("""<h3>Register</h3>
        <form method='POST'>{{ form.hidden_tag() }}
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
            login_user(User(*row)); flash("Login successful", "success"); return redirect(url_for("index"))
        flash("Invalid username or password", "danger")
    return render_template_string("""<h3>Login</h3>
        <form method='POST'>{{ form.hidden_tag() }}
        {{ form.username.label }} {{ form.username() }}<br>
        {{ form.password.label }} {{ form.password() }}<br>
        {{ form.submit() }}</form>""", form=form)

@app.route("/logout")
@login_required
def logout(): 
    logout_user(); flash("Logged out", "info"); return redirect(url_for("index"))

@app.route("/vote", methods=["GET","POST"])
@login_required
def vote():
    if current_user.has_voted:
        bal = query_one("SELECT receipt_hash FROM ballots WHERE user_id=?", (current_user.id,))
        return render_template_string(
            "<h3>You have already voted.</h3><p>Receipt: <code>{{ r }}</code></p>", r=bal["receipt_hash"])
    form = VoteForm()
    if form.validate_on_submit():
        ciphertext = CIPHER_PUB.encrypt(form.choice.data.encode())
        receipt = hashlib.sha256(ciphertext).hexdigest()

        execute_sql("INSERT INTO ballots(user_id,encrypted_vote,receipt_hash,timestamp) VALUES(?,?,?,?)",
                    (current_user.id, ciphertext, receipt, datetime.utcnow().isoformat()))
        execute_sql("UPDATE users SET has_voted=1 WHERE id=?", (current_user.id,))
        current_user.has_voted = True

        with open(RECEIPT_FILE,"a",encoding="utf-8") as f: f.write(receipt+"\n")

        add_block({
            "user_id": current_user.id,
            "receipt": receipt,
            "ciphertext": ciphertext.hex()
        })

        flash("Vote successful! Please keep your receipt safe.", "success")
        return redirect(url_for("vote"))
    return render_template_string(
        "<h3>Vote</h3><form method='POST'>{{ form.hidden_tag() }}{% for s in form.choice %}{{s()}}{{s.label.text}}<br>{% endfor %}{{ form.submit() }}</form>", form=form)

@app.route("/receipts")
@login_required
def receipts_page():
    receipts=[]
    if os.path.exists(RECEIPT_FILE):
        with open(RECEIPT_FILE) as f: receipts=[l.strip() for l in f.readlines()]
    return render_template_string("<h3>Receipt List</h3><pre>{{r|join('\\n')}}</pre>", r=receipts)

@csrf.exempt
@app.route("/verify", methods=["GET","POST"])
def verify_receipt():
    msg = ""
    if request.method == "POST":
        rc = request.form.get("receipt", "").strip()
        if rc and os.path.exists(RECEIPT_FILE):
            with open(RECEIPT_FILE) as f:
                valid = set(line.strip() for line in f)
            msg = "Your vote has been counted" if rc in valid else "Receipt not found"
    return render_template_string(
        "<h3>Verify Receipt</h3><form method='POST'><input name='receipt'><input type='submit'></form><p>{{msg}}</p>",
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
                choice = CIPHER_PRIV.decrypt(enc).decode()
                if choice in counts: counts[choice] += 1
            except ValueError: pass
    return render_template_string("<h3>Tally Results</h3>" + "".join(f"<p>{k}: {v}</p>" for k,v in counts.items()))

if __name__ == "__main__":
    init_db()
    try:
        user_exists = query_one("SELECT 1 FROM users LIMIT 1")
    except sqlite3.OperationalError:
        init_db()
        user_exists = None
    if user_exists is None:
        pwd = "admin1234"
        execute_sql(
            "INSERT INTO users(username,password_hash,is_admin) VALUES(?,?,1)",
            ("admin", generate_password_hash(pwd))
        )
        print("[*] Admin account created: admin /", pwd)
    app.run(host="0.0.0.0", port=80, debug=True)
