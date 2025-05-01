# secure_voting_demo_app.py (修正版)
"""
安全在线投票系统示例（Flask 单文件）
Bug 修复：解决 "block 'body' defined twice" 异常
------------------------------------------------------------
原因：采用 `render_template_string` 时，我们把 `TEMPLATE_BASE` 与子模板直接拼接，
结果一个字符串里重复定义了同名 Jinja2 block，触发 `TemplateAssertionError`。

修正策略：**完全去掉 block 语法**，直接内联最小 HTML 片段即可。
在教学 demo 中我们不需要继承机制，保持模板极简即可避免冲突。
"""

from __future__ import annotations

import os
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime

from flask import (
    Flask, render_template_string, redirect, url_for,
    flash, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    current_user, logout_user
)
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, RadioField
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------------------------------------------------------
#  加密工具函数
# ---------------------------------------------------------------------------
try:
    from Cryptodome.PublicKey import RSA  # PyCryptodome 替代 Crypto
    from Cryptodome.Cipher import PKCS1_OAEP
except ImportError as exc:
    raise ImportError("请先安装 PyCryptodome：pip install pycryptodome") from exc

KEY_DIR = Path("keys")
PUBLIC_KEY_FILE = KEY_DIR / "election_pub.pem"
PRIVATE_KEY_FILE = KEY_DIR / "election_priv.pem"


def generate_or_load_rsa() -> tuple[RSA.RsaKey, RSA.RsaKey]:
    """首次运行生成 2048 位 RSA 密钥对，否则直接读取。"""
    KEY_DIR.mkdir(exist_ok=True)
    if not PUBLIC_KEY_FILE.exists() or not PRIVATE_KEY_FILE.exists():
        key = RSA.generate(2048)
        PUBLIC_KEY_FILE.write_bytes(key.public_key().export_key())
        PRIVATE_KEY_FILE.write_bytes(key.export_key(passphrase=None))
    pub = RSA.import_key(PUBLIC_KEY_FILE.read_bytes())
    priv = RSA.import_key(PRIVATE_KEY_FILE.read_bytes())
    return pub, priv


PUBLIC_KEY, PRIVATE_KEY = generate_or_load_rsa()
CIPHER = PKCS1_OAEP.new(PUBLIC_KEY)  # 使用公钥加密

# ---------------------------------------------------------------------------
#  Flask 与数据库初始化
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET", os.urandom(24)),  # 会话加密密钥
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

DB_PATH = "voting_demo.db"


# -------------------------- 数据库辅助函数 -------------------------------

def init_db():
    """若表不存在则创建。"""
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        # 用户表
        cur.execute(
            """CREATE TABLE IF NOT EXISTS users (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT UNIQUE NOT NULL,
                   password_hash TEXT NOT NULL,
                   has_voted INTEGER DEFAULT 0,
                   is_admin INTEGER DEFAULT 0
               )""")
        # 选票表
        cur.execute(
            """CREATE TABLE IF NOT EXISTS ballots (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   user_id INTEGER NOT NULL,
                   encrypted_vote BLOB NOT NULL,
                   receipt_hash TEXT NOT NULL,
                   timestamp TEXT NOT NULL,
                   FOREIGN KEY(user_id) REFERENCES users(id)
               )""")
        conn.commit()


init_db()


class User(UserMixin):
    """简单封装，便于 Flask-Login 与 SQLite 协作。"""

    def __init__(self, id_: int, username: str, password_hash: str, has_voted: int, is_admin: int):
        self.id = id_  # Flask-Login 需要 id 属性
        self.username = username
        self.password_hash = password_hash
        self.has_voted = bool(has_voted)
        self.is_admin = bool(is_admin)

    @staticmethod
    def get(user_id: int | str) -> "User | None":
        row = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
        return User(*row) if row else None


# ---------------------------------------------------------------------------
#  通用数据库操作封装
# ---------------------------------------------------------------------------

def query_one(sql: str, params: tuple = ()):  # 查询单行
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(sql, params).fetchone()


def execute_sql(sql: str, params: tuple = ()) -> None:  # 写操作
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(sql, params)
        conn.commit()


# ---------------------------------------------------------------------------
#  Flask-Login 回调
# ---------------------------------------------------------------------------
@login_manager.user_loader
def load_user(user_id):  # noqa: ANN001
    return User.get(user_id)


# ---------------------------------------------------------------------------
#  WTForms 表单定义
# ---------------------------------------------------------------------------
class RegistrationForm(FlaskForm):
    username = StringField("用户名", validators=[DataRequired(), Length(3, 30)])
    password = PasswordField("密码", validators=[DataRequired(), Length(6, 128)])
    confirm = PasswordField("确认密码", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("注册")


class LoginForm(FlaskForm):
    username = StringField("用户名", validators=[DataRequired()])
    password = PasswordField("密码", validators=[DataRequired()])
    submit = SubmitField("登录")


class VoteForm(FlaskForm):
    choice = RadioField("请选择候选人", choices=[("Alice", "Alice"), ("Bob", "Bob"), ("Charlie", "Charlie")],
                        validators=[DataRequired()])
    submit = SubmitField("投票")


# ---------------------------------------------------------------------------
#  路由
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """首页：根据登录状态展示入口。"""
    html = """
    <h2>安全投票系统示例</h2>
    {% if current_user.is_authenticated %}
        <p>您好，{{ current_user.username }}。</p>
        <p><a href='{{ url_for("vote") }}'>投票 / 查看投票</a> | <a href='{{ url_for("logout") }}'>退出</a></p>
        {% if current_user.is_admin %}
            <p><a href='{{ url_for("tally") }}'>查看结果</a> | <a href='{{ url_for("receipts") }}'>收据列表</a></p>
        {% endif %}
    {% else %}
        <p><a href='{{ url_for("login") }}'>登录</a> 或 <a href='{{ url_for("register") }}'>注册</a></p>
    {% endif %}
    """
    return render_template_string(html)


# ---------------------- 注册与登录 ------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = RegistrationForm()
    if form.validate_on_submit():
        if query_one("SELECT id FROM users WHERE username = ?", (form.username.data,)):
            flash("用户名已被占用", "danger")
        else:
            pwd_hash = generate_password_hash(form.password.data)
            execute_sql("INSERT INTO users (username, password_hash) VALUES (?, ?)", (form.username.data, pwd_hash))
            flash("注册成功，请登录。", "success")
            return redirect(url_for("login"))
    html = """
      <h3>注册</h3>
      <form method='POST'>{{ form.hidden_tag() }}
        {{ form.username.label }} {{ form.username() }}<br>
        {{ form.password.label }} {{ form.password() }}<br>
        {{ form.confirm.label }} {{ form.confirm() }}<br>
        {{ form.submit() }}
      </form>
    """
    return render_template_string(html, form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        row = query_one("SELECT * FROM users WHERE username = ?", (form.username.data,))
        if row and check_password_hash(row["password_hash"], form.password.data):
            login_user(User(*row))
            flash("登录成功。", "success")
            return redirect(url_for("index"))
        flash("用户名或密码错误", "danger")
    html = """
      <h3>登录</h3>
      <form method='POST'>{{ form.hidden_tag() }}
        {{ form.username.label }} {{ form.username() }}<br>
        {{ form.password.label }} {{ form.password() }}<br>
        {{ form.submit() }}
      </form>
    """
    return render_template_string(html, form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("已退出登录。", "info")
    return redirect(url_for("index"))


# ----------------------------- 投票 -----------------------------
@app.route("/vote", methods=["GET", "POST"])
@login_required
def vote():
    # 如果用户已投票，显示收据
    if current_user.has_voted:
        ballot = query_one("SELECT receipt_hash FROM ballots WHERE user_id = ?", (current_user.id,))
        return render_template_string(
            "<h3>您已完成投票。</h3><p>收据：<code>{{ r }}</code></p><p><a href='/'>返回首页</a></p>",
            r=ballot["receipt_hash"])

    form = VoteForm()
    if form.validate_on_submit():
        # 加密投票选项
        plaintext = form.choice.data.encode()
        ciphertext = CIPHER.encrypt(plaintext)

        # 生成收据哈希
        receipt_hash = hashlib.sha256(ciphertext).hexdigest()

        # 保存到数据库
        execute_sql(
            "INSERT INTO ballots (user_id, encrypted_vote, receipt_hash, timestamp) VALUES (?, ?, ?, ?)",
            (current_user.id, ciphertext, receipt_hash, datetime.utcnow().isoformat())
        )

        # 更新用户状态为已投票
        execute_sql("UPDATE users SET has_voted = 1 WHERE id = ?", (current_user.id,))
        current_user.has_voted = True

        flash("投票成功！您的收据如下。", "success")
        return redirect(url_for("vote"))

    # 首次加载表单
    return render_template_string(
        """
        <h3>投票</h3>
        <form method="POST">
            {{ form.hidden_tag() }}
            {% for sub in form.choice %}
                {{ sub() }} {{ sub.label.text }}<br>
            {% endfor %}
            {{ form.submit() }}
        </form>
        """, form=form
    )