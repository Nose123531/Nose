
import os
import sqlite3
import sys
from functools import wraps
from getpass import getpass

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from werkzeug.security import generate_password_hash, check_password_hash


# -----------------------------
# 기본 설정
# -----------------------------

app = Flask(__name__)
app.secret_key = os.environ.get(
    "NOSE_SECRET_KEY",
    "nose-change-this-secret-key"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")


# -----------------------------
# 데이터베이스
# -----------------------------

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def add_column_if_missing(conn, table, column, definition):
    columns = [
        row["name"]
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    ]

    if column not in columns:
        conn.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )


def init_db():
    conn = db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            category TEXT DEFAULT '자유',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # 기존 데이터베이스에 필요한 열 추가
    add_column_if_missing(conn, "users", "role", "TEXT DEFAULT 'user'")
    add_column_if_missing(
        conn, "users", "created_at", "TEXT DEFAULT CURRENT_TIMESTAMP"
    )

    add_column_if_missing(conn, "posts", "category", "TEXT DEFAULT '자유'")
    add_column_if_missing(
        conn, "posts", "created_at", "TEXT DEFAULT CURRENT_TIMESTAMP"
    )

    # 댓글 테이블
    conn.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # 방문자 수
    conn.execute("""
        CREATE TABLE IF NOT EXISTS site_stats (
            name TEXT PRIMARY KEY,
            value INTEGER DEFAULT 0
        )
    """)

    conn.execute("""
        INSERT OR IGNORE INTO site_stats (name, value)
        VALUES ('visitors', 0)
    """)

    conn.commit()
    conn.close()


# -----------------------------
# 로그인 / 권한
# -----------------------------

def get_current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    conn = db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    conn.close()

    return user


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))

        return func(*args, **kwargs)

    return wrapper


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = get_current_user()

        if not user or user["role"] != "admin":
            abort(403)

        return func(*args, **kwargs)

    return wrapper


# -----------------------------
# 방문자 수
# -----------------------------

@app.before_request
def count_visitor():
    if request.endpoint == "static":
        return

    if not session.get("visited"):
        conn = db()
        conn.execute("""
            UPDATE site_stats
            SET value = value + 1
            WHERE name = 'visitors'
        """)
        conn.commit()
        conn.close()

        session["visited"] = True


# -----------------------------
# 메인 페이지
# -----------------------------

@app.route("/")
def index():
    conn = db()

    visitor = conn.execute("""
        SELECT value FROM site_stats
        WHERE name = 'visitors'
    """).fetchone()

    latest_posts = conn.execute("""
        SELECT posts.*, users.username
        FROM posts
        JOIN users ON users.id = posts.user_id
        ORDER BY posts.id DESC
        LIMIT 5
    """).fetchall()

    conn.close()

    visitor_count = visitor["value"] if visitor else 0

    return render_template(
        "index.html",
        visitor_count=visitor_count,
        latest_posts=latest_posts
    )


# -----------------------------
# 회원가입
# -----------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 2 or len(username) > 20:
            flash("아이디는 2~20자로 입력해 주세요.")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("비밀번호는 6자 이상 입력해 주세요.")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        conn = db()

        try:
            conn.execute("""
                INSERT INTO users (username, password, role)
                VALUES (?, ?, 'user')
            """, (username, hashed_password))

            conn.commit()

        except sqlite3.IntegrityError:
            conn.close()
            flash("이미 사용 중인 아이디입니다.")
            return redirect(url_for("register"))

        conn.close()

        flash("회원가입이 완료되었습니다.")
        return redirect(url_for("login"))

    return render_template("register.html")


# -----------------------------
# 로그인
# -----------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = db()
        user = conn.execute("""
            SELECT * FROM users
            WHERE username = ?
        """, (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            flash("로그인되었습니다.")
            return redirect(url_for("index"))

        flash("아이디 또는 비밀번호가 올바르지 않습니다.")

    return render_template("login.html")


# -----------------------------
# 로그아웃
# -----------------------------

@app.route("/logout")
def logout():
    session.clear()
    flash("로그아웃되었습니다.")
    return redirect(url_for("index"))


# -----------------------------
# 프로필
# -----------------------------

@app.route("/profile")
@login_required
def profile():
    user = get_current_user()

    conn = db()
    posts = conn.execute("""
        SELECT * FROM posts
        WHERE user_id = ?
        ORDER BY id DESC
    """, (session["user_id"],)).fetchall()
    conn.close()

    return render_template(
        "profile.html",
        user=user,
        posts=posts
    )


# -----------------------------
# 게시판
# -----------------------------

@app.route("/board")
def board():
    category = request.args.get("category", "").strip()

    conn = db()

    if category == "공지":
        posts = conn.execute("""
            SELECT posts.*, users.username
            FROM posts
            JOIN users ON users.id = posts.user_id
            WHERE posts.category = '공지'
            ORDER BY posts.id DESC
        """).fetchall()

    elif category == "자유":
        posts = conn.execute("""
            SELECT posts.*, users.username
            FROM posts
            JOIN users ON users.id = posts.user_id
            WHERE posts.category IN ('자유', '일반')
            ORDER BY posts.id DESC
        """).fetchall()

    else:
        posts = conn.execute("""
            SELECT posts.*, users.username
            FROM posts
            JOIN users ON users.id = posts.user_id
            ORDER BY posts.id DESC
        """).fetchall()

    conn.close()

    return render_template(
        "board.html",
        posts=posts,
        selected_category=category
    )


# -----------------------------
# 게시글 작성
# -----------------------------

@app.route("/write", methods=["GET", "POST"])
@login_required
def write():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        category = request.form.get("category", "자유").strip()

        if not title or not content:
            flash("제목과 내용을 입력해 주세요.")
            return redirect(url_for("write"))

        if len(title) > 100 or len(content) > 5000:
            flash("제목 또는 내용이 너무 깁니다.")
            return redirect(url_for("write"))

        if category not in ("공지", "자유"):
            category = "자유"

        user = get_current_user()

        if category == "공지" and (
            not user or user["role"] != "admin"
        ):
            abort(403)

        conn = db()
        conn.execute("""
            INSERT INTO posts (user_id, title, content, category)
            VALUES (?, ?, ?, ?)
        """, (
            session["user_id"],
            title,
            content,
            category
        ))

        conn.commit()
        conn.close()

        flash("게시글이 등록되었습니다.")
        return redirect(url_for("board"))

    return render_template("write.html")


# -----------------------------
# 게시글 상세 보기
# -----------------------------

@app.route("/post/<int:post_id>")
def post_detail(post_id):
    conn = db()

    post = conn.execute("""
        SELECT posts.*, users.username
        FROM posts
        JOIN users ON users.id = posts.user_id
        WHERE posts.id = ?
    """, (post_id,)).fetchone()

    if not post:
        conn.close()
        abort(404)

    comments = conn.execute("""
        SELECT comments.*, users.username
        FROM comments
        JOIN users ON users.id = comments.user_id
        WHERE comments.post_id = ?
        ORDER BY comments.id ASC
    """, (post_id,)).fetchall()

    conn.close()

    return render_template(
        "post.html",
        post=post,
        comments=comments
    )


# -----------------------------
# 게시글 삭제
# -----------------------------

@app.route("/delete/<int:post_id>", methods=["POST"])
@login_required
def delete_post(post_id):
    user = get_current_user()

    conn = db()

    post = conn.execute("""
        SELECT * FROM posts WHERE id = ?
    """, (post_id,)).fetchone()

    if not post:
        conn.close()
        abort(404)

    if post["user_id"] != user["id"] and user["role"] != "admin":
        conn.close()
        abort(403)

    conn.execute(
        "DELETE FROM comments WHERE post_id = ?",
        (post_id,)
    )

    conn.execute(
        "DELETE FROM posts WHERE id = ?",
        (post_id,)
    )

    conn.commit()
    conn.close()

    flash("게시글이 삭제되었습니다.")
    return redirect(url_for("board"))


# -----------------------------
# 댓글 작성
# -----------------------------

@app.route("/post/<int:post_id>/comment", methods=["POST"])
@login_required
def add_comment(post_id):
    content = request.form.get("content", "").strip()

    if not content:
        flash("댓글 내용을 입력해 주세요.")
        return redirect(url_for("post_detail", post_id=post_id))

    if len(content) > 1000:
        flash("댓글은 1000자 이하로 작성해 주세요.")
        return redirect(url_for("post_detail", post_id=post_id))

    conn = db()

    post = conn.execute(
        "SELECT id FROM posts WHERE id = ?",
        (post_id,)
    ).fetchone()

    if not post:
        conn.close()
        abort(404)

    conn.execute("""
        INSERT INTO comments (post_id, user_id, content)
        VALUES (?, ?, ?)
    """, (
        post_id,
        session["user_id"],
        content
    ))

    conn.commit()
    conn.close()

    flash("댓글이 등록되었습니다.")
    return redirect(url_for("post_detail", post_id=post_id))


# -----------------------------
# 댓글 삭제
# -----------------------------

@app.route("/comment/<int:comment_id>/delete", methods=["POST"])
@login_required
def delete_comment(comment_id):
    user = get_current_user()

    conn = db()

    comment = conn.execute("""
        SELECT * FROM comments
        WHERE id = ?
    """, (comment_id,)).fetchone()

    if not comment:
        conn.close()
        abort(404)

    if (
        comment["user_id"] != user["id"]
        and user["role"] != "admin"
    ):
        conn.close()
        abort(403)

    post_id = comment["post_id"]

    conn.execute(
        "DELETE FROM comments WHERE id = ?",
        (comment_id,)
    )

    conn.commit()
    conn.close()

    flash("댓글이 삭제되었습니다.")
    return redirect(url_for("post_detail", post_id=post_id))


# -----------------------------
# 관리자 페이지
# -----------------------------

@app.route("/admin")
@admin_required
def admin():
    conn = db()

    users = conn.execute("""
        SELECT id, username, role, created_at
        FROM users
        ORDER BY id DESC
    """).fetchall()

    posts = conn.execute("""
        SELECT posts.*, users.username
        FROM posts
        JOIN users ON users.id = posts.user_id
        ORDER BY posts.id DESC
    """).fetchall()

    comments = conn.execute("""
        SELECT comments.*, users.username
        FROM comments
        JOIN users ON users.id = comments.user_id
        ORDER BY comments.id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "admin.html",
        users=users,
        posts=posts,
        comments=comments
    )


# -----------------------------
# 관리자 회원 삭제
# -----------------------------

@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    if user_id == session.get("user_id"):
        flash("현재 로그인한 관리자 계정은 삭제할 수 없습니다.")
        return redirect(url_for("admin"))

    conn = db()

    user = conn.execute(
        "SELECT id FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not user:
        conn.close()
        abort(404)

    # 회원이 작성한 댓글 삭제
    conn.execute(
        "DELETE FROM comments WHERE user_id = ?",
        (user_id,)
    )

    # 회원이 작성한 게시글과 해당 댓글 삭제
    user_posts = conn.execute(
        "SELECT id FROM posts WHERE user_id = ?",
        (user_id,)
    ).fetchall()

    for post in user_posts:
        conn.execute(
            "DELETE FROM comments WHERE post_id = ?",
            (post["id"],)
        )

    conn.execute(
        "DELETE FROM posts WHERE user_id = ?",
        (user_id,)
    )

    conn.execute(
        "DELETE FROM users WHERE id = ?",
        (user_id,)
    )

    conn.commit()
    conn.close()

    flash("회원이 삭제되었습니다.")
    return redirect(url_for("admin"))


# -----------------------------
# 오류 페이지
# -----------------------------

@app.errorhandler(403)
def forbidden(error):
    return "접근 권한이 없습니다. (403)", 403


@app.errorhandler(404)
def not_found(error):
    return "페이지를 찾을 수 없습니다. (404)", 404


# -----------------------------
# 관리자 계정 생성 / 변경
# -----------------------------

def create_admin():
    username = "Nose"

    password = getpass("관리자 비밀번호 입력: ")
    confirm = getpass("비밀번호 다시 입력: ")

    if not password or password != confirm:
        print("비밀번호가 비어 있거나 서로 다릅니다.")
        return

    hashed_password = generate_password_hash(password)

    conn = db()

    user = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if user:
        conn.execute("""
            UPDATE users
            SET password = ?, role = 'admin'
            WHERE username = ?
        """, (hashed_password, username))

        print("기존 Nose 계정을 관리자로 변경했습니다.")

    else:
        conn.execute("""
            INSERT INTO users (username, password, role)
            VALUES (?, ?, 'admin')
        """, (username, hashed_password))

        print("관리자 계정을 만들었습니다.")

    conn.commit()
    conn.close()


# -----------------------------
# 실행
# -----------------------------

if __name__ == "__main__":
 init_db()

if __name__ == "__main__":
    if "--create-admin" in sys.argv:
        create_admin()
    else:
        app.run(host="127.0.0.1", port=5000, debug=True)
