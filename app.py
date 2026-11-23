
import os
import sqlite3
import argparse
from pathlib import Path
from functools import wraps
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

app = Flask(__name__)
app.secret_key = os.environ.get(
    "SECRET_KEY", "nose-local-secret-change-this"
)

DB_PATH = os.environ.get(
    "DB_PATH",
    str(Path(__file__).resolve().parent / "users.db")
)


def db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

    conn = db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            category TEXT DEFAULT '일반 게시물',
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 방문자 통계 테이블
    conn.execute("""
        CREATE TABLE IF NOT EXISTS site_stats (
            name TEXT PRIMARY KEY,
            value INTEGER NOT NULL DEFAULT 0
        )
    """)

    conn.execute("""
        INSERT OR IGNORE INTO site_stats (name, value)
        VALUES ('visitors', 0)
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS visitor_days (
            visit_date TEXT PRIMARY KEY,
            count INTEGER NOT NULL DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if session.get("username") != "Nose":
            abort(403)
        return func(*args, **kwargs)
    return wrapper


@app.before_request
def count_visitor():
    if request.endpoint == "static":
        return

    try:
        conn = db()

        conn.execute("""
            UPDATE site_stats
            SET value = value + 1
            WHERE name = 'visitors'
        """)

        today = datetime.now().strftime("%Y-%m-%d")

        conn.execute("""
            INSERT INTO visitor_days (visit_date, count)
            VALUES (?, 1)
            ON CONFLICT(visit_date)
            DO UPDATE SET count = count + 1
        """, (today,))

        conn.commit()
        conn.close()

    except sqlite3.Error:
        app.logger.exception("방문자 수 기록 오류")


@app.route("/")
def index():
    conn = db()

    posts = conn.execute("""
        SELECT * FROM posts
        ORDER BY id DESC
        LIMIT 5
    """).fetchall()

    conn.close()

    return render_template("index.html", posts=posts)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("아이디와 비밀번호를 입력하세요.")
            return redirect(url_for("register"))

        if len(username) > 30 or len(password) < 4:
            flash("아이디는 30자 이하, 비밀번호는 4자 이상이어야 합니다.")
            return redirect(url_for("register"))

        conn = db()

        try:
            conn.execute("""
                INSERT INTO users (username, password)
                VALUES (?, ?)
            """, (
                username,
                generate_password_hash(password)
            ))

            conn.commit()
            flash("회원가입이 완료되었습니다.")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("이미 존재하는 아이디입니다.")

        finally:
            conn.close()

    return render_template("register.html")


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
            return redirect(url_for("index"))

        flash("아이디 또는 비밀번호가 틀렸습니다.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/profile")
@login_required
def profile():
    conn = db()

    user = conn.execute("""
        SELECT * FROM users
        WHERE id = ?
    """, (session["user_id"],)).fetchone()

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


@app.route("/board")
def board():
    conn = db()

    posts = conn.execute("""
        SELECT * FROM posts
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template("board.html", posts=posts)


@app.route("/write", methods=["GET", "POST"])
@login_required
def write():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        category = request.form.get(
            "category", "일반 게시물"
        ).strip()

        if not title or not content:
            flash("제목과 내용을 입력하세요.")
            return redirect(url_for("write"))

        if category not in ("일반 게시물", "공지사항"):
            category = "일반 게시물"

        conn = db()

        conn.execute("""
            INSERT INTO posts
            (user_id, username, category, title, content)
            VALUES (?, ?, ?, ?, ?)
        """, (
            session["user_id"],
            session["username"],
            category,
            title,
            content
        ))

        conn.commit()
        conn.close()

        return redirect(url_for("board"))

    return render_template("write.html")


@app.route("/post/<int:post_id>")
def post(post_id):
    conn = db()

    post_data = conn.execute("""
        SELECT * FROM posts
        WHERE id = ?
    """, (post_id,)).fetchone()

    if post_data is None:
        conn.close()
        abort(404)

    comments = conn.execute("""
        SELECT * FROM comments
        WHERE post_id = ?
        ORDER BY id ASC
    """, (post_id,)).fetchall()

    conn.close()

    return render_template(
        "post.html",
        post=post_data,
        comments=comments
    )


@app.route("/delete/<int:post_id>", methods=["POST"])
@login_required
def delete_post(post_id):
    conn = db()

    post_data = conn.execute("""
        SELECT * FROM posts
        WHERE id = ?
    """, (post_id,)).fetchone()

    if post_data is None:
        conn.close()
        abort(404)

    if (
        post_data["user_id"] != session["user_id"]
        and session.get("username") != "Nose"
    ):
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

    return redirect(url_for("board"))


@app.route(
    "/post/<int:post_id>/comment",
    methods=["POST"]
)
@login_required
def add_comment(post_id):
    content = request.form.get("content", "").strip()

    if not content:
        return redirect(url_for("post", post_id=post_id))

    conn = db()

    exists = conn.execute("""
        SELECT id FROM posts
        WHERE id = ?
    """, (post_id,)).fetchone()

    if exists is None:
        conn.close()
        abort(404)

    conn.execute("""
        INSERT INTO comments
        (post_id, user_id, username, content)
        VALUES (?, ?, ?, ?)
    """, (
        post_id,
        session["user_id"],
        session["username"],
        content
    ))

    conn.commit()
    conn.close()

    return redirect(url_for("post", post_id=post_id))


@app.route(
    "/comment/<int:comment_id>/delete",
    methods=["POST"]
)
@login_required
def delete_comment(comment_id):
    conn = db()

    comment = conn.execute("""
        SELECT * FROM comments
        WHERE id = ?
    """, (comment_id,)).fetchone()

    if comment is None:
        conn.close()
        abort(404)

    if (
        comment["user_id"] != session["user_id"]
        and session.get("username") != "Nose"
    ):
        conn.close()
        abort(403)

    post_id = comment["post_id"]

    conn.execute("""
        DELETE FROM comments
        WHERE id = ?
    """, (comment_id,))

    conn.commit()
    conn.close()

    return redirect(url_for("post", post_id=post_id))


@app.route("/admin")
@login_required
@admin_required
def admin():
    conn = db()

    users = conn.execute("""
        SELECT * FROM users
        ORDER BY id DESC
    """).fetchall()

    posts = conn.execute("""
        SELECT * FROM posts
        ORDER BY id DESC
    """).fetchall()

    visitor_count = conn.execute("""
        SELECT value FROM site_stats
        WHERE name = 'visitors'
    """).fetchone()

    today = datetime.now().strftime("%Y-%m-%d")

    today_count = conn.execute("""
        SELECT count FROM visitor_days
        WHERE visit_date = ?
    """, (today,)).fetchone()

    conn.close()

    return render_template(
        "admin.html",
        users=users,
        posts=posts,
        visitor_count=visitor_count["value"] if visitor_count else 0,
        today_count=today_count["count"] if today_count else 0
    )


@app.route(
    "/admin/user/<int:user_id>/delete",
    methods=["POST"]
)
@login_required
@admin_required
def delete_user(user_id):
    if user_id == session["user_id"]:
        abort(400)

    conn = db()

    conn.execute(
        "DELETE FROM comments WHERE user_id = ?",
        (user_id,)
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

    return redirect(url_for("admin"))


@app.errorhandler(404)
def not_found(error):
    return "페이지를 찾을 수 없습니다.", 404


@app.errorhandler(403)
def forbidden(error):
    return "접근 권한이 없습니다.", 403


# Gunicorn에서도 데이터베이스 초기화
init_db()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--create-admin", action="store_true")
    args = parser.parse_args()

    if args.create_admin:
        print("관리자 계정은 별도로 생성해야 합니다.")
    else:
        app.run(
            host="0.0.0.0",
            port=int(os.environ.get("PORT", 5000)),
            debug=True
        )
