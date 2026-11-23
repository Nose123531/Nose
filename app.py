import os
import sqlite3
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from werkzeug.security import (
    generate_password_hash, check_password_hash
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")

DB = os.environ.get("DATABASE_PATH", "users.db")
UPLOAD_FOLDER = "static/uploads"

# DB 일회성 초기화
if os.environ.get("RESET_DATABASE_ONCE") == "1":
    for suffix in ("", "-wal", "-shm"):
        path = DB + suffix
        if os.path.exists(path):
            os.remove(path)
    print("[DB] 데이터베이스 초기화 완료")

if os.path.dirname(DB):
    os.makedirs(os.path.dirname(DB), exist_ok=True)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


# 데이터베이스 연결
def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


# 컬럼 확인 및 추가
def columns(conn, table):
    return {
        row["name"]
        for row in conn.execute(f"PRAGMA table_info({table})")
    }


def add_column(conn, table, name, definition):
    if name not in columns(conn, table):
        conn.execute(
            f"ALTER TABLE {table} ADD COLUMN {name} {definition}"
        )


# 데이터베이스 초기화
def init_db():
    c = db()

    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS posts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        category TEXT DEFAULT '일반 게시물',
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS comments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER,
        user_id INTEGER,
        username TEXT,
        content TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS site_stats(
        name TEXT PRIMARY KEY,
        value INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS likes(
        user_id INTEGER,
        post_id INTEGER,
        PRIMARY KEY(user_id, post_id)
    );

    CREATE TABLE IF NOT EXISTS follows(
        follower_id INTEGER,
        following_id INTEGER,
        PRIMARY KEY(follower_id, following_id)
    );

    CREATE TABLE IF NOT EXISTS notifications(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        message TEXT,
        url TEXT,
        is_read INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        receiver_id INTEGER,
        content TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS chat_messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        content TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS admin_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin TEXT,
        action TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS visitor_days(
        day TEXT PRIMARY KEY,
        count INTEGER DEFAULT 0
    );
    """)

    for name, definition in [
        ("nickname", "TEXT"),
        ("bio", "TEXT DEFAULT ''"),
        ("avatar", "TEXT DEFAULT ''"),
        ("is_banned", "INTEGER DEFAULT 0"),
        ("is_admin", "INTEGER DEFAULT 0"),
        ("role", "TEXT DEFAULT 'user'")
    ]:
        add_column(c, "users", name, definition)

    add_column(c, "posts", "views", "INTEGER DEFAULT 0")
    add_column(c, "comments", "parent_id", "INTEGER")

    c.execute("""
        INSERT OR IGNORE INTO site_stats(name, value)
        VALUES('visitors', 0)
    """)

    c.execute("""
        UPDATE users
        SET role='admin', is_admin=1
        WHERE role='admin' OR is_admin=1
    """)

    c.commit()
    c.close()


# 관리자 계정 생성 및 갱신
def ensure_admin_account():
    admin_id = os.environ.get("ADMIN_USERNAME", "Nose").strip()
    admin_pw = os.environ.get("ADMIN_PASSWORD", "")

    if not admin_pw:
        print("[ADMIN] ADMIN_PASSWORD가 설정되지 않았습니다.")
        return

    c = db()

    try:
        existing = c.execute(
            "SELECT id FROM users WHERE username=?",
            (admin_id,)
        ).fetchone()

        password_hash = generate_password_hash(admin_pw)

        if existing:
            c.execute("""
                UPDATE users
                SET password=?,
                    role='admin',
                    is_admin=1,
                    is_banned=0
                WHERE username=?
            """, (password_hash, admin_id))

            print("[ADMIN] 관리자 계정을 갱신했습니다.")

        else:
            c.execute("""
                INSERT INTO users(
                    username, password, nickname,
                    role, is_admin, is_banned
                )
                VALUES(?, ?, ?, 'admin', 1, 0)
            """, (admin_id, password_hash, admin_id))

            print("[ADMIN] 관리자 계정을 생성했습니다.")

        c.commit()

    finally:
        c.close()


# 로그인 사용자
def current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    c = db()
    user = c.execute(
        "SELECT * FROM users WHERE id=?",
        (user_id,)
    ).fetchone()
    c.close()

    return user


# 로그인 확인
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = current_user()

        if not user:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))

        if user["is_banned"]:
            session.clear()
            flash("이용이 정지된 계정입니다.")
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return wrapper


# 관리자 확인
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = current_user()

        if not user or not (
            user["role"] == "admin" or user["is_admin"] == 1
        ):
            abort(403)

        return f(*args, **kwargs)

    return wrapper


# 알림 생성
def notify(user_id, message, url):
    if not user_id:
        return

    c = db()
    c.execute("""
        INSERT INTO notifications(user_id, message, url)
        VALUES(?,?,?)
    """, (user_id, message, url))
    c.commit()
    c.close()


# 읽지 않은 알림
def unread_count():
    if not session.get("user_id"):
        return 0

    c = db()
    count = c.execute("""
        SELECT COUNT(*)
        FROM notifications
        WHERE user_id=? AND is_read=0
    """, (session["user_id"],)).fetchone()[0]
    c.close()

    return count


@app.context_processor
def inject_globals():
    return {
        "current_user": current_user(),
        "unread_count": unread_count()
    }


# 메인 게시판
@app.route("/")
@app.route("/board")
def index():
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "")
    sort = request.args.get("sort", "latest")

    c = db()

    sql = """
        SELECT p.*,
        (SELECT COUNT(*) FROM likes l
         WHERE l.post_id=p.id) AS like_count,
        (SELECT COUNT(*) FROM comments cm
         WHERE cm.post_id=p.id) AS comment_count
        FROM posts p
        WHERE 1=1
    """

    params = []

    if q:
        sql += " AND (p.title LIKE ? OR p.content LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%"])

    if category in ("일반 게시물", "공지사항"):
        sql += " AND p.category=?"
        params.append(category)

    if sort == "popular":
        sql += " ORDER BY like_count DESC, p.id DESC"
    else:
        sql += " ORDER BY p.id DESC"

    posts = c.execute(sql, params).fetchall()
    c.close()

    return render_template(
        "index.html",
        posts=posts,
        q=q,
        category=category,
        sort=sort
    )


# 회원가입
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 2 or len(password) < 6:
            flash("아이디는 2자 이상, 비밀번호는 6자 이상이어야 합니다.")
            return redirect(url_for("register"))

        c = db()

        try:
            c.execute("""
                INSERT INTO users(username, password, nickname)
                VALUES(?,?,?)
            """, (
                username,
                generate_password_hash(password),
                username
            ))

            c.commit()
            flash("회원가입이 완료되었습니다.")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("이미 사용 중인 아이디입니다.")

        finally:
            c.close()

    return render_template("register.html")


# 로그인
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        c = db()
        user = c.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        ).fetchone()
        c.close()

        password_ok = False

        if user:
            try:
                password_ok = check_password_hash(
                    user["password"], password
                )
            except (ValueError, TypeError):
                password_ok = False

            # 예전 평문 비밀번호 데이터 호환
            if not password_ok and user["password"] == password:
                password_ok = True

                c = db()
                c.execute(
                    "UPDATE users SET password=? WHERE id=?",
                    (generate_password_hash(password), user["id"])
                )
                c.commit()
                c.close()

        if user and password_ok:
            if user["is_banned"]:
                flash("이용이 정지된 계정입니다.")
                return redirect(url_for("login"))

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            return redirect(url_for("index"))

        flash("아이디 또는 비밀번호가 올바르지 않습니다.")

    return render_template("login.html")


# 로그아웃
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# 게시글 작성
@app.route("/write", methods=["GET", "POST"])
@login_required
def write():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        category = request.form.get("category", "일반 게시물")

        user = current_user()

        if not title or not content:
            flash("제목과 내용을 입력하세요.")
            return redirect(url_for("write"))

        if user["role"] != "admin" and user["is_admin"] != 1:
            category = "일반 게시물"

        c = db()
        c.execute("""
            INSERT INTO posts(
                user_id, username, category, title, content
            )
            VALUES(?,?,?,?,?)
        """, (
            user["id"],
            user["username"],
            category,
            title,
            content
        ))
        c.commit()
        c.close()

        return redirect(url_for("index"))

    return render_template("write.html")
    # 게시글 상세
@app.route("/post/<int:post_id>")
def post(post_id):
    c = db()

    item = c.execute(
        "SELECT * FROM posts WHERE id=?",
        (post_id,)
    ).fetchone()

    if not item:
        c.close()
        abort(404)

    c.execute("""
        UPDATE posts
        SET views=COALESCE(views,0)+1
        WHERE id=?
    """, (post_id,))

    comments = c.execute("""
        SELECT * FROM comments
        WHERE post_id=?
        ORDER BY id
    """, (post_id,)).fetchall()

    like_count = c.execute(
        "SELECT COUNT(*) FROM likes WHERE post_id=?",
        (post_id,)
    ).fetchone()[0]

    liked = False

    if session.get("user_id"):
        liked = bool(c.execute("""
            SELECT 1 FROM likes
            WHERE user_id=? AND post_id=?
        """, (session["user_id"], post_id)).fetchone())

    c.commit()
    c.close()

    return render_template(
        "post.html",
        post=item,
        comments=comments,
        like_count=like_count,
        liked=liked
    )


# 좋아요
@app.route("/like/<int:post_id>", methods=["POST"])
@login_required
def like(post_id):
    c = db()

    if not c.execute(
        "SELECT id FROM posts WHERE id=?",
        (post_id,)
    ).fetchone():
        c.close()
        abort(404)

    old = c.execute("""
        SELECT 1 FROM likes
        WHERE user_id=? AND post_id=?
    """, (session["user_id"], post_id)).fetchone()

    if old:
        c.execute("""
            DELETE FROM likes
            WHERE user_id=? AND post_id=?
        """, (session["user_id"], post_id))

    else:
        c.execute("""
            INSERT OR IGNORE INTO likes(user_id, post_id)
            VALUES(?,?)
        """, (session["user_id"], post_id))

        owner = c.execute(
            "SELECT user_id FROM posts WHERE id=?",
            (post_id,)
        ).fetchone()

        if owner and owner["user_id"] != session["user_id"]:
            notify(
                owner["user_id"],
                "게시글에 좋아요가 달렸습니다.",
                url_for("post", post_id=post_id)
            )

    c.commit()
    c.close()

    return redirect(url_for("post", post_id=post_id))


# 댓글 및 대댓글
@app.route("/comment/<int:post_id>", methods=["POST"])
@login_required
def add_comment(post_id):
    content = request.form.get("content", "").strip()
    parent_id = request.form.get("parent_id", type=int)

    if not content:
        return redirect(url_for("post", post_id=post_id))

    c = db()

    if not c.execute(
        "SELECT id FROM posts WHERE id=?",
        (post_id,)
    ).fetchone():
        c.close()
        abort(404)

    if parent_id and not c.execute("""
        SELECT id FROM comments
        WHERE id=? AND post_id=?
    """, (parent_id, post_id)).fetchone():
        parent_id = None

    c.execute("""
        INSERT INTO comments(
            post_id, user_id, username, content, parent_id
        )
        VALUES(?,?,?,?,?)
    """, (
        post_id,
        session["user_id"],
        session["username"],
        content,
        parent_id
    ))

    owner = c.execute(
        "SELECT user_id FROM posts WHERE id=?",
        (post_id,)
    ).fetchone()

    if owner and owner["user_id"] != session["user_id"]:
        notify(
            owner["user_id"],
            "새 댓글이 작성되었습니다.",
            url_for("post", post_id=post_id)
        )

    c.commit()
    c.close()

    return redirect(url_for("post", post_id=post_id))


# 회원 프로필
@app.route("/profile/<int:user_id>")
def profile(user_id):
    c = db()

    user = c.execute(
        "SELECT * FROM users WHERE id=?",
        (user_id,)
    ).fetchone()

    if not user:
        c.close()
        abort(404)

    posts = c.execute("""
        SELECT * FROM posts
        WHERE user_id=?
        ORDER BY id DESC
    """, (user_id,)).fetchall()

    followers = c.execute(
        "SELECT COUNT(*) FROM follows WHERE following_id=?",
        (user_id,)
    ).fetchone()[0]

    following = c.execute(
        "SELECT COUNT(*) FROM follows WHERE follower_id=?",
        (user_id,)
    ).fetchone()[0]

    followed = False

    if session.get("user_id"):
        followed = bool(c.execute("""
            SELECT 1 FROM follows
            WHERE follower_id=? AND following_id=?
        """, (session["user_id"], user_id)).fetchone())

    c.close()

    return render_template(
        "profile.html",
        profile=user,
        posts=posts,
        followers=followers,
        following=following,
        followed=followed
    )


# 프로필 수정
@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        nickname = request.form.get("nickname", "").strip()[:30]
        bio = request.form.get("bio", "").strip()[:200]

        c = db()
        c.execute("""
            UPDATE users
            SET nickname=?, bio=?
            WHERE id=?
        """, (nickname, bio, session["user_id"]))
        c.commit()
        c.close()

        flash("프로필을 수정했습니다.")
        return redirect(url_for(
            "profile",
            user_id=session["user_id"]
        ))

    return render_template(
        "edit_profile.html",
        user=current_user()
    )


# 팔로우
@app.route("/follow/<int:user_id>", methods=["POST"])
@login_required
def follow(user_id):
    if user_id == session["user_id"]:
        abort(400)

    c = db()

    if not c.execute(
        "SELECT id FROM users WHERE id=?",
        (user_id,)
    ).fetchone():
        c.close()
        abort(404)

    old = c.execute("""
        SELECT 1 FROM follows
        WHERE follower_id=? AND following_id=?
    """, (session["user_id"], user_id)).fetchone()

    if old:
        c.execute("""
            DELETE FROM follows
            WHERE follower_id=? AND following_id=?
        """, (session["user_id"], user_id))

    else:
        c.execute("""
            INSERT OR IGNORE INTO follows(
                follower_id, following_id
            )
            VALUES(?,?)
        """, (session["user_id"], user_id))

        notify(
            user_id,
            "새로운 회원이 팔로우했습니다.",
            url_for("profile", user_id=session["user_id"])
        )

    c.commit()
    c.close()

    return redirect(url_for("profile", user_id=user_id))


# 알림
@app.route("/notifications")
@login_required
def notifications():
    c = db()

    items = c.execute("""
        SELECT * FROM notifications
        WHERE user_id=?
        ORDER BY id DESC
    """, (session["user_id"],)).fetchall()

    c.execute("""
        UPDATE notifications
        SET is_read=1
        WHERE user_id=?
    """, (session["user_id"],))

    c.commit()
    c.close()

    return render_template("notifications.html", items=items)


# 개인 쪽지
@app.route("/messages/<int:user_id>", methods=["GET", "POST"])
@login_required
def messages(user_id):
    c = db()

    if not c.execute(
        "SELECT id FROM users WHERE id=?",
        (user_id,)
    ).fetchone():
        c.close()
        abort(404)

    if request.method == "POST":
        content = request.form.get("content", "").strip()

        if content:
            c.execute("""
                INSERT INTO messages(
                    sender_id, receiver_id, content
                )
                VALUES(?,?,?)
            """, (
                session["user_id"],
                user_id,
                content[:2000]
            ))
            c.commit()

    items = c.execute("""
        SELECT * FROM messages
        WHERE (sender_id=? AND receiver_id=?)
           OR (sender_id=? AND receiver_id=?)
        ORDER BY id
    """, (
        session["user_id"],
        user_id,
        user_id,
        session["user_id"]
    )).fetchall()

    c.close()

    return render_template(
        "messages.html",
        items=items,
        target_id=user_id
    )


# 전체 채팅
@app.route("/chat", methods=["GET", "POST"])
@login_required
def chat():
    c = db()

    if request.method == "POST":
        content = request.form.get("content", "").strip()

        if content:
            c.execute("""
                INSERT INTO chat_messages(
                    user_id, username, content
                )
                VALUES(?,?,?)
            """, (
                session["user_id"],
                session["username"],
                content[:1000]
            ))
            c.commit()

    items = c.execute("""
        SELECT * FROM chat_messages
        ORDER BY id DESC
        LIMIT 100
    """).fetchall()

    c.close()

    return render_template(
        "chat.html",
        items=list(reversed(items))
    )
    # 관리자 페이지
@app.route("/admin")
@login_required
@admin_required
def admin():
    c = db()

    users = c.execute(
        "SELECT * FROM users ORDER BY id DESC"
    ).fetchall()

    posts = c.execute("""
        SELECT * FROM posts
        ORDER BY id DESC
        LIMIT 100
    """).fetchall()

    visitors = c.execute("""
        SELECT value FROM site_stats
        WHERE name='visitors'
    """).fetchone()[0]

    logs = c.execute("""
        SELECT * FROM admin_logs
        ORDER BY id DESC
        LIMIT 50
    """).fetchall()

    c.close()

    return render_template(
        "admin.html",
        users=users,
        posts=posts,
        visitors=visitors,
        logs=logs
    )


# 관리자 회원 관리
@app.route(
    "/admin/user/<int:user_id>/<action>",
    methods=["POST"]
)
@login_required
@admin_required
def admin_user(user_id, action):
    if user_id == session["user_id"]:
        abort(400)

    c = db()

    if action == "ban":
        c.execute(
            "UPDATE users SET is_banned=1 WHERE id=?",
            (user_id,)
        )

    elif action == "unban":
        c.execute(
            "UPDATE users SET is_banned=0 WHERE id=?",
            (user_id,)
        )

    elif action == "delete":
        c.execute(
            "DELETE FROM users WHERE id=?",
            (user_id,)
        )

        c.execute("""
            DELETE FROM follows
            WHERE follower_id=? OR following_id=?
        """, (user_id, user_id))

        c.execute(
            "DELETE FROM likes WHERE user_id=?",
            (user_id,)
        )

    else:
        c.close()
        abort(400)

    c.execute("""
        INSERT INTO admin_logs(admin, action)
        VALUES(?,?)
    """, (
        session["username"],
        f"{action}: user {user_id}"
    ))

    c.commit()
    c.close()

    return redirect(url_for("admin"))


# 관리자 게시글 삭제
@app.route(
    "/admin/post/<int:post_id>/delete",
    methods=["POST"]
)
@login_required
@admin_required
def admin_delete_post(post_id):
    c = db()

    c.execute(
        "DELETE FROM comments WHERE post_id=?",
        (post_id,)
    )

    c.execute(
        "DELETE FROM likes WHERE post_id=?",
        (post_id,)
    )

    c.execute(
        "DELETE FROM posts WHERE id=?",
        (post_id,)
    )

    c.execute("""
        INSERT INTO admin_logs(admin, action)
        VALUES(?,?)
    """, (
        session["username"],
        f"delete post {post_id}"
    ))

    c.commit()
    c.close()

    return redirect(url_for("admin"))


# 오류 페이지
@app.errorhandler(403)
def forbidden(e):
    return render_template(
        "error.html",
        code=403,
        message="접근 권한이 없습니다."
    ), 403


@app.errorhandler(404)
def not_found(e):
    return render_template(
        "error.html",
        code=404,
        message="페이지를 찾을 수 없습니다."
    ), 404


# 앱 시작 시 DB 초기화 및 관리자 계정 설정
init_db()
ensure_admin_account()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )