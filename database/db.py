import os
import sqlite3
import datetime
import random


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_DIR, "xuanchat.db")
PUBLIC_ROOM_NAME = "公共房间"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def generate_room_code(cur):
    while True:
        code = "".join(random.choice("0123456789") for _ in range(6))
        cur.execute("SELECT 1 FROM rooms WHERE room_code = ?", (code,))
        if not cur.fetchone():
            return code


def init_db():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = get_connection()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login_at TEXT
        );

        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS room_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            joined_at TEXT NOT NULL,
            UNIQUE(room_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ws_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            protocol TEXT DEFAULT 'ws',
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            path TEXT DEFAULT '/',
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            UNIQUE(user_id, friend_id)
        );

        CREATE TABLE IF NOT EXISTS room_bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            banned_at TEXT NOT NULL,
            UNIQUE(room_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS room_join_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            UNIQUE(room_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS ai_models (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            api_url TEXT,
            api_base TEXT NOT NULL,
            api_key TEXT NOT NULL,
            model_name TEXT NOT NULL,
            prompt TEXT,
            is_active INTEGER DEFAULT 1,
            total_prompt_tokens INTEGER DEFAULT 0,
            total_completion_tokens INTEGER DEFAULT 0,
            total_tokens INTEGER DEFAULT 0,
            total_requests INTEGER DEFAULT 0,
            last_latency_ms REAL,
            last_test_at TEXT,
            created_at TEXT NOT NULL,
            is_default INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS chat_interfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            command TEXT UNIQUE NOT NULL,
            url TEXT NOT NULL,
            token TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS admin_menus (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT,
            icon TEXT,
            url TEXT NOT NULL,
            sort_order INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT
        );

        CREATE TABLE IF NOT EXISTS role_menus (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role_id INTEGER NOT NULL,
            menu_id INTEGER NOT NULL,
            UNIQUE(role_id, menu_id)
        );

        CREATE TABLE IF NOT EXISTS admin_roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            role_id INTEGER NOT NULL,
            UNIQUE(admin_id, role_id)
        );

        CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);
        CREATE INDEX IF NOT EXISTS idx_users_is_ai ON users(is_ai);
        CREATE INDEX IF NOT EXISTS idx_users_is_banned ON users(is_banned);
        """
    )

    cur.execute("PRAGMA table_info(users)")
    columns = [info[1] for info in cur.fetchall()]
    if "is_banned" not in columns:
        cur.execute("ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0")
    if "is_ai" not in columns:
        cur.execute("ALTER TABLE users ADD COLUMN is_ai INTEGER DEFAULT 0")

    if "avatar" not in columns:
        cur.execute("ALTER TABLE users ADD COLUMN avatar TEXT")

    cur.execute("PRAGMA table_info(rooms)")
    columns = [info[1] for info in cur.fetchall()]
    if "is_banned" not in columns:
        cur.execute("ALTER TABLE rooms ADD COLUMN is_banned INTEGER DEFAULT 0")

    if "creator_id" not in columns:
        cur.execute("ALTER TABLE rooms ADD COLUMN creator_id INTEGER")

    if "is_private" not in columns:
        cur.execute("ALTER TABLE rooms ADD COLUMN is_private INTEGER DEFAULT 0")

    if "room_code" not in columns:
        cur.execute("ALTER TABLE rooms ADD COLUMN room_code TEXT")
        cur.execute("SELECT id FROM rooms")
        room_rows = cur.fetchall()
        for r in room_rows:
            code = generate_room_code(cur)
            cur.execute(
                "UPDATE rooms SET room_code = ? WHERE id = ?",
                (code, r["id"]),
            )
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_rooms_room_code ON rooms(room_code)"
        )

    if "announcement" not in columns:
        cur.execute("ALTER TABLE rooms ADD COLUMN announcement TEXT")

    cur.execute("PRAGMA table_info(room_members)")
    columns = [info[1] for info in cur.fetchall()]
    if "last_read_at" not in columns:
        cur.execute("ALTER TABLE room_members ADD COLUMN last_read_at TEXT")

    if "role" not in columns:
        cur.execute("ALTER TABLE room_members ADD COLUMN role TEXT DEFAULT 'member'")

    cur.execute("PRAGMA table_info(ai_models)")
    columns = [info[1] for info in cur.fetchall()]
    if columns:
        if "api_base" not in columns:
            cur.execute(
                "ALTER TABLE ai_models ADD COLUMN api_base TEXT NOT NULL DEFAULT ''"
            )
        if "model_name" not in columns:
            cur.execute("ALTER TABLE ai_models ADD COLUMN model_name TEXT")
        if "prompt" not in columns:
            cur.execute("ALTER TABLE ai_models ADD COLUMN prompt TEXT")
        if "is_active" not in columns:
            cur.execute(
                "ALTER TABLE ai_models ADD COLUMN is_active INTEGER DEFAULT 1"
            )
        if "is_default" not in columns:
            cur.execute(
                "ALTER TABLE ai_models ADD COLUMN is_default INTEGER DEFAULT 0"
            )
        if "total_prompt_tokens" not in columns:
            cur.execute(
                "ALTER TABLE ai_models ADD COLUMN total_prompt_tokens INTEGER DEFAULT 0"
            )
        if "total_completion_tokens" not in columns:
            cur.execute(
                "ALTER TABLE ai_models ADD COLUMN total_completion_tokens INTEGER DEFAULT 0"
            )
        if "total_tokens" not in columns:
            cur.execute(
                "ALTER TABLE ai_models ADD COLUMN total_tokens INTEGER DEFAULT 0"
            )
        if "total_requests" not in columns:
            cur.execute(
                "ALTER TABLE ai_models ADD COLUMN total_requests INTEGER DEFAULT 0"
            )
        if "last_latency_ms" not in columns:
            cur.execute("ALTER TABLE ai_models ADD COLUMN last_latency_ms REAL")
        if "last_test_at" not in columns:
            cur.execute("ALTER TABLE ai_models ADD COLUMN last_test_at TEXT")
        if "created_at" not in columns:
            cur.execute(
                "ALTER TABLE ai_models ADD COLUMN created_at TEXT NOT NULL DEFAULT ''"
            )

        if "api_url" in columns and "api_base" in columns:
            cur.execute(
                """
                UPDATE ai_models
                SET api_base = api_url
                WHERE (api_base IS NULL OR api_base = '')
                  AND api_url IS NOT NULL
                  AND api_url <> ''
                """
            )

        if "model" in columns and "model_name" in columns:
            cur.execute(
                """
                UPDATE ai_models
                SET model_name = model
                WHERE (model_name IS NULL OR model_name = '')
                  AND model IS NOT NULL
                  AND model <> ''
                """
            )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS room_bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            banned_at TEXT NOT NULL,
            UNIQUE(room_id, user_id)
        );
        """
    )

    # Add default admin
    cur.execute("SELECT id FROM admins WHERE username = ?", ("admin",))
    if not cur.fetchone():
        cur.execute("INSERT INTO admins (username, password) VALUES (?, ?)", ("admin", "admin888"))

    # Add AI user "内小妹"
    cur.execute("SELECT id FROM users WHERE username = ?", ("内小妹",))
    ai_user = cur.fetchone()
    if not ai_user:
        now = datetime.datetime.utcnow().isoformat()
        # Random password hash for security
        dummy_hash = "pbkdf2:sha256:600000$dummy$dummy" 
        cur.execute(
            "INSERT INTO users (username, password_hash, created_at, last_login_at, is_ai) VALUES (?, ?, ?, ?, 1)",
            ("内小妹", dummy_hash, now, now)
        )
    else:
        # Ensure is_ai is set to 1 for existing user
        cur.execute("UPDATE users SET is_ai = 1 WHERE username = ?", ("内小妹",))

    # Add default ws server
    cur.execute("SELECT id FROM ws_servers WHERE name = ?", ("Local Dev Server",))
    if not cur.fetchone():
        now = datetime.datetime.utcnow().isoformat()
        cur.execute(
            "INSERT INTO ws_servers (name, host, port, path, created_at) VALUES (?, ?, ?, ?, ?)",
            ("Local Dev Server", "127.0.0.1", 5000, "/ws", now)
        )

    cur.execute("SELECT id FROM rooms WHERE name = ?", (PUBLIC_ROOM_NAME,))
    row = cur.fetchone()
    if not row:
        now = datetime.datetime.utcnow().isoformat()
        cur.execute(
            "INSERT INTO rooms (name, created_at) VALUES (?, ?)",
            (PUBLIC_ROOM_NAME, now),
        )
    conn.commit()
    conn.close()


def get_user_by_username(username):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row


def get_ai_user():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE is_ai = 1 LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row


def create_user(username, password_hash):
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()
    cur.execute(
        "INSERT INTO users (username, password_hash, created_at, last_login_at) VALUES (?, ?, ?, ?)",
        (username, password_hash, now, now),
    )
    conn.commit()
    conn.close()


def update_user_avatar(username, avatar_path):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET avatar = ? WHERE username = ?",
        (avatar_path, username),
    )
    conn.commit()
    conn.close()


def update_user_nickname(username, new_nickname):
    conn = get_connection()
    cur = conn.cursor()
    # Check if nickname already exists
    cur.execute("SELECT id FROM users WHERE username = ?", (new_nickname,))
    if cur.fetchone():
        conn.close()
        return False, "昵称已存在"
    
    cur.execute(
        "UPDATE users SET username = ? WHERE username = ?",
        (new_nickname, username),
    )
    conn.commit()
    conn.close()
    return True, "修改成功"


def update_user_password(username, new_password_hash):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (new_password_hash, username),
    )
    conn.commit()
    conn.close()



def update_last_login(user_id):
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()
    cur.execute(
        "UPDATE users SET last_login_at = ? WHERE id = ?",
        (now, user_id),
    )
    conn.commit()
    conn.close()


def save_message(username, content, room_name=PUBLIC_ROOM_NAME):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        # Auto-create user for interfaces/bots if they don't exist
        now = datetime.datetime.utcnow().isoformat()
        dummy_hash = "pbkdf2:sha256:600000$dummy$interface"
        cur.execute(
            "INSERT INTO users (username, password_hash, created_at, last_login_at, is_ai) VALUES (?, ?, ?, ?, 0)",
            (username, dummy_hash, now, now)
        )
        user_id = cur.lastrowid
    else:
        user_id = user_row["id"]
    cur.execute("SELECT id, room_code FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    if not room_row:
        now = datetime.datetime.utcnow().isoformat()
        room_code = generate_room_code(cur)
        cur.execute(
            "INSERT INTO rooms (name, created_at, creator_id, room_code) VALUES (?, ?, ?, ?)",
            (room_name, now, user_id, room_code),
        )
        room_id = cur.lastrowid
    else:
        room_id = room_row["id"]
    now = datetime.datetime.utcnow().isoformat()
    cur.execute(
        "INSERT INTO messages (room_id, user_id, content, created_at) VALUES (?, ?, ?, ?)",
        (room_id, user_id, content, now),
    )
    
    # Update sender's last_read_at automatically
    cur.execute(
        "UPDATE room_members SET last_read_at = ? WHERE room_id = ? AND user_id = ?",
        (now, room_id, user_id)
    )
    
    conn.commit()
    conn.close()


def get_recent_messages(limit=10, room_name=PUBLIC_ROOM_NAME):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    if not room_row:
        conn.close()
        return []
    room_id = room_row["id"]
    cur.execute(
        """
        SELECT m.content, m.created_at, u.username, u.avatar
        FROM messages m
        JOIN users u ON m.user_id = u.id
        WHERE m.room_id = ?
        ORDER BY m.id DESC
        LIMIT ?
        """,
        (room_id, limit),
    )
    rows = cur.fetchall()
    conn.close()
    rows = list(rows)[::-1]
    messages = []
    for r in rows:
        created_at = r["created_at"]
        try:
            dt = datetime.datetime.fromisoformat(created_at)
            time_str = dt.strftime("%H:%M")
        except Exception:
            time_str = ""
        messages.append(
            {
                "username": r["username"],
                "avatar": r["avatar"],
                "content": r["content"],
                "time": time_str,
            }
        )
    return messages


def count_messages():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM messages")
    count = cur.fetchone()[0]
    conn.close()
    return count


def get_or_create_private_room(user_id_1, user_id_2):
    # Ensure sorted order for consistency
    u1, u2 = sorted([user_id_1, user_id_2])
    room_name = f"private_{u1}_{u2}"
    
    conn = get_connection()
    cur = conn.cursor()
    
    # Check if room exists
    cur.execute("SELECT id FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    
    if not room_row:
        now = datetime.datetime.utcnow().isoformat()
        # Create room with is_private=1
        cur.execute(
            "INSERT INTO rooms (name, created_at, is_private) VALUES (?, ?, 1)",
            (room_name, now),
        )
        room_id = cur.lastrowid
    else:
        room_id = room_row["id"]
        
    # Ensure both users are members
    for uid in [user_id_1, user_id_2]:
        cur.execute(
            "SELECT id FROM room_members WHERE room_id = ? AND user_id = ?",
            (room_id, uid),
        )
        if not cur.fetchone():
            now = datetime.datetime.utcnow().isoformat()
            cur.execute(
                "INSERT INTO room_members (room_id, user_id, joined_at) VALUES (?, ?, ?)",
                (room_id, uid, now),
            )
            
    conn.commit()
    conn.close()
    return room_name


def ensure_user_in_room(username, room_name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return
    user_id = user_row["id"]
    cur.execute("SELECT id, creator_id FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    if not room_row:
        now = datetime.datetime.utcnow().isoformat()
        room_code = generate_room_code(cur)
        cur.execute(
            "INSERT INTO rooms (name, created_at, creator_id, room_code) VALUES (?, ?, ?, ?)",
            (room_name, now, user_id, room_code),
        )
        room_id = cur.lastrowid
        creator_id = user_id
    else:
        room_id = room_row["id"]
        creator_id = room_row["creator_id"]
    cur.execute(
        "SELECT id FROM room_members WHERE room_id = ? AND user_id = ?",
        (room_id, user_id),
    )
    row = cur.fetchone()
    if not row:
        now = datetime.datetime.utcnow().isoformat()
        cur.execute(
            "INSERT INTO room_members (room_id, user_id, joined_at) VALUES (?, ?, ?)",
            (room_id, user_id, now),
        )
        if creator_id == user_id:
            cur.execute(
                "UPDATE room_members SET role = ? WHERE room_id = ? AND user_id = ?",
                ("owner", room_id, user_id),
            )
    conn.commit()
    conn.close()


def get_admin(username, password):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM admins WHERE username = ? AND password = ?", (username, password))
    row = cur.fetchone()
    conn.close()
    return row


def get_active_admin_menus(limit=200):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT *
        FROM admin_menus
        WHERE is_active = 1
        ORDER BY sort_order ASC, id ASC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def get_admin_menus(limit=20, offset=0):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT *
        FROM admin_menus
        ORDER BY sort_order ASC, id ASC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def count_admin_menus():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM admin_menus")
    count = cur.fetchone()[0]
    conn.close()
    return count


def add_admin_menu(name, category, icon, url, sort_order=0, is_active=1):
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()
    cur.execute(
        """
        INSERT INTO admin_menus (name, category, icon, url, sort_order, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (name, category, icon, url, sort_order, 1 if is_active else 0, now),
    )
    conn.commit()
    menu_id = cur.lastrowid
    conn.close()
    return menu_id


def update_admin_menu(menu_id, name, category, icon, url, sort_order=0, is_active=1):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE admin_menus
        SET name = ?, category = ?, icon = ?, url = ?, sort_order = ?, is_active = ?
        WHERE id = ?
        """,
        (name, category, icon, url, sort_order, 1 if is_active else 0, menu_id),
    )
    conn.commit()
    conn.close()
    return True


def get_ai_employees(limit=20, offset=0):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM users WHERE is_ai = 1 ORDER BY id ASC LIMIT ? OFFSET ?",
        (limit, offset),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def count_ai_employees():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users WHERE is_ai = 1")
    count = cur.fetchone()[0]
    conn.close()
    return count


def add_ai_employee(username, password_hash, title):
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()
    try:
        cur.execute(
            """
            INSERT INTO users (username, password_hash, created_at, is_ai, title, is_banned)
            VALUES (?, ?, ?, 1, ?, 0)
            """,
            (username, password_hash, now, title),
        )
        conn.commit()
        user_id = cur.lastrowid
        conn.close()
        return user_id
    except sqlite3.IntegrityError:
        conn.close()
        return None


def update_ai_employee(user_id, title, is_banned):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET title = ?, is_banned = ? WHERE id = ? AND is_ai = 1",
        (title, 1 if is_banned else 0, user_id),
    )
    conn.commit()
    conn.close()
    return True


def get_ai_employee_by_id(user_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ? AND is_ai = 1", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row


def delete_admin_menu(menu_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM admin_menus WHERE id = ?", (menu_id,))
    cur.execute("DELETE FROM role_menus WHERE menu_id = ?", (menu_id,))
    conn.commit()
    conn.close()
    return True


def get_admin_menu_by_id(menu_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM admin_menus WHERE id = ?", (menu_id,))
    row = cur.fetchone()
    conn.close()
    return row


def get_roles(limit=20, offset=0):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT *
        FROM roles
        ORDER BY id ASC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def count_roles():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM roles")
    count = cur.fetchone()[0]
    conn.close()
    return count


def get_role_by_id(role_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM roles WHERE id = ?", (role_id,))
    row = cur.fetchone()
    conn.close()
    return row


def add_role(name, description):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO roles (name, description) VALUES (?, ?)",
            (name, description),
        )
        conn.commit()
        role_id = cur.lastrowid
    except sqlite3.IntegrityError:
        role_id = None
    conn.close()
    return role_id


def update_role(role_id, name, description):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "UPDATE roles SET name = ?, description = ? WHERE id = ?",
            (name, description, role_id),
        )
        conn.commit()
        ok = True
    except sqlite3.IntegrityError:
        ok = False
    conn.close()
    return ok


def delete_role(role_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM roles WHERE id = ?", (role_id,))
    cur.execute("DELETE FROM role_menus WHERE role_id = ?", (role_id,))
    cur.execute("DELETE FROM admin_roles WHERE role_id = ?", (role_id,))
    conn.commit()
    conn.close()
    return True


def get_role_menu_ids(role_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT menu_id FROM role_menus WHERE role_id = ? ORDER BY menu_id ASC",
        (role_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return [r["menu_id"] for r in rows]


def set_role_menus(role_id, menu_ids):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM role_menus WHERE role_id = ?", (role_id,))
    for mid in menu_ids:
        cur.execute(
            "INSERT OR IGNORE INTO role_menus (role_id, menu_id) VALUES (?, ?)",
            (role_id, mid),
        )
    conn.commit()
    conn.close()
    return True


def get_admins(limit=20, offset=0):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT *
        FROM admins
        ORDER BY id ASC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def count_admins():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM admins")
    count = cur.fetchone()[0]
    conn.close()
    return count


def get_admin_by_id(admin_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM admins WHERE id = ?", (admin_id,))
    row = cur.fetchone()
    conn.close()
    return row


def create_admin(username, password):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO admins (username, password) VALUES (?, ?)",
            (username, password),
        )
        conn.commit()
        admin_id = cur.lastrowid
    except sqlite3.IntegrityError:
        admin_id = None
    conn.close()
    return admin_id


def update_admin(admin_id, username, password=None):
    conn = get_connection()
    cur = conn.cursor()
    try:
        if password is not None:
            cur.execute(
                "UPDATE admins SET username = ?, password = ? WHERE id = ?",
                (username, password, admin_id),
            )
        else:
            cur.execute(
                "UPDATE admins SET username = ? WHERE id = ?",
                (username, admin_id),
            )
        conn.commit()
        ok = True
    except sqlite3.IntegrityError:
        ok = False
    conn.close()
    return ok


def delete_admin(admin_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM admins WHERE id = ?", (admin_id,))
    cur.execute("DELETE FROM admin_roles WHERE admin_id = ?", (admin_id,))
    conn.commit()
    conn.close()
    return True


def get_admin_role_ids(admin_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT role_id FROM admin_roles WHERE admin_id = ? ORDER BY role_id ASC",
        (admin_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return [r["role_id"] for r in rows]


def set_admin_roles(admin_id, role_ids):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM admin_roles WHERE admin_id = ?", (admin_id,))
    for rid in role_ids:
        cur.execute(
            "INSERT OR IGNORE INTO admin_roles (admin_id, role_id) VALUES (?, ?)",
            (admin_id, rid),
        )
    conn.commit()
    conn.close()
    return True


def get_admin_menus_for_admin(admin_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT m.*
        FROM admin_menus m
        JOIN role_menus rm ON m.id = rm.menu_id
        JOIN admin_roles ar ON rm.role_id = ar.role_id
        WHERE ar.admin_id = ?
          AND m.is_active = 1
        GROUP BY m.id
        ORDER BY m.sort_order ASC, m.id ASC
        """,
        (admin_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def get_all_users(limit=20, offset=0, query=None):
    conn = get_connection()
    cur = conn.cursor()
    if query:
        cur.execute("SELECT * FROM users WHERE username LIKE ? ORDER BY id ASC LIMIT ? OFFSET ?", (f'%{query}%', limit, offset))
    else:
        cur.execute("SELECT * FROM users ORDER BY id ASC LIMIT ? OFFSET ?", (limit, offset))
    rows = cur.fetchall()
    conn.close()
    return rows


def count_users(query=None):
    conn = get_connection()
    cur = conn.cursor()
    if query:
        cur.execute("SELECT COUNT(*) FROM users WHERE username LIKE ?", (f'%{query}%',))
    else:
        cur.execute("SELECT COUNT(*) FROM users")
    count = cur.fetchone()[0]
    conn.close()
    return count


def count_banned_users():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users WHERE is_banned = 1")
    count = cur.fetchone()[0]
    conn.close()
    return count


def get_user_by_id(user_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row


def update_user_by_admin(user_id, username, password_hash=None):
    conn = get_connection()
    cur = conn.cursor()
    if password_hash:
        cur.execute("UPDATE users SET username = ?, password_hash = ? WHERE id = ?", (username, password_hash, user_id))
    else:
        cur.execute("UPDATE users SET username = ? WHERE id = ?", (username, user_id))
    conn.commit()
    conn.close()


def delete_user(user_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def batch_delete_users(user_ids):
    conn = get_connection()
    cur = conn.cursor()
    # sqlite supports parameter substitution for IN clause dynamically
    placeholders = ','.join('?' * len(user_ids))
    sql = f"DELETE FROM users WHERE id IN ({placeholders})"
    cur.execute(sql, user_ids)
    conn.commit()
    conn.close()


def set_user_ban_status(user_id, is_banned):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_banned = ? WHERE id = ?", (1 if is_banned else 0, user_id))
    conn.commit()
    conn.close()


def batch_set_user_ban_status(user_ids, is_banned):
    conn = get_connection()
    cur = conn.cursor()
    placeholders = ','.join('?' * len(user_ids))
    sql = f"UPDATE users SET is_banned = ? WHERE id IN ({placeholders})"
    params = [1 if is_banned else 0] + user_ids
    cur.execute(sql, params)
    conn.commit()
    conn.close()


def get_all_rooms_with_stats(limit=12, offset=0):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT 
            r.*,
            u_creator.username as creator_name,
            (SELECT COUNT(*) FROM room_members rm WHERE rm.room_id = r.id) as member_count,
            (SELECT COUNT(*) FROM room_members rm JOIN users u ON rm.user_id = u.id WHERE rm.room_id = r.id AND u.is_banned = 1) as banned_member_count
        FROM rooms r
        LEFT JOIN users u_creator ON r.creator_id = u_creator.id
        ORDER BY r.id ASC
        LIMIT ? OFFSET ?
    """, (limit, offset))
    rows = cur.fetchall()
    conn.close()
    return rows


def count_rooms():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM rooms")
    count = cur.fetchone()[0]
    conn.close()
    return count


def count_banned_rooms():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM rooms WHERE is_banned = 1")
    count = cur.fetchone()[0]
    conn.close()
    return count


def get_room_by_id(room_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM rooms WHERE id = ?", (room_id,))
    row = cur.fetchone()
    conn.close()
    return row


def get_room_by_name(room_name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM rooms WHERE name = ?", (room_name,))
    row = cur.fetchone()
    conn.close()
    return row


def get_room_by_code(room_code):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM rooms WHERE room_code = ?", (room_code,))
    row = cur.fetchone()
    conn.close()
    return row


def get_room_with_creator(room_name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT r.*, u.username as creator_name
        FROM rooms r
        LEFT JOIN users u ON r.creator_id = u.id
        WHERE r.name = ?
        """,
        (room_name,),
    )
    row = cur.fetchone()
    conn.close()
    return row


def delete_room(room_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM rooms WHERE id = ?", (room_id,))
    cur.execute("DELETE FROM room_members WHERE room_id = ?", (room_id,))
    cur.execute("DELETE FROM messages WHERE room_id = ?", (room_id,))
    conn.commit()
    conn.close()


def set_room_ban_status(room_id, is_banned):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE rooms SET is_banned = ? WHERE id = ?", (1 if is_banned else 0, room_id))
    conn.commit()
    conn.close()


def get_room_members_list(room_id, limit=20, offset=0):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.*, rm.joined_at, rm.role
        FROM room_members rm
        JOIN users u ON rm.user_id = u.id
        WHERE rm.room_id = ?
        ORDER BY rm.joined_at DESC
        LIMIT ? OFFSET ?
    """, (room_id, limit, offset))
    rows = cur.fetchall()
    conn.close()
    return rows


def remove_user_from_room(room_name, username):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return False
    user_id = user_row["id"]
    cur.execute("SELECT id FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    if not room_row:
        conn.close()
        return False
    room_id = room_row["id"]
    cur.execute(
        "DELETE FROM room_members WHERE room_id = ? AND user_id = ?",
        (room_id, user_id),
    )
    conn.commit()
    conn.close()
    return True


def get_all_interfaces(limit=10, offset=0):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM chat_interfaces ORDER BY id ASC LIMIT ? OFFSET ?", (limit, offset))
    rows = cur.fetchall()
    conn.close()
    return rows


def count_interfaces():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM chat_interfaces")
    count = cur.fetchone()[0]
    conn.close()
    return count


def add_interface(name, command, url, token=None, is_active=1):
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()
    try:
        cur.execute(
            "INSERT INTO chat_interfaces (name, command, url, token, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (name, command, url, token, is_active, now),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def update_interface(interface_id, name, command, url, token=None, is_active=1):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "UPDATE chat_interfaces SET name = ?, command = ?, url = ?, token = ?, is_active = ? WHERE id = ?",
            (name, command, url, token, is_active, interface_id),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def delete_interface(interface_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM chat_interfaces WHERE id = ?", (interface_id,))
    conn.commit()
    conn.close()


def get_interface_by_id(interface_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM chat_interfaces WHERE id = ?", (interface_id,))
    row = cur.fetchone()
    conn.close()
    return row


def toggle_interface_status(interface_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT is_active FROM chat_interfaces WHERE id = ?", (interface_id,))
    row = cur.fetchone()
    if row:
        new_status = 0 if row['is_active'] else 1
        cur.execute("UPDATE chat_interfaces SET is_active = ? WHERE id = ?", (new_status, interface_id))
        conn.commit()
    conn.close()


def get_all_active_interfaces():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM chat_interfaces WHERE is_active = 1")
    rows = cur.fetchall()
    conn.close()
    return rows


def get_all_ws_servers(limit=12, offset=0):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ws_servers ORDER BY id ASC LIMIT ? OFFSET ?", (limit, offset))
    rows = cur.fetchall()
    conn.close()
    return rows


def count_ws_servers():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM ws_servers")
    count = cur.fetchone()[0]
    conn.close()
    return count


def count_active_ws_servers():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM ws_servers WHERE is_active = 1")
    count = cur.fetchone()[0]
    conn.close()
    return count


def add_ws_server(name, host, port, path="/", protocol="ws", is_active=1):
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()
    cur.execute(
        "INSERT INTO ws_servers (name, host, port, path, protocol, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (name, host, port, path, protocol, is_active, now),
    )
    conn.commit()
    conn.close()


def update_ws_server(server_id, name, host, port, path="/", protocol="ws", is_active=1):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE ws_servers SET name = ?, host = ?, port = ?, path = ?, protocol = ?, is_active = ? WHERE id = ?",
        (name, host, port, path, protocol, is_active, server_id),
    )
    conn.commit()
    conn.close()


def delete_ws_server(server_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM ws_servers WHERE id = ?", (server_id,))
    conn.commit()
    conn.close()


def get_ws_server_by_id(server_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ws_servers WHERE id = ?", (server_id,))
    row = cur.fetchone()
    conn.close()
    return row


def get_active_ws_servers():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ws_servers WHERE is_active = 1")
    rows = cur.fetchall()
    conn.close()
    return rows


def count_room_members(room_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM room_members WHERE room_id = ?", (room_id,))
    count = cur.fetchone()[0]
    conn.close()
    return count


def get_room_member_role(room_name, username):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return None
    user_id = user_row["id"]
    cur.execute("SELECT id FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    if not room_row:
        conn.close()
        return None
    room_id = room_row["id"]
    cur.execute(
        "SELECT role FROM room_members WHERE room_id = ? AND user_id = ?",
        (room_id, user_id),
    )
    member_row = cur.fetchone()
    conn.close()
    if not member_row:
        return None
    return member_row["role"]


def set_room_member_role(room_name, username, role):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return False
    user_id = user_row["id"]
    cur.execute("SELECT id FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    if not room_row:
        conn.close()
        return False
    room_id = room_row["id"]
    cur.execute(
        "UPDATE room_members SET role = ? WHERE room_id = ? AND user_id = ?",
        (role, room_id, user_id),
    )
    conn.commit()
    conn.close()
    return True


def get_room_member_roles(room_name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    if not room_row:
        conn.close()
        return []
    room_id = room_row["id"]
    cur.execute(
        """
        SELECT u.username, u.avatar, rm.role
        FROM room_members rm
        JOIN users u ON rm.user_id = u.id
        WHERE rm.room_id = ?
        """,
        (room_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def get_user_rooms(username):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return []
    user_id = user_row["id"]
    cur.execute(
        """
        SELECT r.id, r.name, r.is_private, rm.last_read_at, rm.joined_at
        FROM room_members rm
        JOIN rooms r ON rm.room_id = r.id
        WHERE rm.user_id = ?
        """,
        (user_id,),
    )
    room_rows = cur.fetchall()
    
    rooms = []
    for r in room_rows:
        name = r["name"]
        is_private = r["is_private"]
        last_read_at = r["last_read_at"]
        joined_at = r["joined_at"]
        
        # Get last message
        msgs = get_recent_messages(limit=1, room_name=name)
        last_time = ""
        last_content = ""
        if msgs:
            last_time = msgs[0]["time"]
            last_content = msgs[0]["content"]
            
        # Calculate unread count
        unread_count = 0
        anchor_time = last_read_at if last_read_at else joined_at
        
        if anchor_time:
            cur.execute(
                "SELECT COUNT(*) FROM messages WHERE room_id = ? AND created_at > ?",
                (r["id"], anchor_time)
            )
            unread_count = cur.fetchone()[0]

        rooms.append(
            {
                "name": name,
                "is_private": is_private,
                "last_time": last_time,
                "last_content": last_content,
                "unread_count": unread_count,
            }
        )
    conn.close()
    rooms.sort(key=lambda x: (x["last_time"] != "", x["last_time"]), reverse=True)
    return rooms


def mark_room_read(username, room_name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return False
    user_id = user_row["id"]
    
    cur.execute("SELECT id FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    if not room_row:
        conn.close()
        return False
    room_id = room_row["id"]
    
    now = datetime.datetime.utcnow().isoformat()
    cur.execute(
        "UPDATE room_members SET last_read_at = ? WHERE room_id = ? AND user_id = ?",
        (now, room_id, user_id)
    )
    conn.commit()
    conn.close()
    return True


def is_user_banned_from_room(room_name, username):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return False
    user_id = user_row["id"]
    cur.execute("SELECT id FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    if not room_row:
        conn.close()
        return False
    room_id = room_row["id"]
    cur.execute(
        "SELECT 1 FROM room_bans WHERE room_id = ? AND user_id = ?",
        (room_id, user_id),
    )
    banned = cur.fetchone() is not None
    conn.close()
    return banned


def add_room_ban(room_name, username):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return False
    user_id = user_row["id"]
    cur.execute("SELECT id FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    if not room_row:
        conn.close()
        return False
    room_id = room_row["id"]
    now = datetime.datetime.utcnow().isoformat()
    cur.execute(
        "INSERT OR IGNORE INTO room_bans (room_id, user_id, banned_at) VALUES (?, ?, ?)",
        (room_id, user_id, now),
    )
    conn.commit()
    conn.close()
    return True


def remove_room_ban(room_name, username):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return False
    user_id = user_row["id"]
    cur.execute("SELECT id FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    if not room_row:
        conn.close()
        return False
    room_id = room_row["id"]
    cur.execute(
        "DELETE FROM room_bans WHERE room_id = ? AND user_id = ?",
        (room_id, user_id),
    )
    conn.commit()
    conn.close()
    return True


def get_first_unread_message(username, room_name):
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row: return None
    user_id = user_row["id"]
    
    cur.execute("SELECT id FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    if not room_row: return None
    room_id = room_row["id"]
    
    cur.execute("SELECT last_read_at FROM room_members WHERE room_id = ? AND user_id = ?", (room_id, user_id))
    member_row = cur.fetchone()
    if not member_row or not member_row['last_read_at']:
        conn.close()
        return None # or first message?
        
    last_read_at = member_row['last_read_at']
    
    cur.execute(
        "SELECT id, created_at FROM messages WHERE room_id = ? AND created_at > ? ORDER BY created_at ASC LIMIT 1",
        (room_id, last_read_at)
    )
    msg_row = cur.fetchone()
    conn.close()
    return msg_row # {'id': ..., 'created_at': ...}


def get_messages_with_unread_focus(username, room_name, default_limit=20):
    # This replaces get_recent_messages for the chat view
    # Logic:
    # 1. Get last_read_at
    # 2. If unread count > 0:
    #      Fetch messages starting from (first_unread_time - context)
    #      Or just fetch ALL unread messages + some context before.
    #      To be safe, let's limit to max 100 or something.
    
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row: return []
    user_id = user_row["id"]
    
    cur.execute("SELECT id FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    if not room_row: return []
    room_id = room_row["id"]
    
    cur.execute("SELECT last_read_at, joined_at FROM room_members WHERE room_id = ? AND user_id = ?", (room_id, user_id))
    member_row = cur.fetchone()
    last_read_at = member_row['last_read_at'] if member_row else None
    joined_at = member_row['joined_at'] if member_row else None
    
    anchor_time = last_read_at if last_read_at else joined_at

    # We want: [ ... 5 messages before unread ... ] [ ... unread messages ... ]
    # If unread messages are too many (e.g. 1000), we limit to say 50.
    
    # Strategy:
    # Get unread count first.
    unread_count = 0
    if anchor_time:
        cur.execute("SELECT COUNT(*) FROM messages WHERE room_id = ? AND created_at > ?", (room_id, anchor_time))
        unread_count = cur.fetchone()[0]
        
    limit = default_limit
    if unread_count > 0:
        # If we have unread messages, ensure we fetch them all (up to a reasonable max) plus some context
        limit = max(default_limit, unread_count + 5)
        # Cap at 100 for performance
        if limit > 100: limit = 100
    
    cur.execute(
        """
        SELECT m.id, m.content, m.created_at, u.username, u.avatar
        FROM messages m
        JOIN users u ON m.user_id = u.id
        WHERE m.room_id = ?
        ORDER BY m.id DESC
        LIMIT ?
        """,
        (room_id, limit),
    )
    rows = cur.fetchall()
    conn.close()
    rows = list(rows)[::-1]
    
    messages = []
    first_unread_found = False
    
    for r in rows:
        created_at = r["created_at"]
        is_unread = False
        if anchor_time and created_at > anchor_time:
            is_unread = True
            
        try:
            dt = datetime.datetime.fromisoformat(created_at)
            time_str = dt.strftime("%H:%M")
        except Exception:
            time_str = ""
            
        messages.append(
            {
                "id": r["id"],
                "username": r["username"],
                "avatar": r["avatar"],
                "content": r["content"],
                "time": time_str,
                "is_unread": is_unread,
                "timestamp": created_at
            }
        )
    return messages


def get_all_servers():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ws_servers ORDER BY id ASC")
    rows = cur.fetchall()
    conn.close()
    return rows


def get_server_by_id(server_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ws_servers WHERE id = ?", (server_id,))
    row = cur.fetchone()
    conn.close()
    return row


def add_server(name, protocol, host, port, path, is_active=1):
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()
    cur.execute(
        "INSERT INTO ws_servers (name, protocol, host, port, path, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (name, protocol, host, port, path, 1 if is_active else 0, now)
    )
    conn.commit()
    conn.close()


def get_ai_models(limit=6, offset=0):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT *
        FROM ai_models
        ORDER BY id ASC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def count_ai_models():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM ai_models")
    count = cur.fetchone()[0]
    conn.close()
    return count


def get_ai_model_by_id(model_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ai_models WHERE id = ?", (model_id,))
    row = cur.fetchone()
    conn.close()
    return row


def add_ai_model(name, api_base, api_key, model_name, prompt, is_active=1, is_default=0):
    conn = get_connection()
    cur = conn.cursor()
    
    if is_default:
        cur.execute("UPDATE ai_models SET is_default = 0")
        
    now = datetime.datetime.utcnow().isoformat()
    cur.execute(
        """
        INSERT INTO ai_models
        (name, api_url, api_base, api_key, model_name, prompt, is_active, is_default, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (name, api_base, api_base, api_key, model_name, prompt, 1 if is_active else 0, 1 if is_default else 0, now),
    )
    conn.commit()
    conn.close()


def update_ai_model(model_id, name, api_base, api_key, model_name, prompt, is_active, is_default):
    conn = get_connection()
    cur = conn.cursor()
    
    if is_default:
        cur.execute("UPDATE ai_models SET is_default = 0")

    cur.execute(
        """
        UPDATE ai_models
        SET name = ?, api_base = ?, api_key = ?, model_name = ?, prompt = ?, is_active = ?, is_default = ?
        WHERE id = ?
        """,
        (name, api_base, api_key, model_name, prompt, 1 if is_active else 0, 1 if is_default else 0, model_id),
    )
    conn.commit()
    conn.close()


def get_default_ai_model():
    conn = get_connection()
    cur = conn.cursor()
    # Prioritize default active model, then any active model, ordered by ID
    cur.execute("SELECT * FROM ai_models WHERE is_active = 1 ORDER BY is_default DESC, id ASC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row


def get_all_active_ai_models():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ai_models WHERE is_active = 1 ORDER BY is_default DESC, id ASC")
    rows = cur.fetchall()
    conn.close()
    return rows


def delete_ai_model(model_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM ai_models WHERE id = ?", (model_id,))
    conn.commit()
    conn.close()


def set_ai_model_active(model_id, is_active):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE ai_models SET is_active = ? WHERE id = ?",
        (1 if is_active else 0, model_id),
    )
    conn.commit()
    conn.close()


def update_ai_model_usage(model_id, prompt_tokens, completion_tokens, total_tokens, latency_ms):
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()
    cur.execute(
        """
        UPDATE ai_models
        SET
            total_prompt_tokens = total_prompt_tokens + ?,
            total_completion_tokens = total_completion_tokens + ?,
            total_tokens = total_tokens + ?,
            total_requests = total_requests + 1,
            last_latency_ms = ?,
            last_test_at = ?
        WHERE id = ?
        """,
        (prompt_tokens, completion_tokens, total_tokens, latency_ms, now, model_id),
    )
    conn.commit()
    conn.close()


def update_server(server_id, name, protocol, host, port, path, is_active):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE ws_servers SET name = ?, protocol = ?, host = ?, port = ?, path = ?, is_active = ? WHERE id = ?",
        (name, protocol, host, port, path, 1 if is_active else 0, server_id)
    )
    conn.commit()
    conn.close()


def delete_server(server_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM ws_servers WHERE id = ?", (server_id,))
    conn.commit()
    conn.close()


def get_friends(user_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.id, u.username, u.avatar, u.is_banned, f.created_at
        FROM friendships f
        JOIN users u ON f.friend_id = u.id
        WHERE f.user_id = ? AND f.status = 'accepted'
    """, (user_id,))
    rows = cur.fetchall()
    conn.close()
    return rows


def get_received_friend_requests(user_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.id, u.username, u.avatar, f.created_at, f.id as request_id
        FROM friendships f
        JOIN users u ON f.user_id = u.id
        WHERE f.friend_id = ? AND f.status = 'pending'
    """, (user_id,))
    rows = cur.fetchall()
    conn.close()
    return rows


def send_friend_request(user_id, friend_id):
    if user_id == friend_id:
        return False, "Cannot add yourself"
    if is_blocked_between(user_id, friend_id):
        return False, "对方已将你拉黑或你已拉黑对方"
    conn = get_connection()
    cur = conn.cursor()
    
    # Check if already friends or requested
    cur.execute("SELECT * FROM friendships WHERE user_id = ? AND friend_id = ?", (user_id, friend_id))
    if cur.fetchone():
        conn.close()
        return False, "Request already sent or already friends"
    
    # Check if the other person already sent a request (in which case, we should auto-accept? Or just block?)
    # For simplicity, we can let them see the incoming request and accept it.
    
    now = datetime.datetime.utcnow().isoformat()
    cur.execute(
        "INSERT INTO friendships (user_id, friend_id, status, created_at) VALUES (?, ?, 'pending', ?)",
        (user_id, friend_id, now)
    )
    conn.commit()
    conn.close()
    return True, "Request sent"


def accept_friend_request(user_id, friend_id):
    conn = get_connection()
    cur = conn.cursor()
    
    # Check if there is a pending request from friend_id to user_id
    cur.execute("SELECT * FROM friendships WHERE user_id = ? AND friend_id = ? AND status = 'pending'", (friend_id, user_id))
    req = cur.fetchone()
    if not req:
        conn.close()
        return False, "No pending request found"
    
    now = datetime.datetime.utcnow().isoformat()
    
    # Update the existing request to accepted
    cur.execute("UPDATE friendships SET status = 'accepted' WHERE id = ?", (req['id'],))
    
    # Create the reverse friendship
    cur.execute(
        "INSERT OR IGNORE INTO friendships (user_id, friend_id, status, created_at) VALUES (?, ?, 'accepted', ?)",
        (user_id, friend_id, now)
    )
    
    conn.commit()
    conn.close()
    return True, "Friend request accepted"


def remove_friend(user_id, friend_id):
    conn = get_connection()
    cur = conn.cursor()
    # Delete both directions
    cur.execute("DELETE FROM friendships WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)", (user_id, friend_id, friend_id, user_id))
    conn.commit()
    conn.close()
    return True


def get_ai_usage_summary():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            COALESCE(SUM(total_prompt_tokens), 0) AS total_prompt_tokens,
            COALESCE(SUM(total_completion_tokens), 0) AS total_completion_tokens,
            COALESCE(SUM(total_tokens), 0) AS total_tokens,
            COALESCE(SUM(total_requests), 0) AS total_requests,
            AVG(last_latency_ms) AS avg_latency_ms
        FROM ai_models
        """
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "total_prompt_tokens": row["total_prompt_tokens"],
        "total_completion_tokens": row["total_completion_tokens"],
        "total_tokens": row["total_tokens"],
        "total_requests": row["total_requests"],
        "avg_latency_ms": row["avg_latency_ms"],
    }


def get_user_stats_for_ai():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM users WHERE is_banned = 1")
    banned_users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM users WHERE is_ai = 1")
    ai_users = cur.fetchone()[0]
    cur.execute(
        """
        SELECT substr(created_at, 1, 10) AS date, COUNT(*) AS count
        FROM users
        WHERE created_at IS NOT NULL AND created_at <> ''
        GROUP BY date
        ORDER BY date DESC
        LIMIT 30
        """
    )
    rows = cur.fetchall()
    conn.close()
    daily_new_users = [
        {"date": r["date"], "count": r["count"]} for r in rows if r["date"]
    ]
    daily_new_users.reverse()
    return {
        "total_users": total_users,
        "banned_users": banned_users,
        "ai_users": ai_users,
        "daily_new_users": daily_new_users,
    }


def get_room_stats_for_ai():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM rooms")
    total_rooms = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM rooms WHERE is_banned = 1")
    banned_rooms = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM rooms WHERE is_private = 1")
    private_rooms = cur.fetchone()[0]
    cur.execute(
        """
        SELECT r.name, COUNT(rm.id) AS member_count
        FROM rooms r
        LEFT JOIN room_members rm ON r.id = rm.room_id
        GROUP BY r.id
        ORDER BY member_count DESC
        LIMIT 5
        """
    )
    top_rooms_by_members = [
        {"name": r["name"], "member_count": r["member_count"]} for r in cur.fetchall()
    ]
    cur.execute(
        """
        SELECT r.name, COUNT(m.id) AS message_count
        FROM rooms r
        LEFT JOIN messages m ON r.id = m.room_id
        GROUP BY r.id
        ORDER BY message_count DESC
        LIMIT 5
        """
    )
    top_rooms_by_messages = [
        {"name": r["name"], "message_count": r["message_count"]}
        for r in cur.fetchall()
    ]
    conn.close()
    return {
        "total_rooms": total_rooms,
        "banned_rooms": banned_rooms,
        "private_rooms": private_rooms,
        "top_rooms_by_members": top_rooms_by_members,
        "top_rooms_by_messages": top_rooms_by_messages,
    }


def get_dashboard_stats():
    conn = get_connection()
    cur = conn.cursor()
    
    # 1. Basic Counts
    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM rooms")
    total_rooms = cur.fetchone()[0]
    
    # Simple estimation for online users (active in last 5 minutes maybe? or just return global var from app)
    # Since DB doesn't track presence, we'll get this from app memory or just return 0 here and let app fill it
    online_users = 0 
    
    now_str = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    next_day_str = (datetime.datetime.utcnow() + datetime.timedelta(days=1)).strftime('%Y-%m-%d')
    
    # Optimize: Use range query instead of LIKE for index usage
    cur.execute("SELECT COUNT(*) FROM messages WHERE created_at >= ? AND created_at < ?", (now_str, next_day_str))
    today_messages = cur.fetchone()[0]
    
    # 2. Message Trend (Last 7 days) - Optimized
    days = []
    msg_counts = []
    
    seven_days_ago = (datetime.datetime.utcnow() - datetime.timedelta(days=6)).strftime('%Y-%m-%d')
    # Use substr to extract YYYY-MM-DD from created_at
    cur.execute("""
        SELECT substr(created_at, 1, 10) as day, COUNT(*) as count
        FROM messages
        WHERE created_at >= ?
        GROUP BY day
    """, (seven_days_ago,))
    
    trend_data = {row['day']: row['count'] for row in cur.fetchall()}
    
    for i in range(6, -1, -1):
        day = (datetime.datetime.utcnow() - datetime.timedelta(days=i)).strftime('%Y-%m-%d')
        days.append(day)
        msg_counts.append(trend_data.get(day, 0))
        
    # 3. Top Active Rooms (Today)
    cur.execute("""
        SELECT r.name, COUNT(m.id) as count
        FROM rooms r
        JOIN messages m ON r.id = m.room_id
        WHERE m.created_at >= ? AND m.created_at < ?
        GROUP BY r.id
        ORDER BY count DESC
        LIMIT 5
    """, (now_str, next_day_str))
    active_rooms = [{"name": row["name"], "value": row["count"]} for row in cur.fetchall()]
    
    # 4. User Distribution (Active vs Banned vs AI)
    cur.execute("SELECT COUNT(*) FROM users WHERE is_banned=0 AND is_ai=0")
    normal_users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM users WHERE is_banned=1")
    banned_users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM users WHERE is_ai=1")
    ai_users = cur.fetchone()[0]
    
    # 5. Recent Alerts (Keyword based simulation for "Dangerous" content)
    # Keywords: "fuck", "stupid", "danger", "bomb", "kill" (Simulated)
    keywords = ['fuck', 'stupid', 'danger', 'kill', '死', '滚', '垃圾']
    alerts = []
    if keywords:
        placeholders = ' OR '.join(['m.content LIKE ?'] * len(keywords))
        params = [f'%{k}%' for k in keywords]
        
        # Optimization: Only scan last 1000 messages instead of full table
        query = f"""
            SELECT m.id, u.username, r.name as room_name, m.content, m.created_at
            FROM (
                SELECT id, user_id, room_id, content, created_at 
                FROM messages 
                ORDER BY created_at DESC 
                LIMIT 1000
            ) m
            JOIN users u ON m.user_id = u.id
            JOIN rooms r ON m.room_id = r.id
            WHERE ({placeholders})
            ORDER BY m.created_at DESC
            LIMIT 10
        """
        cur.execute(query, params)
        for row in cur.fetchall():
            alerts.append({
                "id": row["id"],
                "user": row["username"],
                "room": row["room_name"],
                "content": row["content"],
                "time": row["created_at"],
                "type": "敏感词"
            })
            
    conn.close()
    
    return {
        "total_users": total_users,
        "total_rooms": total_rooms,
        "online_users": online_users, # To be filled by app
        "today_messages": today_messages,
        "msg_trend": {"dates": days, "counts": msg_counts},
        "active_rooms": active_rooms,
        "user_dist": [
            {"name": "正常用户", "value": normal_users},
            {"name": "封禁用户", "value": banned_users},
            {"name": "数字员工", "value": ai_users}
        ],
        "alerts": alerts
    }


def get_message_stats_for_ai():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM messages")
    total_messages = cur.fetchone()[0]
    cur.execute(
        """
        SELECT substr(created_at, 1, 10) AS date, COUNT(*) AS count
        FROM messages
        WHERE created_at IS NOT NULL AND created_at <> ''
        GROUP BY date
        ORDER BY date DESC
        LIMIT 30
        """
    )
    rows = cur.fetchall()
    conn.close()
    daily_messages = [
        {"date": r["date"], "count": r["count"]} for r in rows if r["date"]
    ]
    daily_messages.reverse()
    return {
        "total_messages": total_messages,
        "daily_messages": daily_messages,
    }


def get_room_member_stats_for_ai():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT r.name, COUNT(rm.id) AS member_count
        FROM rooms r
        LEFT JOIN room_members rm ON r.id = rm.room_id
        GROUP BY r.id
        ORDER BY member_count DESC
        """
    )
    rows = cur.fetchall()
    conn.close()
    return [
        {"room_name": r["name"], "member_count": r["member_count"]} for r in rows
    ]


def remove_private_room_membership(user_id, friend_id):
    conn = get_connection()
    cur = conn.cursor()
    
    # Reconstruct room name
    u1, u2 = sorted([user_id, friend_id])
    room_name = f"private_{u1}_{u2}"
    
    cur.execute("SELECT id FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    
    if room_row:
        room_id = room_row["id"]
        # Remove the current user from the room members
        # We only remove the user who requested the deletion (or both?)
        # The requirement is "corresponding chat box also disappears".
        # Usually this means for the user who deleted the friend.
        # But if we remove only one, the room remains "half-empty".
        # Let's remove both to be clean, or just the one. 
        # If I remove myself, get_user_rooms won't find it.
        # Let's remove both because the friendship is gone.
        cur.execute("DELETE FROM room_members WHERE room_id = ? AND (user_id = ? OR user_id = ?)", (room_id, user_id, friend_id))
        
        # Optionally delete the room if empty?
        # cur.execute("SELECT COUNT(*) FROM room_members WHERE room_id = ?", (room_id,))
        # if cur.fetchone()[0] == 0:
        #     cur.execute("DELETE FROM rooms WHERE id = ?", (room_id,))
        #     cur.execute("DELETE FROM messages WHERE room_id = ?", (room_id,))
            
    conn.commit()
    conn.close()


def search_users_exclude_friends(query, current_user_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, username, avatar FROM users 
        WHERE username LIKE ? 
        AND id != ?
        AND id NOT IN (
            SELECT friend_id FROM friendships WHERE user_id = ?
        )
        LIMIT 20
    """, (f'%{query}%', current_user_id, current_user_id))
    
    rows = cur.fetchall()
    conn.close()
    return rows


def get_blocked_users(user_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT u.id, u.username, u.avatar
        FROM friendships f
        JOIN users u ON f.friend_id = u.id
        WHERE f.user_id = ? AND f.status = 'blocked'
        """,
        (user_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def is_blocked_between(user_id, other_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT 1 FROM friendships
        WHERE
            (user_id = ? AND friend_id = ? AND status = 'blocked')
            OR
            (user_id = ? AND friend_id = ? AND status = 'blocked')
        LIMIT 1
        """,
        (user_id, other_id, other_id, user_id),
    )
    row = cur.fetchone()
    conn.close()
    return row is not None


def block_user(user_id, target_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM friendships WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)",
        (user_id, target_id, target_id, user_id),
    )
    now = datetime.datetime.utcnow().isoformat()
    cur.execute(
        "INSERT OR REPLACE INTO friendships (user_id, friend_id, status, created_at) VALUES (?, ?, 'blocked', ?)",
        (user_id, target_id, now),
    )
    conn.commit()
    conn.close()
    return True


def unblock_user(user_id, target_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM friendships WHERE user_id = ? AND friend_id = ? AND status = 'blocked'",
        (user_id, target_id),
    )
    conn.commit()
    conn.close()
    return True


def add_room_join_request(room_name, username):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return False, "用户不存在"
    user_id = user_row["id"]
    cur.execute("SELECT id, is_private, is_banned FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    if not room_row:
        conn.close()
        return False, "房间不存在"
    room_id = room_row["id"]
    if room_row["is_private"]:
        conn.close()
        return False, "私聊不支持入群申请"
    cur.execute(
        "SELECT status FROM room_join_requests WHERE room_id = ? AND user_id = ?",
        (room_id, user_id),
    )
    req = cur.fetchone()
    now = datetime.datetime.utcnow().isoformat()
    if req and req["status"] == "pending":
        conn.close()
        return False, "已提交申请，请等待审核"
    if req:
        cur.execute(
            "UPDATE room_join_requests SET status = 'pending', created_at = ? WHERE room_id = ? AND user_id = ?",
            (now, room_id, user_id),
        )
    else:
        cur.execute(
            "INSERT INTO room_join_requests (room_id, user_id, status, created_at) VALUES (?, ?, 'pending', ?)",
            (room_id, user_id, now),
        )
    conn.commit()
    conn.close()
    return True, "已提交入群申请"


def get_room_join_requests(room_name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    if not room_row:
        conn.close()
        return []
    room_id = room_row["id"]
    cur.execute(
        """
        SELECT u.username, r.created_at
        FROM room_join_requests r
        JOIN users u ON r.user_id = u.id
        WHERE r.room_id = ? AND r.status = 'pending'
        ORDER BY r.created_at ASC
        """,
        (room_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def approve_room_join_request(room_name, username):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return False
    user_id = user_row["id"]
    cur.execute("SELECT id FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    if not room_row:
        conn.close()
        return False
    room_id = room_row["id"]
    cur.execute(
        "UPDATE room_join_requests SET status = 'accepted' WHERE room_id = ? AND user_id = ?",
        (room_id, user_id),
    )
    conn.commit()
    conn.close()
    ensure_user_in_room(username, room_name)
    return True


def reject_room_join_request(room_name, username):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return False
    user_id = user_row["id"]
    cur.execute("SELECT id FROM rooms WHERE name = ?", (room_name,))
    room_row = cur.fetchone()
    if not room_row:
        conn.close()
        return False
    room_id = room_row["id"]
    cur.execute(
        "UPDATE room_join_requests SET status = 'rejected' WHERE room_id = ? AND user_id = ?",
        (room_id, user_id),
    )
    conn.commit()
    conn.close()
    return True


def get_room_announcement(room_name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT announcement FROM rooms WHERE name = ?", (room_name,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return ""
    return row["announcement"] or ""


def set_room_announcement(room_name, content):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE rooms SET announcement = ? WHERE name = ?",
        (content, room_name),
    )
    conn.commit()
    conn.close()
    return True
