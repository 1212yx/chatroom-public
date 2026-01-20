from flask import Flask, render_template, request, redirect, url_for, Response, stream_with_context
from flask_sock import Sock
from werkzeug.security import generate_password_hash, check_password_hash
import json
import datetime
import os
import threading
import time
import uuid
import requests

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

from database.db import (
    init_db,
    get_user_by_username,
    create_user,
    update_last_login,
    save_message,
    get_recent_messages,
    ensure_user_in_room,
    get_user_rooms,
    get_room_by_name,
    get_room_with_creator,
    PUBLIC_ROOM_NAME,
    get_friends,
    get_received_friend_requests,
    send_friend_request,
    accept_friend_request,
    remove_friend,
    search_users_exclude_friends,
    get_or_create_private_room,
    get_user_by_id,
    remove_private_room_membership,
    mark_room_read,
    get_messages_with_unread_focus,
    is_user_banned_from_room,
    add_room_ban,
    remove_room_ban,
    remove_user_from_room,
    get_room_member_role,
    set_room_member_role,
    get_room_member_roles,
    get_room_by_code,
    get_blocked_users,
    is_blocked_between,
    block_user,
    unblock_user,
    add_room_join_request,
    get_room_join_requests,
    approve_room_join_request,
    reject_room_join_request,
    get_room_announcement,
    set_room_announcement,
    get_active_ws_servers,
    get_ws_server_by_id,
    get_default_ai_model,
    get_ai_user,
    get_ai_employees,
    get_all_active_interfaces,
    update_user_avatar,
    update_user_nickname,
    update_user_password,
)

app = Flask(__name__)
app.secret_key = 'dev_secret_key'
sock = Sock(app)

# Configure Upload Folder
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads', 'avatars')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

from admin import admin_bp
app.register_blueprint(admin_bp)

connected_clients = {}


def get_safe_online_users(room_name):
    users = []
    seen = set()
    
    # 1. Add real connected clients
    for info in connected_clients.values():
        name = info.get("username")
        room = info.get("room")
        if room != room_name:
            continue
        if not name:
            continue
        if name in seen:
            continue
        
        user_row = get_user_by_username(name)
        if user_row:
            is_ai = False
            try:
                is_ai = bool(user_row['is_ai'])
            except:
                pass
            users.append({
                "username": name,
                "is_ai": is_ai,
                "avatar": dict(user_row).get('avatar')
            })
            seen.add(name)

    # 2. Add AI user to all group rooms (not starting with private_)
    # This ensures the AI user is always visible in group chats
    if not room_name.startswith('private_'):
        ai_employees = get_ai_employees(limit=100)
        for ai_user in ai_employees:
            ai_name = ai_user['username']
            if ai_name not in seen:
                users.append({
                    "username": ai_name,
                    "is_ai": True,
                    "avatar": dict(ai_user).get('avatar')
                })
                seen.add(ai_name)
                
    return users

@app.route('/api/private_chat', methods=['POST'])
def start_private_chat():
    data = request.get_json()
    username = data.get('username')
    target_username = data.get('target_username')
    
    if not username or not target_username:
        return json.dumps({'code': 400, 'msg': 'Missing parameters'})
        
    user = get_user_by_username(username)
    target = get_user_by_username(target_username)
    
    if not user or not target:
        return json.dumps({'code': 404, 'msg': 'User not found'})
    if is_blocked_between(user['id'], target['id']):
        return json.dumps({'code': 403, 'msg': '你已被对方拉黑或已拉黑对方'})
        
    room_name = get_or_create_private_room(user['id'], target['id'])
    return json.dumps({'code': 0, 'room_name': room_name})

@app.route('/')
def index():
    server_host = request.host
    servers = get_active_ws_servers()
    return render_template('login.html', server_host=server_host, servers=servers)

@app.route('/chat')
def chat():
    username = request.args.get('username')
    room_name = request.args.get('room') or PUBLIC_ROOM_NAME
    ws_server_id = request.args.get('ws_server')
    
    # Validate ws_server_id format (must be integer)
    if ws_server_id and not ws_server_id.isdigit():
        ws_server_id = None
    
    if not username:
        return redirect(url_for('index'))
    user = get_user_by_username(username)
    if not user:
        return redirect(url_for('index'))
    
    ws_server_url = None
    if ws_server_id:
        server = get_ws_server_by_id(ws_server_id)
        if server:
            protocol = server['protocol']
            host = server['host']
            port = server['port']
            path = server['path']
            ws_server_url = f"{protocol}://{host}:{port}{path}"
    
    room_display_name = room_name
    is_private = False
    room_is_banned = False
    room_user_banned = False

    if room_name.startswith('private_'):
        try:
            parts = room_name.split('_')
            if len(parts) >= 3:
                id1, id2 = int(parts[1]), int(parts[2])
                other_id = id2 if user['id'] == id1 else id1
                other_user = get_user_by_id(other_id)
                if other_user:
                    room_display_name = other_user['username']
                    is_private = True
                    # Ensure I am in this room
                    get_or_create_private_room(user['id'], other_user['id'])
        except:
            pass
    else:
        room = get_room_by_name(room_name)
        if room and room["is_banned"]:
            room_is_banned = True
        if room and is_user_banned_from_room(room_name, username):
            room_user_banned = True
        ensure_user_in_room(username, PUBLIC_ROOM_NAME)
        if not room_is_banned and not room_user_banned:
            ensure_user_in_room(username, room_name)
        
    all_rooms = get_user_rooms(username)
    groups = [r for r in all_rooms if not r.get('is_private')]
    current_room_creator_name = None
    current_room_code = None
    current_room_announcement = ""
    if not is_private:
        room_row = get_room_with_creator(room_name)
        if room_row:
            current_room_creator_name = room_row["creator_name"]
            current_room_code = room_row["room_code"]
        current_room_announcement = get_room_announcement(room_name)
    is_room_owner = (
        not is_private and current_room_creator_name == user["username"]
    )
    is_room_manager = False
    if not is_private and not is_room_owner and not room_user_banned:
        role = get_room_member_role(room_name, username)
        if role == "manager":
            is_room_manager = True
    # Process private rooms (DMs)
    dms = []
    for r in all_rooms:
        if r.get('is_private'):
            dm_name = r['name']
            display_name = dm_name # Fallback
            try:
                parts = dm_name.split('_')
                if len(parts) >= 3:
                    id1, id2 = int(parts[1]), int(parts[2])
                    other_id = id2 if user['id'] == id1 else id1
                    other_user = get_user_by_id(other_id)
                    if other_user:
                        display_name = other_user['username']
            except:
                pass
            
            # Create a copy or modify
            r_copy = r.copy()
            r_copy['display_name'] = display_name
            dms.append(r_copy)
    
    friends_list = [dict(f) for f in get_friends(user['id'])]
    blocked_rows = get_blocked_users(user['id'])
    blocked_usernames = [r["username"] for r in blocked_rows]
    
    return render_template('chat.html', 
        username=username, 
        user_avatar=user['avatar'],
        room_name=room_name, 
        room_display_name=room_display_name,
        room_code=current_room_code,
        room_announcement=current_room_announcement,
        groups=groups, 
        dms=dms,
        friends=friends_list,
        blocked_users=blocked_usernames,
        room_is_banned=room_is_banned,
        is_private=is_private,
        room_user_banned=room_user_banned,
        is_room_owner=is_room_owner,
        is_room_manager=is_room_manager,
        ws_server_url=ws_server_url,
    )


@app.route('/api/rooms/join_or_create', methods=['POST'])
def join_or_create_room():
    data = request.get_json()
    username = data.get('username', '').strip()
    room_name = data.get('room_name', '').strip()
    if not username or not room_name:
        return json.dumps({'code': 400, 'msg': '缺少参数'})
    user = get_user_by_username(username)
    if not user:
        return json.dumps({'code': 404, 'msg': '用户不存在'})
    if room_name.startswith('private_'):
        return json.dumps({'code': 400, 'msg': '房间号不合法'})
    if len(room_name) > 50:
        return json.dumps({'code': 400, 'msg': '房间名称过长'})
    existing = get_room_by_name(room_name)
    if existing:
        if existing['is_banned']:
            return json.dumps({'code': 403, 'msg': '该房间已被封禁'})
        if is_user_banned_from_room(room_name, username):
            return json.dumps({'code': 403, 'msg': '你已被本房间封禁'})
        ensure_user_in_room(username, room_name)
        return json.dumps({'code': 0, 'msg': '已加入群聊', 'room_name': room_name})
    ensure_user_in_room(username, room_name)
    return json.dumps({'code': 0, 'msg': '群聊已创建并加入', 'room_name': room_name})


@app.route('/api/rooms/join_by_code', methods=['POST'])
def join_room_by_code():
    data = request.get_json()
    username = data.get('username', '').strip()
    room_code = data.get('room_code', '').strip()
    if not username or not room_code:
        return json.dumps({'code': 400, 'msg': '缺少参数'})
    if not room_code.isdigit() or len(room_code) != 6:
        return json.dumps({'code': 400, 'msg': '房间号格式不正确'})
    user = get_user_by_username(username)
    if not user:
        return json.dumps({'code': 404, 'msg': '用户不存在'})
    room = get_room_by_code(room_code)
    if not room:
        return json.dumps({'code': 404, 'msg': '房间不存在'})
    if room['is_private']:
        return json.dumps({'code': 403, 'msg': '房间号对应的是私聊，无法加入'})
    room_name = room['name']
    if room['is_banned']:
        return json.dumps({'code': 403, 'msg': '该房间已被封禁'})
    if is_user_banned_from_room(room_name, username):
        return json.dumps({'code': 403, 'msg': '你已被本房间封禁'})
    ensure_user_in_room(username, room_name)
    return json.dumps({'code': 0, 'msg': '已加入群聊', 'room_name': room_name})


@app.route('/api/rooms/apply', methods=['POST'])
def apply_room():
    data = request.get_json()
    username = data.get('username', '').strip()
    room_name = data.get('room_name', '').strip()
    if not username or not room_name:
        return json.dumps({'code': 400, 'msg': '缺少参数'})
    user = get_user_by_username(username)
    if not user:
        return json.dumps({'code': 404, 'msg': '用户不存在'})
    if room_name.startswith('private_'):
        return json.dumps({'code': 400, 'msg': '房间号不合法'})
    if len(room_name) > 50:
        return json.dumps({'code': 400, 'msg': '房间名称过长'})
    existing = get_room_by_name(room_name)
    if not existing:
        ensure_user_in_room(username, room_name)
        return json.dumps({'code': 0, 'msg': '群聊已创建并加入', 'room_name': room_name})
    if existing['is_banned']:
        return json.dumps({'code': 403, 'msg': '该房间已被封禁'})
    if existing['is_private']:
        return json.dumps({'code': 400, 'msg': '私聊不支持入群申请'})
    if is_user_banned_from_room(room_name, username):
        return json.dumps({'code': 403, 'msg': '你已被本房间封禁'})
    role = get_room_member_role(room_name, username)
    if role is not None:
        return json.dumps({'code': 0, 'msg': '你已经在本群中', 'room_name': room_name})
    ok, msg = add_room_join_request(room_name, username)
    if ok:
        return json.dumps({'code': 0, 'msg': msg})
    return json.dumps({'code': 1, 'msg': msg})


@app.route('/api/rooms/join_requests', methods=['GET'])
def room_join_requests():
    username = request.args.get('username', '').strip()
    room_name = request.args.get('room_name', '').strip()
    if not username or not room_name:
        return json.dumps({'code': 400, 'msg': '缺少参数'})
    user = get_user_by_username(username)
    if not user:
        return json.dumps({'code': 404, 'msg': '用户不存在'})
    room = get_room_by_name(room_name)
    if not room:
        return json.dumps({'code': 404, 'msg': '房间不存在'})
    if room['is_private']:
        return json.dumps({'code': 400, 'msg': '私聊不支持入群申请'})
    role = get_room_member_role(room_name, username)
    if role not in ('owner', 'manager'):
        return json.dumps({'code': 403, 'msg': '只有房主或房管可以查看入群申请'})
    rows = get_room_join_requests(room_name)
    items = [{'username': r['username'], 'created_at': r['created_at']} for r in rows]
    return json.dumps({'code': 0, 'requests': items})


@app.route('/api/rooms/join_requests/handle', methods=['POST'])
def room_join_requests_handle():
    data = request.get_json()
    actor = data.get('actor')
    target = data.get('target')
    room_name = data.get('room_name')
    action = data.get('action')
    if not actor or not target or not room_name or action not in ('approve', 'reject'):
        return json.dumps({'code': 400, 'msg': '缺少参数'})
    actor_user = get_user_by_username(actor)
    target_user = get_user_by_username(target)
    if not actor_user or not target_user:
        return json.dumps({'code': 404, 'msg': '用户不存在'})
    room = get_room_by_name(room_name)
    if not room:
        return json.dumps({'code': 404, 'msg': '房间不存在'})
    if room['is_private']:
        return json.dumps({'code': 400, 'msg': '私聊不支持入群申请'})
    actor_role = get_room_member_role(room_name, actor)
    if actor_role not in ('owner', 'manager'):
        return json.dumps({'code': 403, 'msg': '只有房主或房管可以处理入群申请'})
    if action == 'approve':
        ok = approve_room_join_request(room_name, target)
        if not ok:
            return json.dumps({'code': 1, 'msg': '处理失败'})
        return json.dumps({'code': 0, 'msg': '已同意入群申请'})
    else:
        ok = reject_room_join_request(room_name, target)
        if not ok:
            return json.dumps({'code': 1, 'msg': '处理失败'})
        return json.dumps({'code': 0, 'msg': '已拒绝入群申请'})


@app.route('/api/rooms/announcement', methods=['GET', 'POST'])
def room_announcement_api():
    if request.method == 'GET':
        room_name = request.args.get('room_name', '').strip()
        if not room_name:
            return json.dumps({'code': 400, 'msg': '缺少参数'})
        room = get_room_by_name(room_name)
        if not room:
            return json.dumps({'code': 404, 'msg': '房间不存在'})
        content = get_room_announcement(room_name)
        return json.dumps({'code': 0, 'announcement': content})
    data = request.get_json()
    username = data.get('username', '').strip()
    room_name = data.get('room_name', '').strip()
    content = data.get('content', '').strip()
    if not username or not room_name:
        return json.dumps({'code': 400, 'msg': '缺少参数'})
    user = get_user_by_username(username)
    if not user:
        return json.dumps({'code': 404, 'msg': '用户不存在'})
    room = get_room_by_name(room_name)
    if not room:
        return json.dumps({'code': 404, 'msg': '房间不存在'})
    if room.get('is_private'):
        return json.dumps({'code': 400, 'msg': '私聊不支持群公告'})
    role = get_room_member_role(room_name, username)
    if role not in ('owner', 'manager'):
        return json.dumps({'code': 403, 'msg': '只有房主或房管可以修改群公告'})
    set_room_announcement(room_name, content)
    return json.dumps({'code': 0, 'msg': '群公告已更新', 'announcement': content})

@app.route('/api/rooms/list', methods=['GET'])
def list_rooms():
    username = request.args.get('username')
    if not username:
        return json.dumps({'code': 400, 'msg': '缺少用户名'})
    user = get_user_by_username(username)
    if not user:
        return json.dumps({'code': 404, 'msg': '用户不存在'})
    all_rooms = get_user_rooms(username)
    groups = [r for r in all_rooms if not r.get('is_private')]
    dms = []
    for r in all_rooms:
        if r.get('is_private'):
            dm_name = r['name']
            display_name = dm_name
            try:
                parts = dm_name.split('_')
                if len(parts) >= 3:
                    id1, id2 = int(parts[1]), int(parts[2])
                    other_id = id2 if user['id'] == id1 else id1
                    other_user = get_user_by_id(other_id)
                    if other_user:
                        display_name = other_user['username']
            except Exception:
                pass
            item = dict(r)
            item['display_name'] = display_name
            dms.append(item)
    return json.dumps({'code': 0, 'groups': groups, 'dms': dms})


@app.route('/api/user/update_nickname', methods=['POST'])
def api_update_nickname():
    data = request.get_json()
    username = data.get('username')
    new_nickname = data.get('new_nickname')
    
    if not username or not new_nickname:
        return json.dumps({'code': 400, 'msg': 'Missing parameters'})
        
    user = get_user_by_username(username)
    if not user:
        return json.dumps({'code': 404, 'msg': 'User not found'})
        
    # Validation similar to registration
    import re
    if len(new_nickname) < 2 or len(new_nickname) > 20:
        return json.dumps({'code': 400, 'msg': '昵称长度需在2-20个字符之间'})
    if not re.match(r'^[\u4e00-\u9fa5a-zA-Z0-9_]+$', new_nickname):
        return json.dumps({'code': 400, 'msg': '昵称只能包含中文、字母、数字和下划线'})
    bad_words = ['admin', 'root', 'system', '管理员', '官方', '违禁词', '傻逼', 'sb', '死']
    lower_name = new_nickname.lower()
    for word in bad_words:
        if word in lower_name:
            return json.dumps({'code': 400, 'msg': '昵称包含敏感词或保留词'})

    success, msg = update_user_nickname(username, new_nickname)
    if success:
        return json.dumps({'code': 0, 'msg': msg, 'new_nickname': new_nickname})
    else:
        return json.dumps({'code': 1, 'msg': msg})


@app.route('/api/user/update_password', methods=['POST'])
def api_update_password():
    data = request.get_json()
    username = data.get('username')
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    if not username or not old_password or not new_password:
        return json.dumps({'code': 400, 'msg': 'Missing parameters'})
        
    user = get_user_by_username(username)
    if not user:
        return json.dumps({'code': 404, 'msg': 'User not found'})
        
    if not check_password_hash(user['password_hash'], old_password):
        return json.dumps({'code': 403, 'msg': '原密码错误'})
        
    new_hash = generate_password_hash(new_password)
    update_user_password(username, new_hash)
    return json.dumps({'code': 0, 'msg': '密码修改成功'})


@app.route('/api/user/upload_avatar', methods=['POST'])
def api_upload_avatar():
    username = request.form.get('username')
    if not username:
        return json.dumps({'code': 400, 'msg': 'Missing username'})
    
    if 'avatar' not in request.files:
        return json.dumps({'code': 400, 'msg': 'No file part'})
        
    file = request.files['avatar']
    if file.filename == '':
        return json.dumps({'code': 400, 'msg': 'No selected file'})
        
    if file:
        filename = f"{uuid.uuid4().hex}_{file.filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Relative path for frontend
        avatar_url = f"/static/uploads/avatars/{filename}"
        update_user_avatar(username, avatar_url)
        
        # Broadcast user list update to rooms where this user is present
        target_rooms = set()
        for info in connected_clients.values():
            if info.get('username') == username:
                room = info.get('room')
                if room:
                    target_rooms.add(room)
        
        for room in target_rooms:
            broadcast({
                'type': 'user_list',
                'users': get_safe_online_users(room)
            }, room)
            
        return json.dumps({'code': 0, 'msg': '头像上传成功', 'avatar_url': avatar_url})
        
    return json.dumps({'code': 400, 'msg': 'Upload failed'})





@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    ws_server_id = request.form.get('ws_server')
    server_host = request.host
    servers = get_active_ws_servers()
    error = None
    if not username:
        error = '请输入昵称'
    elif not password:
        error = '请输入密码'
    if error:
        return render_template('login.html', error=error, server_host=server_host, servers=servers)
    user = get_user_by_username(username)
    if not user or not check_password_hash(user['password_hash'], password):
        return render_template('login.html', error='用户名或密码错误', server_host=server_host, servers=servers)
    if user['is_banned']:
        return render_template('login.html', error='该账号已被封禁', server_host=server_host, servers=servers)
    update_last_login(user['id'])
    ensure_user_in_room(username, PUBLIC_ROOM_NAME)
    return redirect(url_for('chat', username=username, ws_server=ws_server_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html', error=None)
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    error = None
    if not username:
        error = '请输入昵称'
    elif not password:
        error = '请输入密码'
    
    # Registration Validation
    import re
    if not error:
        # 1. Length check (2-20 chars)
        if len(username) < 2 or len(username) > 20:
            error = '昵称长度需在2-20个字符之间'
        
        # 2. Character check (Chinese, letters, numbers, underscores)
        # Regex: ^[\u4e00-\u9fa5a-zA-Z0-9_]+$
        elif not re.match(r'^[\u4e00-\u9fa5a-zA-Z0-9_]+$', username):
            error = '昵称只能包含中文、字母、数字和下划线'
            
        # 3. Profanity filter (Basic list)
        else:
            bad_words = ['admin', 'root', 'system', '管理员', '官方', '违禁词', '傻逼', 'sb', '死']
            lower_name = username.lower()
            for word in bad_words:
                if word in lower_name:
                    error = '昵称包含敏感词或保留词，请重试'
                    break

    if error:
        return render_template('register.html', error=error)
    existing = get_user_by_username(username)
    if existing:
        return render_template('register.html', error='该昵称已被注册')
    password_hash = generate_password_hash(password)
    create_user(username, password_hash)
    ensure_user_in_room(username, PUBLIC_ROOM_NAME)
    return redirect(url_for('chat', username=username))

@app.route('/api/friends', methods=['GET', 'POST'])
def friends():
    username = request.args.get('username')
    if not username:
        return json.dumps({'code': 400, 'msg': 'Missing username'})
    user = get_user_by_username(username)
    if not user:
        return json.dumps({'code': 404, 'msg': 'User not found'})
    
    if request.method == 'GET':
        friends_list = get_friends(user['id'])
        requests_list = get_received_friend_requests(user['id'])
        blocks_list = get_blocked_users(user['id'])
        return json.dumps({
            'code': 0,
            'friends': [dict(f) for f in friends_list],
            'requests': [dict(r) for r in requests_list],
            'blocks': [dict(b) for b in blocks_list],
        })
    elif request.method == 'POST':
        data = request.get_json()
        target_username = data.get('target_username')
        if not target_username:
            return json.dumps({'code': 400, 'msg': 'Missing target_username'})
        
        target = get_user_by_username(target_username)
        if not target:
            return json.dumps({'code': 404, 'msg': 'Target user not found'})
        
        success, msg = send_friend_request(user['id'], target['id'])
        if success:
            handle_friend_event('request', user['username'], target['username'])
            return json.dumps({'code': 0, 'msg': msg})
        else:
            return json.dumps({'code': 1, 'msg': msg})

@app.route('/api/friends/accept', methods=['POST'])
def friend_accept():
    data = request.get_json()
    username = data.get('username')
    request_id = data.get('request_id') # Ideally we use request_id, but our DB function uses user_ids.
    # Let's adjust DB or API. The DB accept_friend_request takes (user_id, friend_id).
    # "friend_id" in DB context is the one who SENT the request (if we view it from receiver's perspective, wait).
    # DB: user_id=Sender, friend_id=Receiver, status=pending.
    # So if Alice (id=1) requests Bob (id=2): (1, 2, pending).
    # Bob accepts: accept_friend_request(2, 1) -> looks for (1, 2, pending).
    # So API should receive: username (Bob), friend_username (Alice).
    
    friend_username = data.get('friend_username')
    if not username or not friend_username:
        return json.dumps({'code': 400, 'msg': 'Missing parameters'})
    
    user = get_user_by_username(username)
    friend = get_user_by_username(friend_username)
    if not user or not friend:
        return json.dumps({'code': 404, 'msg': 'User not found'})
        
    success, msg = accept_friend_request(user['id'], friend['id'])
    if success:
        handle_friend_event('accept', user['username'], friend['username'])
        return json.dumps({'code': 0, 'msg': msg})
    else:
        return json.dumps({'code': 1, 'msg': msg})

@app.route('/api/mark_read', methods=['POST'])
def mark_read():
    data = request.get_json()
    username = data.get('username')
    room_name = data.get('room_name')
    if not username or not room_name:
        return json.dumps({'code': 400, 'msg': 'Missing parameters'})
    
    success = mark_room_read(username, room_name)
    if success:
        return json.dumps({'code': 0, 'msg': 'Marked as read'})
    else:
        return json.dumps({'code': 1, 'msg': 'Failed'})

@app.route('/api/friends/delete', methods=['POST'])
def friend_delete():
    data = request.get_json()
    username = data.get('username')
    friend_username = data.get('friend_username')
    
    if not username or not friend_username:
        return json.dumps({'code': 400, 'msg': 'Missing parameters'})
        
    user = get_user_by_username(username)
    friend = get_user_by_username(friend_username)
    if not user or not friend:
        return json.dumps({'code': 404, 'msg': 'User not found'})
        
    success = remove_friend(user['id'], friend['id'])
    if success:
        remove_private_room_membership(user['id'], friend['id'])
        handle_friend_event('delete', user['username'], friend['username'])
        return json.dumps({'code': 0, 'msg': 'Deleted'})
    else:
        return json.dumps({'code': 1, 'msg': 'Failed'})


@app.route('/api/friends/block', methods=['POST'])
def friend_block():
    data = request.get_json()
    username = data.get('username')
    target_username = data.get('target_username')
    if not username or not target_username:
        return json.dumps({'code': 400, 'msg': 'Missing parameters'})
    user = get_user_by_username(username)
    target = get_user_by_username(target_username)
    if not user or not target:
        return json.dumps({'code': 404, 'msg': 'User not found'})
    block_user(user['id'], target['id'])
    return json.dumps({'code': 0, 'msg': '已拉黑该用户'})


@app.route('/api/friends/unblock', methods=['POST'])
def friend_unblock():
    data = request.get_json()
    username = data.get('username')
    target_username = data.get('target_username')
    if not username or not target_username:
        return json.dumps({'code': 400, 'msg': 'Missing parameters'})
    user = get_user_by_username(username)
    target = get_user_by_username(target_username)
    if not user or not target:
        return json.dumps({'code': 404, 'msg': 'User not found'})
    unblock_user(user['id'], target['id'])
    return json.dumps({'code': 0, 'msg': '已取消拉黑'})


@app.route('/api/rooms/kick', methods=['POST'])
def room_kick():
    data = request.get_json()
    actor = data.get('actor')
    target = data.get('target')
    room_name = data.get('room_name')
    if not actor or not target or not room_name:
        return json.dumps({'code': 400, 'msg': '缺少参数'})
    actor_user = get_user_by_username(actor)
    target_user = get_user_by_username(target)
    if not actor_user or not target_user:
        return json.dumps({'code': 404, 'msg': '用户不存在'})
    room = get_room_with_creator(room_name)
    if not room:
        return json.dumps({'code': 404, 'msg': '房间不存在'})
    if room.get('is_private'):
        return json.dumps({'code': 400, 'msg': '私聊不支持踢人'})
    actor_role = get_room_member_role(room_name, actor_user['username'])
    target_role = get_room_member_role(room_name, target_user['username'])
    if actor_role not in ('owner', 'manager'):
        return json.dumps({'code': 403, 'msg': '只有房主或房管可以踢人'})
    if target_role == 'owner':
        return json.dumps({'code': 403, 'msg': '不能踢出房主'})
    if actor_role == 'manager' and target_role == 'manager':
        return json.dumps({'code': 403, 'msg': '房管不能踢出其他房管'})
    if target_user['username'] == actor_user['username']:
        return json.dumps({'code': 400, 'msg': '不能踢出自己'})
    removed = remove_user_from_room(room_name, target_user['username'])
    if not removed:
        return json.dumps({'code': 1, 'msg': '该用户不在房间中'})
    for ws_conn, info in list(connected_clients.items()):
        if info.get('username') == target_user['username'] and info.get('room') == room_name:
            try:
                ws_conn.send(json.dumps({
                    'type': 'system',
                    'content': f'你已被房主从房间 {room_name} 踢出',
                    'time': datetime.datetime.now().strftime('%H:%M')
                }))
                ws_conn.close()
            except Exception:
                pass
    broadcast({
        'type': 'system',
        'content': f'{target_user["username"]} 被房主移出房间',
        'time': datetime.datetime.now().strftime('%H:%M')
    }, room_name)
    return json.dumps({'code': 0, 'msg': '已踢出'})


@app.route('/api/rooms/ban', methods=['POST'])
def room_ban():
    data = request.get_json()
    actor = data.get('actor')
    target = data.get('target')
    room_name = data.get('room_name')
    if not actor or not target or not room_name:
        return json.dumps({'code': 400, 'msg': '缺少参数'})
    actor_user = get_user_by_username(actor)
    target_user = get_user_by_username(target)
    if not actor_user or not target_user:
        return json.dumps({'code': 404, 'msg': '用户不存在'})
    room = get_room_with_creator(room_name)
    if not room:
        return json.dumps({'code': 404, 'msg': '房间不存在'})
    if room.get('is_private'):
        return json.dumps({'code': 400, 'msg': '私聊不支持禁人'})
    actor_role = get_room_member_role(room_name, actor_user['username'])
    target_role = get_room_member_role(room_name, target_user['username'])
    if actor_role not in ('owner', 'manager'):
        return json.dumps({'code': 403, 'msg': '只有房主或房管可以禁人'})
    if target_role == 'owner':
        return json.dumps({'code': 403, 'msg': '不能禁房主'})
    if actor_role == 'manager' and target_role == 'manager':
        return json.dumps({'code': 403, 'msg': '房管不能禁其他房管'})
    if target_user['username'] == actor_user['username']:
        return json.dumps({'code': 400, 'msg': '不能禁自己'})
    add_room_ban(room_name, target_user['username'])
    remove_user_from_room(room_name, target_user['username'])
    for ws_conn, info in list(connected_clients.items()):
        if info.get('username') == target_user['username'] and info.get('room') == room_name:
            try:
                ws_conn.send(json.dumps({
                    'type': 'system',
                    'content': f'你已被房主封禁，无法再次加入房间 {room_name}',
                    'time': datetime.datetime.now().strftime('%H:%M')
                }))
                ws_conn.close()
            except Exception:
                pass
    broadcast({
        'type': 'system',
        'content': f'{target_user["username"]} 被房主封禁',
        'time': datetime.datetime.now().strftime('%H:%M')
    }, room_name)
    return json.dumps({'code': 0, 'msg': '已封禁'})


@app.route('/api/rooms/invite', methods=['POST'])
def room_invite():
    data = request.get_json()
    actor = data.get('actor')
    target = data.get('target')
    room_name = data.get('room_name')
    if not actor or not target or not room_name:
        return json.dumps({'code': 400, 'msg': '缺少参数'})
    actor_user = get_user_by_username(actor)
    target_user = get_user_by_username(target)
    if not actor_user or not target_user:
        return json.dumps({'code': 404, 'msg': '用户不存在'})
    room = get_room_by_name(room_name)
    if not room:
        return json.dumps({'code': 404, 'msg': '房间不存在'})
    if room.get('is_private'):
        return json.dumps({'code': 400, 'msg': '私聊不支持邀请入群'})
    if room.get('is_banned'):
        return json.dumps({'code': 403, 'msg': '该房间已被封禁'})
    actor_role = get_room_member_role(room_name, actor_user['username'])
    if actor_role is None:
        return json.dumps({'code': 403, 'msg': '仅房间成员可以邀请好友'})
    if is_user_banned_from_room(room_name, target_user['username']):
        return json.dumps({'code': 403, 'msg': '该用户已被本房间封禁，无法邀请'})
    target_role = get_room_member_role(room_name, target_user['username'])
    if target_role is not None:
        return json.dumps({'code': 1, 'msg': '该用户已在房间中'})
    ensure_user_in_room(target_user['username'], room_name)
    broadcast({
        'type': 'system',
        'content': f'{target_user["username"]} 被 {actor_user["username"]} 邀请加入群聊',
        'time': datetime.datetime.now().strftime('%H:%M')
    }, room_name)
    return json.dumps({'code': 0, 'msg': '邀请成功'})


@app.route('/api/rooms/set_manager', methods=['POST'])
def room_set_manager():
    data = request.get_json()
    actor = data.get('actor')
    target = data.get('target')
    room_name = data.get('room_name')
    is_manager = bool(data.get('is_manager'))
    if not actor or not target or not room_name:
        return json.dumps({'code': 400, 'msg': '缺少参数'})
    actor_user = get_user_by_username(actor)
    target_user = get_user_by_username(target)
    if not actor_user or not target_user:
        return json.dumps({'code': 404, 'msg': '用户不存在'})
    room = get_room_with_creator(room_name)
    if not room:
        return json.dumps({'code': 404, 'msg': '房间不存在'})
    if room.get('is_private'):
        return json.dumps({'code': 400, 'msg': '私聊不支持房管设置'})
    actor_role = get_room_member_role(room_name, actor_user['username'])
    if actor_role != 'owner':
        return json.dumps({'code': 403, 'msg': '只有房主可以设置房管'})
    if target_user['username'] == actor_user['username']:
        return json.dumps({'code': 400, 'msg': '不能修改自己角色'})
    target_role = get_room_member_role(room_name, target_user['username'])
    if target_role is None:
        return json.dumps({'code': 400, 'msg': '目标用户不在房间中'})
    new_role = 'manager' if is_manager else 'member'
    set_room_member_role(room_name, target_user['username'], new_role)
    return json.dumps({'code': 0, 'msg': '已更新角色'})


@app.route('/api/rooms/member_roles', methods=['GET'])
def room_member_roles():
    username = request.args.get('username')
    room_name = request.args.get('room_name')
    if not username or not room_name:
        return json.dumps({'code': 400, 'msg': '缺少参数'})
    user = get_user_by_username(username)
    if not user:
        return json.dumps({'code': 404, 'msg': '用户不存在'})
    room = get_room_by_name(room_name)
    if not room:
        return json.dumps({'code': 404, 'msg': '房间不存在'})
    rows = get_room_member_roles(room_name)
    members = [{'username': r['username'], 'role': r['role'], 'avatar': r['avatar']} for r in rows]
    return json.dumps({'code': 0, 'members': members})

@app.route('/api/search/users', methods=['GET'])
def search_users():
    query = request.args.get('q')
    username = request.args.get('username')
    if not query or not username:
        return json.dumps({'code': 400, 'msg': 'Missing query or username'})
        
    user = get_user_by_username(username)
    if not user:
        return json.dumps({'code': 404, 'msg': 'User not found'})
        
    results = search_users_exclude_friends(query, user['id'])
    return json.dumps({
        'code': 0, 
        'data': [{'username': r['username']} for r in results]
    })


@app.route('/api/ai/chat_stream')
def ai_chat_stream():
    username = request.args.get('username')
    prompt = request.args.get('prompt')
    room_name_arg = request.args.get('room_name')
    
    if not username or not prompt:
        return "Missing parameters", 400
        
    user = get_user_by_username(username)
    if not user:
        return "User not found", 404
        
    model = get_default_ai_model()
    if not model:
        def generate_error():
            yield "data: " + json.dumps({'content': '[系统提示] 当前没有可用的默认AI模型，请联系管理员。'}, ensure_ascii=False) + "\n\n"
            yield "data: [DONE]\n\n"
        return Response(stream_with_context(generate_error()), mimetype='text/event-stream')
        
    if OpenAI is None:
        def generate_error():
            yield "data: " + json.dumps({'content': '[系统提示] 后端缺少 openai 依赖库。'}, ensure_ascii=False) + "\n\n"
            yield "data: [DONE]\n\n"
        return Response(stream_with_context(generate_error()), mimetype='text/event-stream')

    # Find the user's room to broadcast to
    room_name = room_name_arg
    if not room_name:
        for _, info in connected_clients.items():
            if info.get('username') == username:
                room_name = info.get('room')
                break
            
    # Fallback if not found (though unlikely if they are chatting)
    if not room_name:
        room_name = PUBLIC_ROOM_NAME

    def generate():
        ai_msg_id = str(uuid.uuid4())
        
        # Get dynamic AI name
        ai_user = get_ai_user()
        ai_name = ai_user['username'] if ai_user else 'AI'
        ai_avatar = ai_user['avatar'] if ai_user and ai_user.get('avatar') else None
        
        # Broadcast Start Event to Room
        broadcast({
            'type': 'ai_message_start',
            'id': ai_msg_id,
            'ai_name': f'{ai_name} (AI)',
            'ai_avatar': ai_avatar,
            'reply_to': username,
            'time': datetime.datetime.now().strftime('%H:%M')
        }, room_name)

        try:
            client = OpenAI(
                api_key=model['api_key'],
                base_url=model['api_base'],
                timeout=30.0
            )
            
            messages = []
            if model['prompt']:
                # Inject dynamic name into system prompt
                sys_prompt = model['prompt']
                if ai_name and ai_name != 'AI':
                     sys_prompt = sys_prompt.replace('内小妹', ai_name)
                     # Also append explicit instruction to be sure
                     sys_prompt += f"\nIMPORTANT: Your name is {ai_name}. Always use this name."
                messages.append({'role': 'system', 'content': sys_prompt})
            
            clean_prompt = prompt.replace(f'@{ai_name}', '').strip()
            messages.append({'role': 'user', 'content': clean_prompt})
            
            stream = client.chat.completions.create(
                model=model['model_name'],
                messages=messages,
                stream=True
            )
            
            # Prefix with @username
            prefix = f"@{username} "
            full_response = prefix
            
            # Send prefix first
            broadcast({
                'type': 'ai_message_chunk',
                'id': ai_msg_id,
                'content': prefix
            }, room_name)
            yield f"data: {json.dumps({'content': prefix}, ensure_ascii=False)}\n\n"
            
            for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    content = chunk.choices[0].delta.content
                    full_response += content
                    
                    # Broadcast Chunk
                    broadcast({
                        'type': 'ai_message_chunk',
                        'id': ai_msg_id,
                        'content': content
                    }, room_name)
                    
                    yield f"data: {json.dumps({'content': content}, ensure_ascii=False)}\n\n"
            
            # Save the full message to database
            print(f"[DEBUG] Saving AI message: ai_name={ai_name}, room={room_name}, len={len(full_response)}")
            save_message(ai_name, full_response, room_name=room_name)

            # Broadcast End
            broadcast({
                'type': 'ai_message_end',
                'id': ai_msg_id
            }, room_name)
            
            yield "data: [DONE]\n\n"
            
        except Exception as e:
            error_msg = f'\n[Error: {str(e)}]'
            broadcast({
                'type': 'ai_message_chunk',
                'id': ai_msg_id,
                'content': error_msg
            }, room_name)
            broadcast({
                'type': 'ai_message_end',
                'id': ai_msg_id
            }, room_name)
            
            yield f"data: {json.dumps({'error': str(e)}, ensure_ascii=False)}\n\n"
            yield "data: [DONE]\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')


@sock.route('/ws')
def websocket(ws):
    try:
        while True:
            data = ws.receive()
            if data:
                message_data = json.loads(data)
                msg_type = message_data.get('type')
                
                if msg_type == 'join':
                    username = message_data.get('username')
                    room_name = message_data.get('room') or PUBLIC_ROOM_NAME
                    user_row = get_user_by_username(username)
                    if not user_row:
                        ws.send(json.dumps({
                            'type': 'system',
                            'content': '未注册用户，无法加入群聊',
                            'time': datetime.datetime.now().strftime('%H:%M')
                        }))
                        break
                    if user_row['is_banned']:
                        ws.send(json.dumps({
                            'type': 'system',
                            'content': '该账号已被封禁，无法加入',
                            'time': datetime.datetime.now().strftime('%H:%M')
                        }))
                        break
                    room = get_room_by_name(room_name)
                    if room and room['is_banned']:
                        ws.send(json.dumps({
                            'type': 'system',
                            'content': f'房间 {room_name} 已被封禁，无法加入',
                            'time': datetime.datetime.now().strftime('%H:%M')
                        }))
                        break
                    if is_user_banned_from_room(room_name, username):
                        ws.send(json.dumps({
                            'type': 'system',
                            'content': f'你已被房主封禁，无法加入房间 {room_name}',
                            'time': datetime.datetime.now().strftime('%H:%M')
                        }))
                        break

                    ensure_user_in_room(username, room_name)
                    
                    # Single Session Enforcement: Kick old connection if exists
                    # We check if this user is already connected in ANY room (or specifically this app instance)
                    # Since users might open multiple tabs for different rooms, we might want to allow that?
                    # The requirement says "Login only allows 1 account online". 
                    # Usually this means 1 active session. If we want strict single session, we should check by username.
                    # However, this app architecture seems to create a WS per room/page load.
                    # If the user opens multiple tabs, they are multiple WS connections.
                    # If we kick the old one, multi-tab support breaks.
                    # Assuming "1 account online" means "kick other devices". 
                    # If I am on Device A, and I login on Device B.
                    # But here we don't distinguish devices easily without a session token or device ID.
                    # Let's assume strict single session: If a new WS connects with username X, close ALL other WS with username X.
                    
                    for old_ws, info in list(connected_clients.items()):
                        if info.get('username') == username:
                            try:
                                old_ws.send(json.dumps({
                                    'type': 'system',
                                    'content': '您的账号已在别处登录，当前连接已断开',
                                    'time': datetime.datetime.now().strftime('%H:%M')
                                }))
                                old_ws.close()
                            except:
                                pass
                            # We don't need to pop here, the finally block of the old_ws loop will handle it?
                            # Actually, if we close it, the 'finally' block in the other thread/loop will run.
                            # But to be safe and avoid race conditions, we can let the other loop handle removal.

                    connected_clients[ws] = {
                        "username": username,
                        "room": room_name,
                    }
                    
                    join_msg = f'{username} 加入了私聊' if room_name.startswith('private_') else f'{username} 加入了群聊'
                    broadcast({
                        'type': 'system',
                        'content': join_msg,
                        'time': datetime.datetime.now().strftime('%H:%M')
                    }, room_name)
                    
                    current_users = get_safe_online_users(room_name)
                    ws.send(json.dumps({
                        'type': 'user_list',
                        'users': current_users
                    }))
                    
                    # Get messages with unread support
                    recent = get_messages_with_unread_focus(username, room_name)
                    if recent:
                        ws.send(json.dumps({
                            'type': 'history',
                            'messages': recent
                        }))
                    
                    broadcast({
                        'type': 'user_list',
                        'users': get_safe_online_users(room_name)
                    }, room_name)
                    
                elif msg_type == 'message':
                    info = connected_clients.get(ws)
                    username = info.get("username") if info else "Unknown"
                    room_name = info.get("room") if info else PUBLIC_ROOM_NAME
                    content = message_data.get('content')
                    
                    if content:
                        # Check for interface commands
                        interfaces = get_all_active_interfaces()
                        handled_by_interface = False
                        
                        for iface in interfaces:
                            cmd = iface['command']
                            if content.startswith(cmd):
                                arg = content[len(cmd):].strip()
                                # If command is strictly equal (no args needed) or has args
                                if not arg and len(content) > len(cmd):
                                     continue
                                
                                print(f"DEBUG: Matched interface {iface['name']}, cmd='{cmd}', arg='{arg}'") # Debug log

                                # Execute Interface
                                handled_by_interface = True
                                
                                # Save user message first
                                save_message(username, content, room_name=room_name)
                                
                                # Get avatar
                                user = get_user_by_username(username)
                                avatar = user['avatar'] if user else None
                                
                                broadcast({
                                    'type': 'message',
                                    'username': username,
                                    'avatar': avatar,
                                    'content': content,
                                    'time': datetime.datetime.now().strftime('%H:%M')
                                }, room_name)
                                
                                # Special Handling for Movie (Client-side Rendering)
                                if '电影' in iface['name'] or 'movie' in iface['name'].lower():
                                    target_url = iface['url']
                                    if '{}' in target_url:
                                        target_url = target_url.replace('{}', arg)
                                    else:
                                        target_url += arg
                                    
                                    broadcast({
                                        'type': 'movie_card',
                                        'username': iface['name'],
                                        'url': target_url,
                                        'time': datetime.datetime.now().strftime('%H:%M')
                                    }, room_name)
                                    
                                    # Save as JSON for persistence
                                    card_data = {
                                        'type': 'movie_card',
                                        'username': iface['name'],
                                        'url': target_url,
                                        'time': datetime.datetime.now().strftime('%H:%M')
                                    }
                                    summary = "$$JSON$$" + json.dumps(card_data)
                                    save_message(iface['name'], summary, room_name=room_name)
                                    break

                                try:
                                    if '新闻' in iface['name'] or 'news' in iface['name'].lower():
                                        if not iface['token']:
                                            err_msg = '新闻接口未配置 Token，请先在后台接口管理中填写 Token'
                                            broadcast({
                                                'type': 'system',
                                                'content': err_msg,
                                                'time': datetime.datetime.now().strftime('%H:%M')
                                            }, room_name)
                                            save_message(iface['name'], err_msg, room_name=room_name)
                                        else:
                                            target_url = iface['url']
                                            data = {'token': iface['token']}
                                            resp = requests.post(target_url, data=data, timeout=10)
                                            if resp.status_code == 200:
                                                try:
                                                    news_data = resp.json()
                                                except Exception:
                                                    text_resp = resp.text
                                                    broadcast({
                                                        'type': 'message',
                                                        'username': iface['name'],
                                                        'content': text_resp,
                                                        'time': datetime.datetime.now().strftime('%H:%M')
                                                    }, room_name)
                                                    save_message(iface['name'], text_resp, room_name=room_name)
                                                else:
                                                    if isinstance(news_data, dict) and str(news_data.get('code')) != '200':
                                                        err_text = news_data.get('data') or news_data.get('msg') or '新闻接口调用失败'
                                                        full_msg = '新闻接口错误: ' + str(err_text)
                                                        broadcast({
                                                            'type': 'system',
                                                            'content': full_msg,
                                                            'time': datetime.datetime.now().strftime('%H:%M')
                                                        }, room_name)
                                                        save_message(iface['name'], full_msg, room_name=room_name)
                                                    else:
                                                        payload = {
                                                            'type': 'news_card',
                                                            'username': iface['name'],
                                                            'data': news_data,
                                                            'time': datetime.datetime.now().strftime('%H:%M')
                                                        }
                                                        broadcast(payload, room_name)
                                                        summary = "$$JSON$$" + json.dumps(payload)
                                                        save_message(iface['name'], summary, room_name=room_name)
                                            else:
                                                err_msg = f"接口调用失败: {resp.status_code}"
                                                broadcast({
                                                    'type': 'system',
                                                    'content': err_msg,
                                                    'time': datetime.datetime.now().strftime('%H:%M')
                                                }, room_name)
                                    elif '音乐' in iface['name'] or 'music' in iface['name'].lower():
                                        token_value = (iface['token'] or '').strip() if 'token' in iface.keys() else ''
                                        if not token_value:
                                            err_msg = '音乐接口未配置 Token，请先在后台接口管理中填写 Token'
                                            broadcast({
                                                'type': 'system',
                                                'content': err_msg,
                                                'time': datetime.datetime.now().strftime('%H:%M')
                                            }, room_name)
                                            save_message(iface['name'], err_msg, room_name=room_name)
                                        else:
                                            target_url = iface['url']
                                            data = {'token': token_value}
                                            params = {'token': token_value}
                                            resp = requests.post(target_url, data=data, params=params, timeout=10)
                                            if resp.status_code == 200:
                                                try:
                                                    music_data = resp.json()
                                                except Exception:
                                                    text_resp = resp.text
                                                    broadcast({
                                                        'type': 'message',
                                                        'username': iface['name'],
                                                        'content': text_resp,
                                                        'time': datetime.datetime.now().strftime('%H:%M')
                                                    }, room_name)
                                                    save_message(iface['name'], text_resp, room_name=room_name)
                                                else:
                                                    if isinstance(music_data, dict) and str(music_data.get('code')) not in ('200', '0'):
                                                        err_text = music_data.get('data') or music_data.get('msg') or '音乐接口调用失败'
                                                        full_msg = '音乐接口错误: ' + str(err_text)
                                                        broadcast({
                                                            'type': 'system',
                                                            'content': full_msg,
                                                            'time': datetime.datetime.now().strftime('%H:%M')
                                                        }, room_name)
                                                        save_message(iface['name'], full_msg, room_name=room_name)
                                                    else:
                                                        payload = {
                                                            'type': 'music_card',
                                                            'username': iface['name'],
                                                            'data': music_data,
                                                            'time': datetime.datetime.now().strftime('%H:%M'),
                                                            'interface_name': iface['name']
                                                        }
                                                        broadcast(payload, room_name)
                                                        summary = "$$JSON$$" + json.dumps(payload)
                                                        save_message(iface['name'], summary, room_name=room_name)
                                            else:
                                                err_msg = f"接口调用失败: {resp.status_code}"
                                                broadcast({
                                                    'type': 'system',
                                                    'content': err_msg,
                                                    'time': datetime.datetime.now().strftime('%H:%M')
                                                }, room_name)
                                    else:
                                        target_url = iface['url']
                                        if '{}' in target_url:
                                            target_url = target_url.replace('{}', arg)
                                        else:
                                            target_url += arg
                                        headers = {}
                                        if iface['token']:
                                            headers['Authorization'] = f"Bearer {iface['token']}"
                                        resp = requests.get(target_url, headers=headers, timeout=10)
                                        if resp.status_code == 200:
                                            if '天气' in iface['name'] or 'weather' in iface['name'].lower():
                                                try:
                                                    weather_data = resp.json()
                                                    broadcast({
                                                        'type': 'weather_card',
                                                        'username': iface['name'],
                                                        'data': weather_data,
                                                        'location': arg,
                                                        'time': datetime.datetime.now().strftime('%H:%M')
                                                    }, room_name)
                                                    card_data = {
                                                        'type': 'weather_card',
                                                        'username': iface['name'],
                                                        'data': weather_data,
                                                        'location': arg,
                                                        'time': datetime.datetime.now().strftime('%H:%M')
                                                    }
                                                    summary = "$$JSON$$" + json.dumps(card_data)
                                                    save_message(iface['name'], summary, room_name=room_name)
                                                except Exception:
                                                    text_resp = resp.text
                                                    broadcast({
                                                        'type': 'message',
                                                        'username': iface['name'],
                                                        'content': text_resp,
                                                        'time': datetime.datetime.now().strftime('%H:%M')
                                                    }, room_name)
                                                    save_message(iface['name'], text_resp, room_name=room_name)
                                            else:
                                                text_resp = resp.text
                                                try:
                                                    j = resp.json()
                                                    if isinstance(j, dict):
                                                        if 'text' in j:
                                                            text_resp = j['text']
                                                        elif 'message' in j:
                                                            text_resp = j['message']
                                                        elif 'msg' in j:
                                                            text_resp = j['msg']
                                                        elif 'data' in j:
                                                            text_resp = str(j['data'])
                                                        else:
                                                            text_resp = str(j)
                                                except Exception:
                                                    pass
                                                broadcast({
                                                    'type': 'message',
                                                    'username': iface['name'],
                                                    'content': text_resp,
                                                    'time': datetime.datetime.now().strftime('%H:%M')
                                                }, room_name)
                                                save_message(iface['name'], text_resp, room_name=room_name)
                                        else:
                                            err_msg = f"接口调用失败: {resp.status_code}"
                                            broadcast({
                                                'type': 'system',
                                                'content': err_msg,
                                                'time': datetime.datetime.now().strftime('%H:%M')
                                            }, room_name)
                                except Exception as e:
                                    print(f"Interface Error: {e}")
                                    broadcast({
                                        'type': 'system',
                                        'content': f"接口错误: {str(e)}",
                                        'time': datetime.datetime.now().strftime('%H:%M')
                                    }, room_name)
                                
                                break # Stop checking other interfaces
                        
                        if not handled_by_interface:
                            save_message(username, content, room_name=room_name)
                            
                            # Get avatar
                            user = get_user_by_username(username)
                            avatar = user['avatar'] if user else None
                            
                            broadcast({
                                'type': 'message',
                                'username': username,
                                'avatar': avatar,
                                'content': content,
                                'time': datetime.datetime.now().strftime('%H:%M')
                            }, room_name)
                elif msg_type == 'leave':
                    break
    except Exception as e:
        pass
    finally:
        info = connected_clients.pop(ws, None)
        if info:
            username = info.get("username")
            room_name = info.get("room") or PUBLIC_ROOM_NAME
            leave_msg = f'{username} 离开了私聊' if room_name.startswith('private_') else f'{username} 离开了群聊'
            broadcast({
                'type': 'system',
                'content': leave_msg,
                'time': datetime.datetime.now().strftime('%H:%M')
            }, room_name)
            broadcast({
                'type': 'user_list',
                'users': get_safe_online_users(room_name)
            }, room_name)

def broadcast(message_dict, room_name=None):
    message_json = json.dumps(message_dict)
    for ws, info in list(connected_clients.items()):
        if room_name is not None:
            room = info.get("room")
            if room != room_name:
                continue
        try:
            ws.send(message_json)
        except:
            connected_clients.pop(ws, None)

def handle_admin_event(event_type, target_username):
    """
    Handle admin events like ban or delete user.
    event_type: 'ban', 'delete', 'kick'
    """
    for ws, info in list(connected_clients.items()):
        if info.get('username') == target_username:
            msg_content = ''
            if event_type == 'ban':
                msg_content = '您的账号已被管理员封禁，连接断开'
            elif event_type == 'delete':
                msg_content = '您的账号已被管理员删除，连接断开'
            elif event_type == 'kick':
                msg_content = '您的账号信息已变更，请重新登录'
            
            if msg_content:
                try:
                    ws.send(json.dumps({
                        'type': 'system',
                        'content': msg_content,
                        'time': datetime.datetime.now().strftime('%H:%M')
                    }))
                    ws.close()
                except:
                    pass
            # We don't pop here, let the websocket loop's finally block handle cleanup and broadcast
            
app.handle_admin_event = handle_admin_event

@app.route('/api/music/refresh', methods=['POST'])
def refresh_music_card():
    data = request.get_json()
    interface_name = data.get('interface_name')
    if not interface_name:
        return json.dumps({'code': 400, 'msg': '缺少参数'})
    
    interfaces = get_all_active_interfaces()
    target_iface = None
    for iface in interfaces:
        if iface['name'] == interface_name:
            target_iface = iface
            break
            
    if not target_iface:
        return json.dumps({'code': 404, 'msg': '接口不存在或已关闭'})
        
    # Logic from socket handling
    token_value = (target_iface['token'] or '').strip() if 'token' in target_iface.keys() else ''
    if not token_value:
        return json.dumps({'code': 500, 'msg': '接口Token未配置'})
        
    target_url = target_iface['url']
    req_data = {'token': token_value}
    params = {'token': token_value}
    
    try:
        resp = requests.post(target_url, data=req_data, params=params, timeout=10)
        if resp.status_code == 200:
            try:
                music_data = resp.json()
                if isinstance(music_data, dict) and str(music_data.get('code')) not in ('200', '0'):
                     return json.dumps({'code': 502, 'msg': music_data.get('msg', '接口返回错误')})
                return json.dumps({'code': 0, 'data': music_data})
            except:
                return json.dumps({'code': 502, 'msg': '接口返回格式错误'})
        else:
            return json.dumps({'code': 502, 'msg': f'接口调用失败: {resp.status_code}'})
    except Exception as e:
        return json.dumps({'code': 500, 'msg': str(e)})

@app.route('/api/music/proxy')
def proxy_music_audio():
    url = request.args.get('url')
    music_id = request.args.get('id')
    
    if not url and not music_id:
        return Response('Missing URL or ID', status=400)
    
    if not url and music_id:
        url = f"https://music.163.com/song/media/outer/url?id={music_id}.mp3"
    
    # Simple validation to prevent arbitrary local file access or other misuse
    if not url.startswith('http'):
        return Response('Invalid URL', status=400)

    try:
        # Mimic a browser request to bypass basic anti-hotlinking
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Referer': 'https://music.163.com/',
            'Range': request.headers.get('Range')  # Forward Range header for seeking
        }
        
        # Stream the content
        # allow_redirects=True is default, which is good for Netease outer links
        resp = requests.get(url, headers=headers, stream=True, timeout=15)
        
        # Check if we got a valid audio file (sometimes Netease returns a 404 page or JSON)
        content_type = resp.headers.get('Content-Type', '')
        if 'text/html' in content_type:
             # Try to parse if it's a Netease error page? Or just fail.
             return Response("Music unavailable (Netease returned HTML)", status=404)
        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.headers.items()
                   if name.lower() not in excluded_headers]
        
        return Response(
            stream_with_context(resp.iter_content(chunk_size=1024*8)),
            status=resp.status_code,
            headers=headers,
            direct_passthrough=True
        )
    except Exception as e:
        return Response(str(e), status=500)

if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, 'config.json')
    default_server = {
        'host': '0.0.0.0',
        'port': 5000,
        'debug': True
    }
    server_cfg = {}
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            server_cfg = data.get('server', {}) or {}
    except Exception:
        server_cfg = {}
    init_db()
    host = server_cfg.get('host', default_server['host'])
    try:
        port = int(server_cfg.get('port', default_server['port']))
    except Exception:
        port = default_server['port']
    debug = bool(server_cfg.get('debug', default_server['debug']))
    app.run(host=host, port=port, debug=debug)
