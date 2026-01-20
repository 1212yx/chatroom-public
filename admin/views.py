from flask import render_template, request, redirect, url_for, session, flash, current_app, Response, stream_with_context
from . import admin_bp
from database.db import (
    get_admin,
    get_all_users,
    count_users,
    count_banned_users,
    get_user_by_id,
    update_user_by_admin,
    delete_user,
    set_user_ban_status,
    batch_delete_users,
    batch_set_user_ban_status,
    get_all_rooms_with_stats,
    count_rooms,
    count_banned_rooms,
    get_room_by_id,
    delete_room,
    set_room_ban_status,
    get_room_members_list,
    count_room_members,
    get_all_ws_servers,
    get_ws_server_by_id,
    add_ws_server,
    update_ws_server,
    delete_ws_server,
    count_ws_servers,
    count_active_ws_servers,
    get_ai_models,
    count_ai_models,
    get_ai_model_by_id,
    add_ai_model,
    update_ai_model,
    delete_ai_model,
    set_ai_model_active,
    get_all_active_ai_models,
    update_ai_model_usage,
    get_all_interfaces,
    count_interfaces,
    add_interface,
    update_interface,
    delete_interface,
    get_interface_by_id,
    toggle_interface_status,
    get_active_admin_menus,
    get_admin_menus,
    count_admin_menus,
    add_admin_menu,
    update_admin_menu,
    delete_admin_menu,
    get_admin_menu_by_id,
    get_roles,
    count_roles,
    get_role_by_id,
    add_role,
    update_role,
    delete_role,
    get_role_menu_ids,
    set_role_menus,
    get_admins,
    count_admins,
    get_admin_by_id,
    create_admin,
    update_admin,
    delete_admin,
    get_admin_role_ids,
    set_admin_roles,
    get_admin_menus_for_admin,
    count_messages,
    get_ai_usage_summary,
    get_default_ai_model,
    get_user_stats_for_ai,
    get_room_stats_for_ai,
    get_message_stats_for_ai,
    get_room_member_stats_for_ai,
    get_ai_employees,
    count_ai_employees,
    add_ai_employee,
    update_ai_employee,
    get_ai_employee_by_id,
    get_dashboard_stats,
)
from werkzeug.security import generate_password_hash
import math
import json
import time

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

@admin_bp.route('/dashboard')
def dashboard():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    return render_template('admin/dashboard.html')

@admin_bp.route('/api/dashboard/stats')
def dashboard_stats():
    if not session.get('admin_id'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    stats = get_dashboard_stats()
    
    # Calculate online users from connected_clients
    from app import connected_clients
    unique_users = set()
    for client in connected_clients.values():
        if client.get('username'):
            unique_users.add(client['username'])
    
    stats['online_users'] = len(unique_users)
    
    return Response(json.dumps(stats, ensure_ascii=False), mimetype='application/json')

@admin_bp.before_request
def before_request():
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        session['base_layout'] = 'admin/base_ajax.html'
    else:
        session['base_layout'] = 'admin/base.html'

@admin_bp.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


@admin_bp.context_processor
def inject_sidebar_menus():
    admin_id = session.get('admin_id')
    admin_name = session.get('admin_name')
    if not admin_id:
        try:
            menus = get_active_admin_menus(limit=200)
        except Exception:
            menus = []
    else:
        # If admin is superuser 'admin', they get all menus by default in old logic
        # But to respect role permissions strictly, we should check if 'admin' needs to be restricted or has all roles.
        # Usually superuser 'admin' has access to everything.
        # However, user requested: "Only if associated with dashboard menu can see dashboard"
        # So we should treat 'admin' like any other user regarding role-based menu access, 
        # OR we assume 'admin' has all permissions but we want to HIDE dashboard if not explicitly assigned?
        # Re-reading user request: "不需要重新创建...只要关联了数字大屏菜单即可查看到"
        # This implies standard RBAC. 
        # But 'admin' user usually bypasses RBAC in this system (get_active_admin_menus called directly).
        # To support "admin default doesn't see dashboard unless assigned", we need to change how admin gets menus.
        
        # Current Logic for 'admin':
        # if admin_name == 'admin': menus = get_active_admin_menus() (All menus)
        
        # We need to change this so 'admin' also follows role-based access OR explicitly exclude dashboard from 'all menus'
        # But user said "admin default doesn't appear dashboard".
        
        if admin_name == 'admin':
            try:
                # Get all menus first
                all_menus = get_active_admin_menus(limit=200)
                # Filter out dashboard for admin unless they have a role that grants it? 
                # Or simply: Admin sees everything EXCEPT dashboard?
                # User said: "admin默认中不出现数据大屏" AND "只要关联了...即可查看"
                # This suggests 'admin' should NOT see it by default.
                
                # Strategy: For 'admin', load all menus BUT filter out dashboard.
                # If 'admin' needs to see it, they should assign a role to themselves?
                # But 'admin' is superuser.
                
                # Alternative interpretation: 'admin' user should ALSO be subject to Role-Based Menu system?
                # If we switch 'admin' to use get_admin_menus_for_admin(admin_id), then 'admin' needs roles assigned.
                # Let's check if 'admin' has roles.
                
                # Let's try to mix: Admin gets all standard system menus, but special menus like Dashboard require role?
                # Or simpler: Just hide it for admin as requested in previous turn, but allow it if they have permission?
                # But 'admin' has all permissions by default implementation.
                
                # Let's implement strict RBAC for everyone including 'admin' IF we want total control.
                # But that might break existing access if 'admin' has no roles.
                
                # Safer approach matching user intent "Associated -> Visible":
                # We will check if the current user (even admin) has the specific permission/role for dashboard.
                # BUT 'admin' usually bypasses this.
                
                # Let's modify: Admin sees all menus EXCEPT those marked as "Require Explicit Assignment"?
                # No such field.
                
                # Let's stick to the User's specific logic: 
                # "Only login Liaowang (or anyone with role) sees it, admin default doesn't"
                # And "Don't need to create new role, just associate menu".
                
                # So, for 'admin' (superuser), we will EXPLICITLY filter out '数字大屏' unless we find a reason to show it?
                # Actually, the previous code I just removed did exactly that: hid it for admin.
                # The user said: "不需要重新创建...只要关联了...即可查看"
                # This implies if I assign the menu to 'admin' (via a role), 'admin' should see it.
                # But 'admin' by default gets ALL menus via `get_active_admin_menus`.
                
                # So I should change `if admin_name == 'admin'` block to NOT automatically get all menus, 
                # OR filter the result of `get_active_admin_menus`.
                
                menus = get_active_admin_menus(limit=200)
                # Default admin shouldn't see Dashboard (id=8 or url='/admin/dashboard')
                # UNLESS they have a role that explicitly grants it? 
                # But `get_active_admin_menus` returns everything.
                
                # Let's check if 'admin' has the role for dashboard.
                # If not, filter it out from the "All Menus" list.
                
                has_dashboard_access = False
                # Check if admin has a role with dashboard menu
                # We need a helper or query for this.
                # Since we are in view, we can query.
                
                # Hack: Just filter it out for 'admin' for now as per "admin default no show".
                # User said: "只要关联了...即可查看". 
                # This means if I go to Role Management, give 'admin' a role with 'Dashboard', they should see it.
                # But `get_active_admin_menus` ignores roles.
                
                # CORRECT FIX:
                # 1. 'admin' should ALSO use `get_admin_menus_for_admin` (RBAC) 
                #    BUT we must ensure 'admin' has a "Super Admin" role with all other menus first.
                #    If 'admin' has no roles, they will see nothing, which is bad.
                
                # 2. Hybrid: 'admin' gets All Menus MINUS Dashboard. 
                #    PLUS Dashboard IF authorized via Role.
                
                user_menus = get_admin_menus_for_admin(admin_id) # Menus from assigned roles
                user_menu_ids = set(m['id'] for m in user_menus)
                
                final_menus = []
                for m in menus:
                    # If it's Dashboard
                    if m['url'] == '/admin/dashboard':
                        # Only show if explicitly in assigned roles
                        if m['id'] in user_menu_ids:
                            final_menus.append(m)
                    else:
                        # Show all other menus for admin by default
                        final_menus.append(m)
                menus = final_menus
                
            except Exception:
                menus = []
        else:
            try:
                menus = get_admin_menus_for_admin(admin_id)
            except Exception:
                menus = []
    filtered_menus = []
    for m in menus:
        name = m.get('name') if isinstance(m, dict) else m['name']
        url = m.get('url') if isinstance(m, dict) else m['url']
        
        # Filter out placeholder/invalid dashboard menu
        if name == '数字大屏' and url == 'admin':
            continue
            
        filtered_menus.append(m)
    menus = filtered_menus
    grouped = {}
    for m in menus:
        category = m.get('category') if isinstance(m, dict) else m['category']
        if not category:
            category = '菜单'
        if category not in grouped:
            grouped[category] = []
        grouped[category].append(m)
    for category in grouped:
        grouped[category].sort(key=lambda x: (x['sort_order'], x['id']))
    return dict(sidebar_menus=grouped)

@admin_bp.route('/')
def index():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = get_admin(username, password)
        if admin:
            session['admin_id'] = admin['id']
            session['admin_name'] = admin['username']
            return redirect(url_for('admin.user_list'))
        else:
            return render_template('admin/login.html', error='用户名或密码错误')
    return render_template('admin/login.html')

@admin_bp.route('/logout')
def logout():
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    return redirect(url_for('admin.login'))

@admin_bp.route('/users')
def user_list():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    page = request.args.get('page', 1, type=int)
    query = request.args.get('q', '').strip()
    
    per_page = 20
    total_users = count_users(query)
    total_pages = math.ceil(total_users / per_page)
    offset = (page - 1) * per_page
    
    users = get_all_users(limit=per_page, offset=offset, query=query)
    
    return render_template('admin/user_list.html', users=users, page=page, total_pages=total_pages, total_users=total_users, query=query)

@admin_bp.route('/users/batch/delete', methods=['POST'])
def batch_delete():
    if not session.get('admin_id'):
        return json.dumps({'code': 401, 'msg': 'Unauthorized'})
    
    try:
        data = request.get_json()
        ids = data.get('ids', [])
        if ids:
            # Get usernames before deleting for notification
            users_to_notify = []
            for uid in ids:
                u = get_user_by_id(uid)
                if u:
                    if u['is_ai']:
                        return json.dumps({'code': 403, 'msg': f'用户 {u["username"]} 是AI用户，禁止删除'})
                    users_to_notify.append(u['username'])
            
            batch_delete_users(ids)
            
            # Notify connected clients
            if hasattr(current_app, 'handle_admin_event'):
                for username in users_to_notify:
                    current_app.handle_admin_event('delete', username)
            
            return json.dumps({'code': 0, 'msg': '删除成功'})
        return json.dumps({'code': 1, 'msg': '未选择用户'})
    except Exception as e:
        msg = str(e)
        lower = msg.lower()
        friendly = msg
        if "model does not exist" in lower:
            friendly = "模型服务返回：模型不存在，请检查模型标识是否填写正确，例如 deepseek-ai/DeepSeek-V3 或 Qwen/Qwen2.5-7B-Instruct。"
        return json.dumps({'code': 500, 'msg': friendly})

@admin_bp.route('/users/batch/ban', methods=['POST'])
def batch_ban():
    if not session.get('admin_id'):
        return json.dumps({'code': 401, 'msg': 'Unauthorized'})
    
    try:
        data = request.get_json()
        ids = data.get('ids', [])
        is_banned = data.get('is_banned', 1)
        if ids:
            # Get usernames for notification
            users_to_notify = []
            for uid in ids:
                u = get_user_by_id(uid)
                if u:
                    if u['is_ai']:
                        return json.dumps({'code': 403, 'msg': f'用户 {u["username"]} 是AI用户，禁止操作'})
                    users_to_notify.append(u['username'])

            batch_set_user_ban_status(ids, is_banned)
            
            # Notify connected clients if banning
            if is_banned and hasattr(current_app, 'handle_admin_event'):
                for username in users_to_notify:
                    current_app.handle_admin_event('ban', username)
            
            return json.dumps({'code': 0, 'msg': '操作成功'})
        return json.dumps({'code': 1, 'msg': '未选择用户'})
    except Exception as e:
        return json.dumps({'code': 500, 'msg': str(e)})

@admin_bp.route('/interfaces')
def interface_list():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    total_interfaces = count_interfaces()
    total_pages = math.ceil(total_interfaces / per_page)
    offset = (page - 1) * per_page
    
    interfaces = get_all_interfaces(limit=per_page, offset=offset)
    
    return render_template('admin/interface_list.html', interfaces=interfaces, page=page, total_pages=total_pages, total_interfaces=total_interfaces)

@admin_bp.route('/interfaces/add', methods=['GET', 'POST'])
def interface_add():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        command = request.form.get('command')
        url = request.form.get('url')
        token = request.form.get('token')
        is_active = 1 if request.form.get('is_active') == 'on' else 0
        
        if not name or not command or not url:
            flash('请填写完整信息')
            return render_template('admin/interface_form.html')
            
        if add_interface(name, command, url, token, is_active):
            flash('添加成功')
            return redirect(url_for('admin.interface_list'))
        else:
            flash('添加失败，可能是指令已存在')
            
    return render_template('admin/interface_form.html')

@admin_bp.route('/interfaces/edit/<int:interface_id>', methods=['GET', 'POST'])
def interface_edit(interface_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
        
    interface = get_interface_by_id(interface_id)
    if not interface:
        flash('接口不存在')
        return redirect(url_for('admin.interface_list'))
        
    if request.method == 'POST':
        name = request.form.get('name')
        command = request.form.get('command')
        url = request.form.get('url')
        token = request.form.get('token')
        is_active = 1 if request.form.get('is_active') == 'on' else 0
        
        if not name or not command or not url:
            flash('请填写完整信息')
            return render_template('admin/interface_form.html', interface=interface)
            
        if update_interface(interface_id, name, command, url, token, is_active):
            flash('修改成功')
            return redirect(url_for('admin.interface_list'))
        else:
            flash('修改失败，可能是指令已存在')
            
    return render_template('admin/interface_form.html', interface=interface)

@admin_bp.route('/interfaces/delete', methods=['POST'])
def interface_delete():
    if not session.get('admin_id'):
        return json.dumps({'code': 401, 'msg': 'Unauthorized'})
        
    interface_id = request.form.get('id')
    delete_interface(interface_id)
    return json.dumps({'code': 0, 'msg': '删除成功'})

@admin_bp.route('/interfaces/toggle_status', methods=['POST'])
def interface_toggle_status():
    if not session.get('admin_id'):
        return json.dumps({'code': 401, 'msg': 'Unauthorized'})
        
    interface_id = request.form.get('id')
    toggle_interface_status(interface_id)
    return json.dumps({'code': 0, 'msg': '操作成功'})

@admin_bp.route('/users/view/<int:user_id>')
def user_view(user_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    user = get_user_by_id(user_id)
    if not user:
        flash('用户不存在')
        return redirect(url_for('admin.user_list'))
    
    return render_template('admin/user_view.html', user=user)

@admin_bp.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
def user_edit(user_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    user = get_user_by_id(user_id)
    if not user:
        flash('用户不存在')
        return redirect(url_for('admin.user_list'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        password_hash = None
        if password:
            password_hash = generate_password_hash(password)
            
        update_user_by_admin(user_id, username, password_hash)
        
        # If critical info changed, kick user
        if hasattr(current_app, 'handle_admin_event'):
            # Kick the user if their username changed or password changed
            # Note: 'user' variable holds OLD data here? No, 'user' is fetched before update.
            # Wait, update_user_by_admin updates the DB. 'user' variable still has old data?
            # get_user_by_id returns a Row object (sqlite3.Row) which acts like a dict.
            # It's a snapshot.
            
            should_kick = False
            if user['username'] != username:
                should_kick = True
                # If username changed, we should target the OLD username to kick the connection
                current_app.handle_admin_event('kick', user['username'])
            
            if password: # Password changed
                 should_kick = True
                 # If username also changed, we already kicked above.
                 # If only password changed, kick via (new) username? 
                 # If username didn't change, new username == old username.
                 if user['username'] == username:
                     current_app.handle_admin_event('kick', username)

        flash('修改成功')
        return redirect(url_for('admin.user_list'))
        
    return render_template('admin/user_edit.html', user=user)

@admin_bp.route('/users/delete/<int:user_id>')
def user_delete(user_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    user = get_user_by_id(user_id)
    target_username = user['username'] if user else None
    
    if user and user['is_ai']:
        flash('AI用户禁止删除')
        return redirect(url_for('admin.user_list'))

    delete_user(user_id)
    
    if target_username and hasattr(current_app, 'handle_admin_event'):
        current_app.handle_admin_event('delete', target_username)

    flash('删除成功')
    return redirect(url_for('admin.user_list'))

@admin_bp.route('/users/ban/<int:user_id>/<int:status>')
def user_ban(user_id, status):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    user = get_user_by_id(user_id)
    target_username = user['username'] if user else None
    
    if user and user['is_ai']:
        flash('AI用户禁止封禁/解封')
        return redirect(url_for('admin.user_list'))

    set_user_ban_status(user_id, status)
    
    if status == 1 and target_username and hasattr(current_app, 'handle_admin_event'):
        current_app.handle_admin_event('ban', target_username)

    flash('操作成功')
    return redirect(url_for('admin.user_list'))


# Room Management
@admin_bp.route('/rooms')
def room_list():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 12
    total_rooms = count_rooms()
    total_pages = math.ceil(total_rooms / per_page)
    offset = (page - 1) * per_page
    
    rooms = get_all_rooms_with_stats(limit=per_page, offset=offset)
    
    return render_template('admin/room_list.html', rooms=rooms, page=page, total_pages=total_pages, total_rooms=total_rooms)

@admin_bp.route('/rooms/delete/<int:room_id>')
def room_delete(room_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    delete_room(room_id)
    flash('删除成功')
    return redirect(url_for('admin.room_list'))

@admin_bp.route('/rooms/ban/<int:room_id>/<int:status>')
def room_ban(room_id, status):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    set_room_ban_status(room_id, status)
    flash('操作成功')
    return redirect(url_for('admin.room_list'))

@admin_bp.route('/rooms/members/<int:room_id>')
def room_members(room_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    room = get_room_by_id(room_id)
    if not room:
        flash('房间不存在')
        return redirect(url_for('admin.room_list'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    total_members = count_room_members(room_id)
    total_pages = math.ceil(total_members / per_page)
    offset = (page - 1) * per_page
    
    members = get_room_members_list(room_id, limit=per_page, offset=offset)
    
    return render_template('admin/room_members.html', room=room, members=members, page=page, total_pages=total_pages, total_members=total_members)


# WS Server Management
@admin_bp.route('/servers')
def server_list():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 12
    total_servers = count_ws_servers()
    total_pages = math.ceil(total_servers / per_page)
    offset = (page - 1) * per_page

    servers = get_all_ws_servers(limit=per_page, offset=offset)
    return render_template('admin/server_list.html', servers=servers, page=page, total_pages=total_pages, total_servers=total_servers)

@admin_bp.route('/servers/add', methods=['GET', 'POST'])
def server_add():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        protocol = request.form.get('protocol')
        host = request.form.get('host')
        port = request.form.get('port')
        path = request.form.get('path')
        is_active = 1 if request.form.get('is_active') == '1' else 0
        
        if not name or not host or not port:
            flash('请填写必要信息')
            return redirect(url_for('admin.server_add'))
            
        try:
            port = int(port)
        except ValueError:
            flash('端口必须是数字')
            return redirect(url_for('admin.server_add'))
            
        add_ws_server(name, host, port, path, protocol, is_active)
        flash('添加成功')
        return redirect(url_for('admin.server_list'))
        
    return render_template('admin/server_form.html', mode='add')

@admin_bp.route('/servers/edit/<int:server_id>', methods=['GET', 'POST'])
def server_edit(server_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    server = get_ws_server_by_id(server_id)
    if not server:
        flash('服务器不存在')
        return redirect(url_for('admin.server_list'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        protocol = request.form.get('protocol')
        host = request.form.get('host')
        port = request.form.get('port')
        path = request.form.get('path')
        is_active = 1 if request.form.get('is_active') == '1' else 0
        
        try:
            port = int(port)
        except ValueError:
            flash('端口必须是数字')
            return redirect(url_for('admin.server_edit', server_id=server_id))
            
        update_ws_server(server_id, name, host, port, path, protocol, is_active)
        flash('修改成功')
        return redirect(url_for('admin.server_list'))
        
    return render_template('admin/server_form.html', mode='edit', server=server)

@admin_bp.route('/servers/delete/<int:server_id>')
def server_delete(server_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    delete_ws_server(server_id)
    flash('删除成功')
    return redirect(url_for('admin.server_list'))


@admin_bp.route('/ai-models')
def ai_model_list():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 6
    total_models = count_ai_models()
    total_pages = math.ceil(total_models / per_page) if per_page else 1
    offset = (page - 1) * per_page
    
    models = get_ai_models(limit=per_page, offset=offset)
    
    return render_template('admin/ai_model_list.html', models=models, page=page, total_pages=total_pages, total_models=total_models)


@admin_bp.route('/ai-models/add', methods=['GET', 'POST'])
def ai_model_add():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        api_base = request.form.get('api_base')
        api_key = request.form.get('api_key')
        model_name = request.form.get('model_name')
        prompt = request.form.get('prompt') or ''
        is_active = 1 if request.form.get('is_active') == '1' else 0
        is_default = 1 if request.form.get('is_default') == '1' else 0
        
        if not name or not api_base or not api_key or not model_name:
            flash('请填写完整信息')
            return redirect(url_for('admin.ai_model_add'))
        
        add_ai_model(name, api_base, api_key, model_name, prompt, is_active, is_default)
        flash('添加成功')
        return redirect(url_for('admin.ai_model_list'))
    
    return render_template('admin/ai_model_form.html', mode='add')


@admin_bp.route('/ai-models/edit/<int:model_id>', methods=['GET', 'POST'])
def ai_model_edit(model_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    model = get_ai_model_by_id(model_id)
    if not model:
        flash('模型不存在')
        return redirect(url_for('admin.ai_model_list'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        api_base = request.form.get('api_base')
        api_key = request.form.get('api_key') or model['api_key']
        model_name = request.form.get('model_name')
        prompt = request.form.get('prompt') or ''
        is_active = 1 if request.form.get('is_active') == '1' else 0
        is_default = 1 if request.form.get('is_default') == '1' else 0
        
        if not name or not api_base or not api_key or not model_name:
            flash('请填写完整信息')
            return redirect(url_for('admin.ai_model_edit', model_id=model_id))
        
        update_ai_model(model_id, name, api_base, api_key, model_name, prompt, is_active, is_default)
        flash('修改成功')
        return redirect(url_for('admin.ai_model_list'))
    
    return render_template('admin/ai_model_form.html', mode='edit', model=model)


@admin_bp.route('/ai-models/delete/<int:model_id>')
def ai_model_delete(model_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    delete_ai_model(model_id)
    flash('删除成功')
    return redirect(url_for('admin.ai_model_list'))


@admin_bp.route('/ai-models/toggle/<int:model_id>/<int:status>')
def ai_model_toggle(model_id, status):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    set_ai_model_active(model_id, status == 1)
    flash('操作成功')
    return redirect(url_for('admin.ai_model_list'))


@admin_bp.route('/ai-models/test_api/<int:model_id>', methods=['POST'])
def ai_model_test_api(model_id):
    if not session.get('admin_id'):
        return json.dumps({'code': 401, 'msg': 'Unauthorized'})
    
    model = get_ai_model_by_id(model_id)
    if not model:
        return json.dumps({'code': 1, 'msg': '模型不存在'})
    
    if OpenAI is None:
        return json.dumps({'code': 2, 'msg': '未安装 openai 库，请先安装后重试'})
    
    try:
        data = request.get_json() or {}
        messages = data.get('messages') or []
        prompt_text = data.get('prompt') or ''
        
        msgs = []
        prompt = model['prompt'] or ''
        if prompt:
            msgs.append({'role': 'system', 'content': prompt})
        
        if messages:
            for m in messages:
                role = m.get('role')
                content = m.get('content')
                if role and content:
                    msgs.append({'role': role, 'content': content})
        elif prompt_text:
            msgs.append({'role': 'user', 'content': prompt_text})
        
        if not msgs:
            return json.dumps({'code': 3, 'msg': '请输入内容'})
        
        client = OpenAI(
            api_key=model['api_key'],
            base_url=model['api_base'],
            timeout=10.0
        )
        
        start = time.time()
        resp = client.chat.completions.create(
            model=model['model_name'],
            messages=msgs,
        )
        end = time.time()
        
        latency_ms = int((end - start) * 1000)
        
        reply = ''
        if getattr(resp, 'choices', None):
            first_choice = resp.choices[0]
            message = getattr(first_choice, 'message', None)
            if message:
                reply = getattr(message, 'content', '') or ''
        
        usage = getattr(resp, 'usage', None)
        prompt_tokens = 0
        completion_tokens = 0
        total_tokens = 0
        if usage:
            try:
                prompt_tokens = int(getattr(usage, 'prompt_tokens', 0) or 0)
                completion_tokens = int(getattr(usage, 'completion_tokens', 0) or 0)
                total_tokens = int(getattr(usage, 'total_tokens', 0) or 0)
            except Exception:
                prompt_tokens = 0
                completion_tokens = 0
                total_tokens = 0
        
        try:
            update_ai_model_usage(model_id, prompt_tokens, completion_tokens, total_tokens, latency_ms)
        except Exception:
            pass
        
        return json.dumps(
            {
                'code': 0,
                'msg': 'ok',
                'data': {
                    'reply': reply,
                    'latency_ms': latency_ms,
                    'usage': {
                        'prompt_tokens': prompt_tokens,
                        'completion_tokens': completion_tokens,
                        'total_tokens': total_tokens,
                    },
                },
            }
        )
    except Exception as e:
        return json.dumps({'code': 500, 'msg': str(e)})


@admin_bp.route('/ai-analysis')
def ai_analysis():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    active_models = get_all_active_ai_models()
    return render_template('admin/ai_analysis.html', models=active_models)


@admin_bp.route('/ai-analysis/chat', methods=['POST'])
def ai_analysis_chat():
    if not session.get('admin_id'):
        return Response(json.dumps({'error': 'Unauthorized'}), mimetype='text/event-stream')

    data = request.get_json()
    user_message = data.get('message')
    model_id = data.get('model_id')
    
    model_config = None
    if model_id:
        model_config = get_ai_model_by_id(model_id)
        if model_config and not model_config['is_active']:
            model_config = None
            
    if not model_config:
        model_config = get_default_ai_model()
        
    if not model_config:
        def generate_error():
            yield f"data: {json.dumps({'error': '未找到活跃的AI模型，请先在AI模型管理中配置并激活模型。'})}\n\n"
        return Response(stream_with_context(generate_error()), mimetype='text/event-stream')

    if OpenAI is None:
        def generate_error():
            yield f"data: {json.dumps({'error': '服务器未安装openai库，请联系管理员。'})}\n\n"
        return Response(stream_with_context(generate_error()), mimetype='text/event-stream')

    client = OpenAI(
        api_key=model_config['api_key'],
        base_url=model_config['api_base'],
        timeout=30.0
    )

    tools = [
        {
            "type": "function",
            "function": {
                "name": "get_user_stats",
                "description": "获取用户相关的统计信息，包括总用户数、封禁用户数、AI用户数以及每日新增用户趋势。",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_room_stats",
                "description": "获取聊天室（群聊）相关的统计信息，包括总房间数、封禁房间数、私密房间数、成员最多的房间列表以及消息最多的房间列表。",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_message_stats",
                "description": "获取消息相关的统计信息，包括总消息数以及每日消息数量趋势。",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_room_member_stats",
                "description": "获取各个房间的成员数量分布情况。",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            }
        }
    ]

    messages = [
        {
            "role": "system",
            "content": model_config["prompt"]
            or "你是一个智能数据分析助手，需要基于真实数据库统计结果生成专业的数据分析报告。"
            "当用户的问题与用户、房间、消息等统计相关时，必须优先通过提供的工具函数获取数据，严禁凭空编造任何统计数字。"
            "在工具返回结果后，你要先认真阅读和理解，再用清晰的Markdown结构（标题、列表、表格）进行分析、对比和总结，并给出结论和可执行建议。",
        },
        {"role": "user", "content": user_message},
    ]

    def generate():
        try:
            yield f"data: {json.dumps({'type': 'status', 'step': 1, 'status': '正在分析你的问题…'})}\n\n"

            completion = client.chat.completions.create(
                model=model_config['model_name'],
                messages=messages,
                tools=tools,
                tool_choice="auto",
                stream=False
            )
            
            msg = completion.choices[0].message
            tool_calls = msg.tool_calls

            if tool_calls:
                yield f"data: {json.dumps({'type': 'status', 'step': 2, 'status': '已确定需要检索的数据，正在调用统计工具…'})}\n\n"

                messages.append(msg)
                
                for tool_call in tool_calls:
                    function_name = tool_call.function.name
                    
                    result_content = ""
                    if function_name == "get_user_stats":
                        yield f"data: {json.dumps({'type': 'status', 'step': 2, 'status': '正在获取用户相关统计数据…'})}\n\n"
                        try:
                            result_content = json.dumps(get_user_stats_for_ai(), ensure_ascii=False)
                        except Exception as e:
                            result_content = json.dumps({'error': f'get_user_stats_failed: {str(e)}'}, ensure_ascii=False)
                    elif function_name == "get_room_stats":
                        yield f"data: {json.dumps({'type': 'status', 'step': 2, 'status': '正在获取群聊房间相关统计数据…'})}\n\n"
                        try:
                            result_content = json.dumps(get_room_stats_for_ai(), ensure_ascii=False)
                        except Exception as e:
                            result_content = json.dumps({'error': f'get_room_stats_failed: {str(e)}'}, ensure_ascii=False)
                    elif function_name == "get_message_stats":
                        yield f"data: {json.dumps({'type': 'status', 'step': 2, 'status': '正在获取消息数量与趋势相关统计数据…'})}\n\n"
                        try:
                            result_content = json.dumps(get_message_stats_for_ai(), ensure_ascii=False)
                        except Exception as e:
                            result_content = json.dumps({'error': f'get_message_stats_failed: {str(e)}'}, ensure_ascii=False)
                    elif function_name == "get_room_member_stats":
                        yield f"data: {json.dumps({'type': 'status', 'step': 2, 'status': '正在获取房间成员分布相关统计数据…'})}\n\n"
                        try:
                            result_content = json.dumps(get_room_member_stats_for_ai(), ensure_ascii=False)
                        except Exception as e:
                            result_content = json.dumps({'error': f'get_room_member_stats_failed: {str(e)}'}, ensure_ascii=False)
                    else:
                        result_content = json.dumps({"error": "Unknown function"}, ensure_ascii=False)
                    
                    messages.append({
                        "tool_call_id": tool_call.id,
                        "role": "tool",
                        "name": function_name,
                        "content": result_content
                    })

                yield f"data: {json.dumps({'type': 'status', 'step': 3, 'status': '数据检索完成，正在生成分析报告…'})}\n\n"

                stream = client.chat.completions.create(
                    model=model_config['model_name'],
                    messages=messages,
                    stream=True
                )
                
                for chunk in stream:
                    if chunk.choices[0].delta.content:
                        content = chunk.choices[0].delta.content
                        yield f"data: {json.dumps({'type': 'content', 'content': content})}\n\n"
                        
            else:
                yield f"data: {json.dumps({'type': 'status', 'step': 2, 'status': '本次问题无需数据库检索，直接生成分析报告…'})}\n\n"

                if msg.content:
                    yield f"data: {json.dumps({'type': 'content', 'content': msg.content})}\n\n"

            yield f"data: {json.dumps({'type': 'status', 'step': 4, 'status': '报告已生成完成。'})}\n\n"
            yield "data: [DONE]\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')


@admin_bp.route('/ai-employees')
def ai_employee_list():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    page = request.args.get('page', 1, type=int)
    per_page = 20
    total = count_ai_employees()
    total_pages = math.ceil(total / per_page) if per_page else 1
    offset = (page - 1) * per_page
    employees = get_ai_employees(limit=per_page, offset=offset)
    return render_template('admin/ai_employee_list.html', employees=employees, page=page, total_pages=total_pages, total=total)


@admin_bp.route('/ai-employees/add', methods=['GET', 'POST'])
def ai_employee_add():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        title = request.form.get('title')
        
        if not username or not password:
            flash('用户名和密码不能为空')
            return render_template('admin/ai_employee_form.html', employee=None)
            
        password_hash = generate_password_hash(password)
        user_id = add_ai_employee(username, password_hash, title)
        
        if not user_id:
            flash('添加失败，用户名可能已存在')
            return render_template('admin/ai_employee_form.html', employee=None)
            
        flash('添加成功')
        return redirect(url_for('admin.ai_employee_list'))
        
    return render_template('admin/ai_employee_form.html', employee=None)


@admin_bp.route('/ai-employees/edit/<int:user_id>', methods=['GET', 'POST'])
def ai_employee_edit(user_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    employee = get_ai_employee_by_id(user_id)
    if not employee:
        flash('数字员工不存在')
        return redirect(url_for('admin.ai_employee_list'))
        
    if request.method == 'POST':
        title = request.form.get('title')
        is_banned = request.form.get('is_banned') == '1'
        
        update_ai_employee(user_id, title, is_banned)
        flash('修改成功')
        return redirect(url_for('admin.ai_employee_list'))
        
    return render_template('admin/ai_employee_form.html', employee=employee)


@admin_bp.route('/ai-employees/delete/<int:user_id>')
def ai_employee_delete(user_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    delete_user(user_id)
    flash('删除成功')
    return redirect(url_for('admin.ai_employee_list'))


@admin_bp.route('/ai-employees/toggle-status/<int:user_id>')
def ai_employee_toggle_status(user_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    
    employee = get_ai_employee_by_id(user_id)
    if employee:
        new_status = not employee['is_banned']
        update_ai_employee(user_id, employee['title'], new_status)
        flash('状态已更新')
    
    return redirect(url_for('admin.ai_employee_list'))


@admin_bp.route('/menus')
def menu_list():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    page = request.args.get('page', 1, type=int)
    per_page = 20
    total_menus = count_admin_menus()
    total_pages = math.ceil(total_menus / per_page) if per_page else 1
    offset = (page - 1) * per_page
    menus = get_admin_menus(limit=per_page, offset=offset)
    return render_template('admin/menu_list.html', menus=menus, page=page, total_pages=total_pages, total_menus=total_menus)


@admin_bp.route('/menus/add', methods=['GET', 'POST'])
def menu_add():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    if request.method == 'POST':
        name = request.form.get('name')
        category = request.form.get('category')
        icon = request.form.get('icon')
        url_value = request.form.get('url')
        sort_order_value = request.form.get('sort_order') or '0'
        is_active = 1 if request.form.get('is_active') == '1' else 0
        if not name or not url_value:
            flash('请填写菜单名称和链接地址')
            return render_template('admin/menu_form.html', menu=None)
        try:
            sort_order = int(sort_order_value)
        except ValueError:
            sort_order = 0
        add_admin_menu(name, category, icon, url_value, sort_order, is_active)
        flash('添加成功')
        return redirect(url_for('admin.menu_list'))
    return render_template('admin/menu_form.html', menu=None)


@admin_bp.route('/menus/edit/<int:menu_id>', methods=['GET', 'POST'])
def menu_edit(menu_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    menu = get_admin_menu_by_id(menu_id)
    if not menu:
        flash('菜单不存在')
        return redirect(url_for('admin.menu_list'))
    if request.method == 'POST':
        name = request.form.get('name')
        category = request.form.get('category')
        icon = request.form.get('icon')
        url_value = request.form.get('url')
        sort_order_value = request.form.get('sort_order') or '0'
        is_active = 1 if request.form.get('is_active') == '1' else 0
        if not name or not url_value:
            flash('请填写菜单名称和链接地址')
            return render_template('admin/menu_form.html', menu=menu)
        try:
            sort_order = int(sort_order_value)
        except ValueError:
            sort_order = 0
        update_admin_menu(menu_id, name, category, icon, url_value, sort_order, is_active)
        flash('修改成功')
        return redirect(url_for('admin.menu_list'))
    return render_template('admin/menu_form.html', menu=menu)


@admin_bp.route('/menus/delete/<int:menu_id>')
def menu_delete(menu_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    delete_admin_menu(menu_id)
    flash('删除成功')
    return redirect(url_for('admin.menu_list'))


@admin_bp.route('/roles')
def role_list():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    page = request.args.get('page', 1, type=int)
    per_page = 20
    total_roles = count_roles()
    total_pages = math.ceil(total_roles / per_page) if per_page else 1
    offset = (page - 1) * per_page
    roles = get_roles(limit=per_page, offset=offset)
    all_menus = get_admin_menus(limit=500, offset=0)
    menu_map = {m['id']: m for m in all_menus}
    role_menu_names = {}
    for r in roles:
        ids = get_role_menu_ids(r['id'])
        names = []
        for mid in ids:
            menu = menu_map.get(mid)
            if menu:
                names.append(menu['name'])
        role_menu_names[r['id']] = names
    return render_template(
        'admin/role_list.html',
        roles=roles,
        page=page,
        total_pages=total_pages,
        total_roles=total_roles,
        role_menu_names=role_menu_names,
    )


@admin_bp.route('/roles/add', methods=['GET', 'POST'])
def role_add():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    menus = get_admin_menus(limit=500, offset=0)
    selected_menu_ids = []
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        menu_ids_raw = request.form.getlist('menu_ids')
        if not name:
            flash('请输入角色名称')
            return render_template('admin/role_form.html', role=None, menus=menus, selected_menu_ids=selected_menu_ids)
        menu_ids = []
        for mid in menu_ids_raw:
            try:
                menu_ids.append(int(mid))
            except ValueError:
                continue
        role_id = add_role(name, description)
        if not role_id:
            flash('添加失败，角色名称可能已存在')
            return render_template('admin/role_form.html', role=None, menus=menus, selected_menu_ids=selected_menu_ids)
        if menu_ids:
            set_role_menus(role_id, menu_ids)
        flash('添加成功')
        return redirect(url_for('admin.role_list'))
    return render_template('admin/role_form.html', role=None, menus=menus, selected_menu_ids=selected_menu_ids)


@admin_bp.route('/roles/edit/<int:role_id>', methods=['GET', 'POST'])
def role_edit(role_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    role = get_role_by_id(role_id)
    if not role:
        flash('角色不存在')
        return redirect(url_for('admin.role_list'))
    menus = get_admin_menus(limit=500, offset=0)
    selected_menu_ids = get_role_menu_ids(role_id)
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        menu_ids_raw = request.form.getlist('menu_ids')
        if not name:
            flash('请输入角色名称')
            return render_template('admin/role_form.html', role=role, menus=menus, selected_menu_ids=selected_menu_ids)
        new_menu_ids = []
        for mid in menu_ids_raw:
            try:
                new_menu_ids.append(int(mid))
            except ValueError:
                continue
        ok = update_role(role_id, name, description)
        if not ok:
            flash('保存失败，角色名称可能已存在')
            return render_template('admin/role_form.html', role=role, menus=menus, selected_menu_ids=selected_menu_ids)
        set_role_menus(role_id, new_menu_ids)
        flash('修改成功')
        return redirect(url_for('admin.role_list'))
    return render_template('admin/role_form.html', role=role, menus=menus, selected_menu_ids=selected_menu_ids)


@admin_bp.route('/roles/delete/<int:role_id>')
def role_delete(role_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    delete_role(role_id)
    flash('删除成功')
    return redirect(url_for('admin.role_list'))


@admin_bp.route('/admins')
def admin_list():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    page = request.args.get('page', 1, type=int)
    per_page = 20
    total_admins = count_admins()
    total_pages = math.ceil(total_admins / per_page) if per_page else 1
    offset = (page - 1) * per_page
    admins = get_admins(limit=per_page, offset=offset)
    roles = get_roles(limit=500, offset=0)
    role_map = {r['id']: r for r in roles}
    admin_roles = {}
    for a in admins:
        ids = get_admin_role_ids(a['id'])
        names = []
        for rid in ids:
            r = role_map.get(rid)
            if r:
                names.append(r['name'])
        admin_roles[a['id']] = names
    return render_template(
        'admin/admin_list.html',
        admins=admins,
        page=page,
        total_pages=total_pages,
        total_admins=total_admins,
        admin_roles=admin_roles,
    )


@admin_bp.route('/admins/add', methods=['GET', 'POST'])
def admin_add():
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    roles = get_roles(limit=500, offset=0)
    selected_role_ids = []
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role_ids_raw = request.form.getlist('role_ids')
        if not username or not password:
            flash('请填写用户名和密码')
            return render_template('admin/admin_form.html', admin=None, roles=roles, selected_role_ids=selected_role_ids)
        role_ids = []
        for rid in role_ids_raw:
            try:
                role_ids.append(int(rid))
            except ValueError:
                continue
        admin_id = create_admin(username, password)
        if not admin_id:
            flash('添加失败，用户名可能已存在')
            return render_template('admin/admin_form.html', admin=None, roles=roles, selected_role_ids=selected_role_ids)
        if role_ids:
            set_admin_roles(admin_id, role_ids)
        flash('添加成功')
        return redirect(url_for('admin.admin_list'))
    return render_template('admin/admin_form.html', admin=None, roles=roles, selected_role_ids=selected_role_ids)


@admin_bp.route('/admins/edit/<int:admin_id>', methods=['GET', 'POST'])
def admin_edit(admin_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    admin = get_admin_by_id(admin_id)
    if not admin:
        flash('管理员不存在')
        return redirect(url_for('admin.admin_list'))
    roles = get_roles(limit=500, offset=0)
    selected_role_ids = get_admin_role_ids(admin_id)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role_ids_raw = request.form.getlist('role_ids')
        if not username:
            flash('请填写用户名')
            return render_template('admin/admin_form.html', admin=admin, roles=roles, selected_role_ids=selected_role_ids)
        if admin['username'] == 'admin' and username != 'admin':
            flash('默认admin账号的用户名不允许修改')
            return render_template('admin/admin_form.html', admin=admin, roles=roles, selected_role_ids=selected_role_ids)
        role_ids = []
        for rid in role_ids_raw:
            try:
                role_ids.append(int(rid))
            except ValueError:
                continue
        ok = update_admin(admin_id, username, password or None)
        if not ok:
            flash('保存失败，用户名可能已存在')
            return render_template('admin/admin_form.html', admin=admin, roles=roles, selected_role_ids=selected_role_ids)
        set_admin_roles(admin_id, role_ids)
        flash('修改成功')
        return redirect(url_for('admin.admin_list'))
    return render_template('admin/admin_form.html', admin=admin, roles=roles, selected_role_ids=selected_role_ids)


@admin_bp.route('/admins/delete/<int:admin_id>')
def admin_delete(admin_id):
    if not session.get('admin_id'):
        return redirect(url_for('admin.login'))
    admin = get_admin_by_id(admin_id)
    if not admin:
        flash('管理员不存在')
        return redirect(url_for('admin.admin_list'))
    if admin['username'] == 'admin':
        flash('默认admin账号不能删除')
        return redirect(url_for('admin.admin_list'))
    delete_admin(admin_id)
    flash('删除成功')
    return redirect(url_for('admin.admin_list'))
