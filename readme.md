# 萱聊 (XuanChat) 项目文档

## 1. 项目基本信息
- **项目名称**: 萱聊 (XuanChat)
- **项目描述**: 一个基于 Web 的实时即时通讯系统，支持多房间群聊、实时消息推送。包含独立的后台业务管理系统，用于用户管理和系统维护。
- **主要功能**:
  - **前台应用**: 
    - 用户注册与登录
    - 多房间实时群聊 (WebSocket)
    - 实时在线用户列表更新
    - 历史消息查看 (最近 10 条)
  - **后台管理系统**: 
    - 管理员登录
    - 用户列表查看 (分页)
    - 用户信息编辑 (修改昵称、重置密码)
    - 用户封禁与解封 (封禁后无法登录和发送消息)
    - 用户删除

## 2. 开发与运行环境
- **开发语言**: Python 3.x
- **运行环境**: 建议使用 Python 虚拟环境 (Virtual Environment) 以隔离依赖。
- **数据库**: SQLite (轻量级文件数据库，无需额外安装服务，数据文件位于 `database/xuanchat.db`)
- **前端框架**: 
  - 前台: Bootstrap, jQuery, FontAwesome
  - 后台: Layui (本地资源位于 `static/lib/layui-v2.13.3`)

## 3. 技术栈与依赖
主要 Python 依赖库 (详见 `requirements.txt`):
- `Flask`: 核心 Web 框架
- `flask-sock`: WebSocket 协议支持，用于实时通讯
- `Werkzeug`: 提供密码哈希与安全校验

## 4. 目录结构说明
```text
chatroom/
├── admin/              # 后台管理系统模块 (Blueprint)
│   ├── templates/      # 后台页面模板 (Layui)
│   ├── __init__.py     # 后台蓝图初始化与配置
│   └── views.py        # 后台视图函数与业务逻辑
├── database/           # 数据库模块
│   ├── db.py           # 数据库连接与 CRUD 操作封装
│   └── xuanchat.db     # SQLite 数据库文件 (自动生成)
├── dist/               # 资源备份目录 (存放 Layui 等组件压缩包)
├── static/             # 静态资源目录
│   ├── css/            # 自定义样式文件
│   ├── lib/            # 第三方库 (Bootstrap, FontAwesome, Layui)
│   ├── mp3/            # 提示音效文件
│   └── js/             # 前端脚本
├── templates/          # 前台页面模板 (Jinja2)
│   ├── chat.html       # 聊天室主页
│   ├── login.html      # 登录页
│   └── register.html   # 注册页
├── app.py              # 应用入口文件 (Main Application)
├── config.json         # 项目配置文件 (端口、Debug模式等)
├── requirements.txt    # Python 依赖清单
└── readme.md           # 项目说明文档
```

## 5. 部署与启动指南

### 5.1 环境准备
1. 确保系统已安装 **Python 3.x**。
2. (可选) 创建并激活虚拟环境：
   ```bash
   # Windows PowerShell
   python -m venv venv
   .\venv\Scripts\activate

   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

### 5.2 安装依赖
在项目根目录下执行：
```bash
pip install -r requirements.txt
```

### 5.3 配置
检查项目根目录下的 `config.json` 文件。如果不存在，系统会使用默认配置。
自定义配置示例：
```json
{
    "server": {
        "host": "0.0.0.0",
        "port": 5000,
        "debug": true
    }
}
```

### 5.4 启动服务
在终端运行：
```bash
python app.py
```
启动成功后，控制台将输出服务监听地址 (默认 `http://127.0.0.1:5000`)。

## 6. 系统访问

### 前台用户端
- **访问地址**: `http://localhost:5000/`
- **测试流程**: 注册一个新账号，登录后即可开始聊天。建议开启两个浏览器窗口模拟不同用户进行对话。

### 后台管理端
- **访问地址**: `http://localhost:5000/admin`
- **默认管理员账号**:
  - **用户名**: `admin`
  - **密码**: `admin888`
- **提示**: 首次启动应用时，系统会自动在数据库中创建该默认管理员账号。

## 7. 运维与维护
- **数据库备份**: 
  - 核心数据存储在 `database/xuanchat.db`。
  - 运维时建议定期备份该文件。
- **用户封禁**: 
  - 如发现违规用户，可登录后台将其状态设置为“封禁”。
  - 封禁用户将立即无法发送 WebSocket 消息，且下次登录时会被拦截。
- **安全性建议**:
  - 生产环境部署时，请在 `app.py` 中修改 `app.secret_key` 为随机强字符串。
  - 修改默认管理员密码。

---
**维护记录**
- 2026-01-17: 完成后台管理系统开发，集成 Layui，新增 `readme.md` 文档。
