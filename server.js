// server.js - Com PostgreSQL para Render
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'receita_federal_secret_key_2024';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '/')));

// Conexão com PostgreSQL (Render fornece essa variável)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Necessário para Render
});

// Criar tabelas automaticamente
async function initDatabase() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS usuarios (
            id SERIAL PRIMARY KEY,
            nome TEXT NOT NULL,
            cpf TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            ultimo_acesso TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    await pool.query(`
        CREATE TABLE IF NOT EXISTS acessos (
            id SERIAL PRIMARY KEY,
            usuario_id INTEGER REFERENCES usuarios(id),
            nome TEXT,
            cpf TEXT,
            ip TEXT,
            dispositivo TEXT,
            navegador TEXT,
            data TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    await pool.query(`
        CREATE TABLE IF NOT EXISTS logs_acoes (
            id SERIAL PRIMARY KEY,
            usuario_id INTEGER REFERENCES usuarios(id),
            usuario TEXT,
            acao TEXT,
            detalhes TEXT,
            ip TEXT,
            data TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    await pool.query(`
        CREATE TABLE IF NOT EXISTS pendencias (
            id SERIAL PRIMARY KEY,
            cpf TEXT,
            tipo TEXT,
            descricao TEXT,
            valor DECIMAL(10,2),
            data_vencimento DATE,
            status TEXT DEFAULT 'pendente'
        )
    `);
    
    // Inserir usuário admin padrão
    const adminSenha = bcrypt.hashSync('admin123', 8);
    await pool.query(`
        INSERT INTO usuarios (nome, cpf, senha, role) 
        VALUES ('Administrador', '00000000000', $1, 'admin')
        ON CONFLICT (cpf) DO NOTHING
    `, [adminSenha]);
    
    // Inserir usuário demo
    const demoSenha = bcrypt.hashSync('123456', 8);
    await pool.query(`
        INSERT INTO usuarios (nome, cpf, senha, role) 
        VALUES ('BRENO DE JESUS MEDEIROS', '09846518102', $1, 'user')
        ON CONFLICT (cpf) DO NOTHING
    `, [demoSenha]);
    
    // Inserir pendência demo
    await pool.query(`
        INSERT INTO pendencias (cpf, tipo, descricao, valor, data_vencimento) 
        VALUES ('09846518102', 'IPTU', 'Pendência de IPTU do exercício 2024', 1250.00, '2024-12-15')
        ON CONFLICT DO NOTHING
    `);
    
    console.log('✅ Banco de dados PostgreSQL inicializado!');
}

initDatabase();

// Middleware de autenticação
function autenticarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, error: 'Token não fornecido' });
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, error: 'Token inválido' });
        req.user = user;
        next();
    });
}

function verificarAdmin(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).json({ success: false, error: 'Acesso negado' });
    next();
}

// ==================== ROTAS ====================

app.post('/api/login', async (req, res) => {
    const { cpf, password, ip, dispositivo, navegador } = req.body;
    
    if (!cpf || !password) {
        return res.status(400).json({ success: false, error: 'CPF e senha são obrigatórios' });
    }
    
    try {
        const result = await pool.query(`SELECT * FROM usuarios WHERE cpf = $1`, [cpf]);
        const user = result.rows[0];
        
        if (!user) {
            return res.status(401).json({ success: false, error: 'CPF ou senha inválidos' });
        }
        
        const senhaValida = await bcrypt.compare(password, user.senha);
        if (!senhaValida) {
            await pool.query(`INSERT INTO logs_acoes (usuario_id, usuario, acao, detalhes, ip) VALUES ($1, $2, $3, $4, $5)`,
                [user.id, user.nome, 'TENTATIVA_FALHA_LOGIN', `CPF: ${cpf}`, ip || 'Não registrado']);
            return res.status(401).json({ success: false, error: 'CPF ou senha inválidos' });
        }
        
        await pool.query(`UPDATE usuarios SET ultimo_acesso = NOW() WHERE id = $1`, [user.id]);
        await pool.query(`INSERT INTO acessos (usuario_id, nome, cpf, ip, dispositivo, navegador) VALUES ($1, $2, $3, $4, $5, $6)`,
            [user.id, user.nome, user.cpf, ip || 'Não registrado', dispositivo || 'Desconhecido', navegador || 'Desconhecido']);
        await pool.query(`INSERT INTO logs_acoes (usuario_id, usuario, acao, detalhes, ip) VALUES ($1, $2, $3, $4, $5)`,
            [user.id, user.nome, 'LOGIN_SUCESSO', 'Login realizado com sucesso', ip || 'Não registrado']);
        
        const token = jwt.sign({ id: user.id, nome: user.nome, cpf: user.cpf, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
        
        res.json({ success: true, token, user: { id: user.id, nome: user.nome, cpf: user.cpf, role: user.role } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: 'Erro interno' });
    }
});

app.get('/api/consultar-pendencias', autenticarToken, async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM pendencias WHERE cpf = $1 AND status = 'pendente'`, [req.user.cpf]);
        const pendencias = result.rows;
        
        await pool.query(`INSERT INTO logs_acoes (usuario_id, usuario, acao, detalhes, ip) VALUES ($1, $2, $3, $4, $5)`,
            [req.user.id, req.user.nome, 'CONSULTA_PENDENCIAS', pendencias.length > 0 ? `Encontradas ${pendencias.length} pendências` : 'Nenhuma pendência encontrada', req.ip]);
        
        res.json({
            success: true,
            temPendencia: pendencias.length > 0,
            pendencias,
            mensagem: pendencias.length > 0 
                ? `Foram encontradas ${pendencias.length} pendência(s) registradas.`
                : 'Não existe pendência na Receita Federal e na Procuradoria-Geral da Fazenda Nacional para emitir a certidão.'
        });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Erro ao consultar' });
    }
});

app.get('/api/gerar-certidao', autenticarToken, async (req, res) => {
    await pool.query(`INSERT INTO logs_acoes (usuario_id, usuario, acao, detalhes, ip) VALUES ($1, $2, $3, $4, $5)`,
        [req.user.id, req.user.nome, 'EMISSAO_CERTIDAO', `Certidão emitida`, req.ip]);
    res.json({ success: true, url: '#', mensagem: 'Certidão gerada com sucesso' });
});

app.get('/api/gerar-relatorio', autenticarToken, async (req, res) => {
    await pool.query(`INSERT INTO logs_acoes (usuario_id, usuario, acao, detalhes, ip) VALUES ($1, $2, $3, $4, $5)`,
        [req.user.id, req.user.nome, 'GERAR_RELATORIO', 'Relatório de pendências gerado', req.ip]);
    res.json({ success: true, url: '#', mensagem: 'Relatório gerado' });
});

// ==================== ROTAS ADMIN ====================

app.get('/api/admin/dashboard', autenticarToken, verificarAdmin, async (req, res) => {
    try {
        const totalAcessos = await pool.query(`SELECT COUNT(*) as total FROM acessos`);
        const totalUsuarios = await pool.query(`SELECT COUNT(*) as total FROM usuarios WHERE role = 'user'`);
        const totalPendencias = await pool.query(`SELECT COUNT(*) as total FROM pendencias WHERE status = 'pendente'`);
        const totalCertidoes = await pool.query(`SELECT COUNT(*) as total FROM logs_acoes WHERE acao = 'EMISSAO_CERTIDAO'`);
        const ultimosAcessos = await pool.query(`SELECT a.*, u.nome FROM acessos a LEFT JOIN usuarios u ON a.usuario_id = u.id ORDER BY a.data DESC LIMIT 10`);
        
        res.json({
            success: true,
            totalAcessos: totalAcessos.rows[0]?.total || 0,
            usuariosAtivos: totalUsuarios.rows[0]?.total || 0,
            totalPendencias: totalPendencias.rows[0]?.total || 0,
            totalCertidoes: totalCertidoes.rows[0]?.total || 0,
            ultimosAcessos: ultimosAcessos.rows || []
        });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Erro ao carregar dashboard' });
    }
});

app.get('/api/admin/acessos', autenticarToken, verificarAdmin, async (req, res) => {
    try {
        let query = `SELECT a.*, u.nome FROM acessos a LEFT JOIN usuarios u ON a.usuario_id = u.id WHERE 1=1`;
        const params = [];
        let paramIndex = 1;
        
        if (req.query.cpf) {
            query += ` AND a.cpf LIKE $${paramIndex}`;
            params.push(`%${req.query.cpf}%`);
            paramIndex++;
        }
        if (req.query.data) {
            query += ` AND DATE(a.data) = $${paramIndex}`;
            params.push(req.query.data);
            paramIndex++;
        }
        query += ` ORDER BY a.data DESC LIMIT 500`;
        
        const result = await pool.query(query, params);
        res.json({ success: true, acessos: result.rows || [] });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Erro ao carregar acessos' });
    }
});

app.get('/api/admin/usuarios', autenticarToken, verificarAdmin, async (req, res) => {
    const result = await pool.query(`SELECT id, nome, cpf, role, ultimo_acesso, created_at FROM usuarios ORDER BY id`);
    res.json({ success: true, usuarios: result.rows || [] });
});

app.get('/api/admin/logs', autenticarToken, verificarAdmin, async (req, res) => {
    const result = await pool.query(`SELECT * FROM logs_acoes ORDER BY data DESC LIMIT 500`);
    res.json({ success: true, logs: result.rows || [] });
});

app.post('/api/admin/resetar-senha', autenticarToken, verificarAdmin, async (req, res) => {
    const { userId } = req.body;
    const novaSenha = Math.random().toString(36).slice(-8);
    const senhaHash = bcrypt.hashSync(novaSenha, 8);
    
    await pool.query(`UPDATE usuarios SET senha = $1 WHERE id = $2`, [senhaHash, userId]);
    res.json({ success: true, message: `Senha resetada. Nova senha: ${novaSenha}` });
});

// Servir arquivos estáticos
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/password.html', (req, res) => res.sendFile(path.join(__dirname, 'password.html')));
app.get('/dashboard.html', (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

app.listen(PORT, () => console.log(`🚀 Servidor rodando na porta ${PORT}`));