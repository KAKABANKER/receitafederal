const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

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
// ROTA TEMPORÁRIA PARA INICIALIZAR O BANCO
// Acesse no navegador: https://seu-backend.onrender.com/api/init
// ============================================================
app.get('/api/init', async (req, res) => {
    try {
        // Criar tabela de usuários
        await pool.query(`
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                nome VARCHAR(255) NOT NULL DEFAULT 'Usuário',
                email VARCHAR(255) DEFAULT 'nao_informado@email.com',
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
        
        // Criar tabela para logs de acesso
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
        
        // Criar usuário admin (senha: admin123)
        const senhaHash = await bcrypt.hash('admin123', 10);
        
        await pool.query(`
            INSERT INTO usuarios (nome, cpf, email, senha, role)
            VALUES ('Administrador', '00000000000', 'admin@gov.br', $1, 'admin')
            ON CONFLICT (cpf) DO NOTHING
        `, [senhaHash]);
        
        res.json({ 
            success: true, 
            message: 'Banco inicializado! Admin: CPF 000.000.000-00, senha: admin123' 
        });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

// ============================================================
// ROTA DE LOGIN
// Recebe CPF + Senha + IP + Dispositivo
// ============================================================
app.post('/api/login', async (req, res) => {
    const { cpf, password, ip, dispositivo, navegador } = req.body;
    const cpfLimpo = cpf.replace(/\D/g, '');
    
    try {
        // Buscar usuário no banco
        const result = await pool.query('SELECT * FROM usuarios WHERE cpf = $1', [cpfLimpo]);
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'CPF ou senha inválidos' });
        }
        
        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.senha);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'CPF ou senha inválidos' });
        }
        
        // Registrar log de acesso com IP e dispositivo
        await pool.query(`
            INSERT INTO logs_acesso (cpf, ip, dispositivo, navegador)
            VALUES ($1, $2, $3, $4)
        `, [cpfLimpo, ip || 'Não coletado', dispositivo || 'Desconhecido', navegador || 'Desconhecido']);
        
        // Atualizar último acesso do usuário
        await pool.query(`
            UPDATE usuarios SET ip = $1, dispositivo = $2, navegador = $3, ultimo_acesso = NOW()
            WHERE cpf = $4
        `, [ip || 'Não coletado', dispositivo || 'Desconhecido', navegador || 'Desconhecido', cpfLimpo]);
        
        // Gerar token JWT
        const token = jwt.sign(
            { id: user.id, cpf: user.cpf, nome: user.nome, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            success: true,
            token,
            user: { 
                id: user.id,
                nome: user.nome, 
                cpf: user.cpf, 
                email: user.email,
                role: user.role 
            }
        });
        
    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ error: 'Erro no servidor' });
    }
});

// ============================================================
// ROTA PARA CADASTRO DE NOVO USUÁRIO
// ============================================================
app.post('/api/register', async (req, res) => {
    const { nome, cpf, email, password } = req.body;
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const cpfLimpo = cpf.replace(/\D/g, '');
        
        await pool.query(
            `INSERT INTO usuarios (nome, cpf, email, senha, role) 
             VALUES ($1, $2, $3, $4, 'user')`,
            [nome, cpfLimpo, email, hashedPassword]
        );
        
        res.json({ success: true, message: 'Usuário cadastrado com sucesso' });
    } catch (error) {
        if (error.code === '23505') {
            res.status(400).json({ error: 'CPF ou e-mail já cadastrado' });
        } else {
            res.status(500).json({ error: 'Erro ao cadastrar usuário' });
        }
    }
});

// ============================================================
// MIDDLEWARE PARA VERIFICAR SE É ADMIN
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
// ROTAS ADMIN (protegidas)
// ============================================================

// Listar todos os usuários
app.get('/api/admin/users', isAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, nome, cpf, email, role, ip, dispositivo, navegador, ultimo_acesso, created_at FROM usuarios ORDER BY id DESC'
        );
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar usuários' });
    }
});

// Listar logs de acesso
app.get('/api/admin/logs', isAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM logs_acesso ORDER BY data_acesso DESC LIMIT 100'
        );
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar logs' });
    }
});

// Estatísticas gerais
app.get('/api/admin/stats', isAdmin, async (req, res) => {
    try {
        const totalUsers = await pool.query('SELECT COUNT(*) FROM usuarios WHERE role = $1', ['user']);
        const totalAdmins = await pool.query('SELECT COUNT(*) FROM usuarios WHERE role = $1', ['admin']);
        const totalLogs = await pool.query('SELECT COUNT(*) FROM logs_acesso');
        const logsHoje = await pool.query(`
            SELECT COUNT(*) FROM logs_acesso 
            WHERE DATE(data_acesso) = CURRENT_DATE
        `);
        
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

// Deletar usuário
app.delete('/api/admin/users/:id', isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM usuarios WHERE id = $1 AND role != $2', [id, 'admin']);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao deletar usuário' });
    }
});

// ============================================================
// ROTA PARA DASHBOARD (informações do usuário logado)
// ============================================================
app.get('/api/user/info', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token não fornecido' });
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const result = await pool.query(
            'SELECT id, nome, cpf, email, role FROM usuarios WHERE id = $1',
            [decoded.id]
        );
        res.json(result.rows[0]);
    } catch (error) {
        res.status(401).json({ error: 'Token inválido' });
    }
});

// ============================================================
// INICIAR SERVIDOR
// ============================================================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
});