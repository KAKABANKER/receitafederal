const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Conexão com PostgreSQL no Render
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Rota de login
app.post('/api/login', async (req, res) => {
  const { cpf, password } = req.body;
  
  try {
    const result = await pool.query(
      'SELECT * FROM usuarios WHERE cpf = $1',
      [cpf]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'CPF ou senha inválidos' });
    }
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.senha);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'CPF ou senha inválidos' });
    }
    
    const token = jwt.sign(
      { id: user.id, cpf: user.cpf, nome: user.nome },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    res.json({ 
      success: true, 
      token,
      user: { nome: user.nome, cpf: user.cpf }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

// Rota para criar usuário (cadastro)
app.post('/api/register', async (req, res) => {
  const { nome, cpf, email, password } = req.body;
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    await pool.query(
      'INSERT INTO usuarios (nome, cpf, email, senha) VALUES ($1, $2, $3, $4)',
      [nome, cpf, email, hashedPassword]
    );
    
    res.json({ success: true, message: 'Usuário cadastrado com sucesso' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao cadastrar usuário' });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});