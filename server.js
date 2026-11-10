const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Middleware de seguridad JWT
function autenticarToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ mensaje: 'Acceso denegado' });

  jwt.verify(token.split(' ')[1], process.env.JWT_SECRET, (err, usuario) => {
    if (err) return res.status(403).json({ mensaje: 'Token inválido' });
    req.usuario = usuario;
    next();
  });
}

// 1. Registro de usuario
app.post('/api/registro', async (req, res) => {
  const { nombre, telefono, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO usuarios (nombre, telefono, password_hash) VALUES ($1, $2, $3) RETURNING id, nombre',
      [nombre, telefono, hashedPassword]
    );
    res.json({ mensaje: 'Usuario registrado con éxito', usuario: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'El número ya está registrado o hubo un error' });
  }
});

// 2. Inicio de Sesión
app.post('/api/login', async (req, res) => {
  const { telefono, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE telefono = $1', [telefono]);
    if (result.rows.length === 0) return res.status(400).json({ error: 'Usuario no encontrado' });

    const usuario = result.rows[0];
    const passwordValido = await bcrypt.compare(password, usuario.password_hash);
    if (!passwordValido) return res.status(400).json({ error: 'Contraseña incorrecta' });

    const token = jwt.sign({ id: usuario.id, nombre: usuario.nombre }, process.env.JWT_SECRET);
    res.json({ token, usuario: { id: usuario.id, nombre: usuario.nombre } });
  } catch (err) {
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// 3. Registrar Alerta con GPS
app.post('/api/incidencias', autenticarToken, async (req, res) => {
  const { tipo_incidencia, latitud, longitud, descripcion } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO incidencias (usuario_id, tipo_incidencia, latitud, longitud, descripcion) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.usuario.id, tipo_incidencia, latitud, longitud, descripcion]
    );
    res.json({ mensaje: '¡Alerta emitida con éxito!', incidencia: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Error al guardar la incidencia' });
  }
});

app.listen(process.env.PORT || 3000, () => {
  console.log(`🚀 Servidor listo y corriendo en http://localhost:${process.env.PORT || 3000}`);
});