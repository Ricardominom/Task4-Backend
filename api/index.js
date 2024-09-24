require('dotenv').config();
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

// Crear conexión a la base de datos
const db = mysql.createConnection({
    host: 'tu-host', // Cambia esto a la dirección de tu base de datos
    user: 'tu-usuario', // Cambia esto a tu usuario
    password: 'tu-contraseña', // Cambia esto a tu contraseña
    database: 'myapp',
});

// Middleware de CORS
const middleware = (req, res, next) => {
    cors()(req, res, next);
};

// Función handler
module.exports = async (req, res) => {
    middleware(req, res, () => {
        if (req.method === 'POST' && req.url === '/register') {
            const { name, email, password } = req.body;
            const hashedPassword = bcrypt.hashSync(password, 10);
            db.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword], (err, results) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ error: err.message });
                }
                res.status(201).json({ id: results.insertId, name, email });
            });
        } else if (req.method === 'POST' && req.url === '/login') {
            const { email, password } = req.body;
            db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
                if (err || results.length === 0) {
                    console.error('Error or User not found:', err);
                    return res.status(401).json({ error: 'User not found' });
                }

                const user = results[0];
                if (!bcrypt.compareSync(password, user.password)) {
                    return res.status(401).json({ error: 'Password invalid' });
                }

                const lastLogin = new Date();
                db.query('UPDATE users SET last_login = ? WHERE id = ?', [lastLogin, user.id], (updateErr) => {
                    if (updateErr) {
                        return res.status(500).json({ error: updateErr.message });
                    }
                    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
                    res.json({ token, user: { ...user, last_login: lastLogin } });
                });
            });
        } else if (req.method === 'GET' && req.url === '/users') {
            const token = req.headers['authorization'];
            if (!token) return res.sendStatus(403);
            jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
                if (err) return res.sendStatus(403);

                db.query('SELECT id, name, email, last_login, registration_time, status FROM users', (err, results) => {
                    if (err) return res.status(500).json({ error: err.message });
                    res.json(results);
                });
            });
        } else if (req.method === 'POST' && req.url === '/users/block') {
            const { userIds } = req.body;
            const token = req.headers['authorization'];
            jwt.verify(token, process.env.JWT_SECRET, (err) => {
                if (err) return res.sendStatus(403);

                db.query('UPDATE users SET status = "blocked" WHERE id IN (?)', [userIds], (err) => {
                    if (err) return res.status(500).json({ error: err.message });
                    res.sendStatus(200);
                });
            });
        } else if (req.method === 'POST' && req.url === '/users/unblock') {
            const { userIds } = req.body;
            const token = req.headers['authorization'];
            jwt.verify(token, process.env.JWT_SECRET, (err) => {
                if (err) return res.sendStatus(403);

                db.query('UPDATE users SET status = "active" WHERE id IN (?)', [userIds], (err) => {
                    if (err) return res.status(500).json({ error: err.message });
                    res.sendStatus(200);
                });
            });
        } else if (req.method === 'DELETE' && req.url.startsWith('/users/')) {
            const id = req.url.split('/')[2];
            const token = req.headers['authorization'];
            jwt.verify(token, process.env.JWT_SECRET, (err) => {
                if (err) return res.sendStatus(403);

                db.query('DELETE FROM users WHERE id = ?', [id], (err) => {
                    if (err) return res.status(500).json({ error: err.message });
                    res.sendStatus(204);
                });
            });
        } else {
            res.setHeader('Allow', ['POST', 'GET', 'DELETE']);
            res.status(405).end(`Method ${req.method} Not Allowed`);
        }
    });
};
