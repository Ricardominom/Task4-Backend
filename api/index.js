require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const db = mysql.createConnection({
    host: 'bhk95na7hbuhfge732zp-mysql.services.clever-cloud.com',
    user: 'urwwjidkpxwmlu7l', 
    password: 'Pianos10', 
    database: 'myapp',
});

app.post('/register', (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    db.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: err.message });
        } 
        res.status(201).json({ id: results.insertId, name, email });
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err || results.length === 0) {
            console.error('Error or User not found:', err);
            return res.status(401).json({ error: 'User not found' });
        }

        const user = results[0];
        if (user.status === 'blocked') return res.status(403).json({ error: 'User block' });
        if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Password invalid' });

        const lastLogin = new Date();

        db.query('UPDATE users SET last_login = ? WHERE id = ?', [lastLogin, user.id], (updateErr) => {
            if (updateErr) {
                return res.status(500).json({ error: updateErr.message });
            }

            const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.json({ token, user: { ...user, last_login: lastLogin } });
        });
    });
});



const authenticate = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(403);
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

app.get('/users', authenticate, (req, res) => {
    db.query('SELECT id, name, email, last_login, registration_time, status FROM users', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.post('/users/block', authenticate, (req, res) => {
    const { userIds } = req.body; 
    db.query('UPDATE users SET status = "blocked" WHERE id IN (?)', [userIds], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.sendStatus(200);
    });
});

app.post('/users/unblock', authenticate, (req, res) => {
    const { userIds } = req.body; 
    db.query('UPDATE users SET status = "active" WHERE id IN (?)', [userIds], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.sendStatus(200);
    });
});

app.delete('/users/:id', authenticate, (req, res) => {
    const { id } = req.params;
    db.query('DELETE FROM users WHERE id = ?', [id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.sendStatus(204);
    });
});

app.listen(5000, () => {
    console.log('Servidor funcionando en http://localhost:5000');
});
