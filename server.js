const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const db = new sqlite3.Database('college.db');
const secret = 'my_super_secret_key_123';

app.use(bodyParser.json());
app.use(express.static(__dirname));

db.serialize(() => {
    // Таблица пользователей
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )`);

    // Остальные таблицы
    db.run(`CREATE TABLE IF NOT EXISTS teachers (
        id INTEGER PRIMARY KEY,
        name TEXT,
        specialization TEXT,
        max_hours INTEGER,
        current_hours INTEGER DEFAULT 0,
        user_id INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY,
        name TEXT,
        course TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS disciplines (
        id INTEGER PRIMARY KEY,
        name TEXT,
        hours_required INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS assignments (
        id INTEGER PRIMARY KEY,
        teacher_id INTEGER,
        group_id INTEGER,
        discipline_id INTEGER,
        hours INTEGER,
        semester INTEGER DEFAULT 1
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS reserves (
        id INTEGER PRIMARY KEY,
        teacher_id INTEGER,
        discipline_id INTEGER,
        hours INTEGER
    )`);

    const adminUsername = 'admin';
    const adminPassword = '123';  
    const adminRole = 'admin';

    db.get('SELECT * FROM users WHERE username = ?', [adminUsername], async (err, user) => {
        if (!user) {
            const hash = await bcrypt.hash(adminPassword, 10);
            db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', 
                [adminUsername, hash, adminRole], 
                () => console.log('Администратор создан: admin / 123')
            );
        } else {
            console.log('Администратор уже существует');
        }
    });
});
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Токен не предоставлен' });

    jwt.verify(token, secret, (err, user) => {
        if (err) return res.status(403).json({ message: 'Неверный токен' });
        req.user = user;
        next();
    });
}
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.json({ message: 'Неверный логин или пароль' });
        }
        const token = jwt.sign({ id: user.id, role: user.role }, secret, { expiresIn: '1h' });
        res.json({ token, role: user.role, userId: user.id });
    });
});

app.get('/api/teachers', authenticateToken, (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); db.all('SELECT * FROM teachers', (err, rows) => res.json(rows)); });
app.post('/api/teachers', authenticateToken, (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); const { name, specialization, max_hours } = req.body; db.run('INSERT INTO teachers (name, specialization, max_hours, current_hours) VALUES (?, ?, ?, 0)', [name, specialization, max_hours], function() { res.json({ id: this.lastID }); }); });
app.delete('/api/teachers/:id', authenticateToken, (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); db.run('DELETE FROM teachers WHERE id = ?', [req.params.id], () => res.sendStatus(200)); });

app.get('/api/groups', authenticateToken, (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); db.all('SELECT * FROM groups', (err, rows) => res.json(rows)); });
app.post('/api/groups', authenticateToken, (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); const { name, course } = req.body; db.run('INSERT INTO groups (name, course) VALUES (?, ?)', [name, course], function() { res.json({ id: this.lastID }); }); });
app.delete('/api/groups/:id', authenticateToken, (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); db.run('DELETE FROM groups WHERE id = ?', [req.params.id], () => res.sendStatus(200)); });

app.get('/api/disciplines', authenticateToken, (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); db.all('SELECT * FROM disciplines', (err, rows) => res.json(rows)); });
app.post('/api/disciplines', authenticateToken, (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); const { name, hours_required } = req.body; db.run('INSERT INTO disciplines (name, hours_required) VALUES (?, ?)', [name, hours_required], function() { res.json({ id: this.lastID }); }); });
app.delete('/api/disciplines/:id', authenticateToken, (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); db.run('DELETE FROM disciplines WHERE id = ?', [req.params.id], () => res.sendStatus(200)); });

app.get('/api/assignments', authenticateToken, (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); db.all('SELECT * FROM assignments', (err, rows) => res.json(rows)); });
app.post('/api/assign', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    const { teacher_id, group_id, discipline_id, hours } = req.body;
    db.get('SELECT current_hours, max_hours FROM teachers WHERE id = ?', [teacher_id], (err, teacher) => {
        if (teacher.current_hours + hours > teacher.max_hours) {
            db.run('INSERT INTO reserves (teacher_id, discipline_id, hours) VALUES (?, ?, ?)', [teacher_id, discipline_id, hours]);
            return res.json({ message: 'В резерв' });
        }
        db.run('INSERT INTO assignments (teacher_id, group_id, discipline_id, hours) VALUES (?, ?, ?, ?)', [teacher_id, group_id, discipline_id, hours], () => {
            db.run('UPDATE teachers SET current_hours = current_hours + ? WHERE id = ?', [hours, teacher_id]);
            res.json({});
        });
    });
});
app.delete('/api/assignments/:id', authenticateToken, (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); db.get('SELECT teacher_id, hours FROM assignments WHERE id = ?', [req.params.id], (err, a) => { db.run('DELETE FROM assignments WHERE id = ?', [req.params.id]); db.run('UPDATE teachers SET current_hours = current_hours - ? WHERE id = ?', [a.hours, a.teacher_id]); res.json({}); }); });

app.get('/api/reserves', authenticateToken, (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); db.all('SELECT * FROM reserves', (err, rows) => res.json(rows)); });
app.post('/api/reserves', authenticateToken, (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); const { teacher_id, discipline_id, hours } = req.body; db.run('INSERT INTO reserves (teacher_id, discipline_id, hours) VALUES (?, ?, ?)', [teacher_id, discipline_id, hours], function() { res.json({ id: this.lastID }); }); });
app.delete('/api/reserves/:id', authenticateToken, (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); db.run('DELETE FROM reserves WHERE id = ?', [req.params.id], () => res.sendStatus(200)); });

app.get('/api/reports/current', authenticateToken, (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); db.all('SELECT * FROM teachers', (err, rows) => res.json(rows)); });
app.get('/api/reports/semester', authenticateToken, (req, res) => { if (req.user.role !== 'admin') return res.sendStatus(403); db.all('SELECT * FROM assignments WHERE semester = ?', [1], (err, rows) => res.json(rows)); });

app.get('/api/my-assignments/:userId', authenticateToken, (req, res) => {
    if (req.user.id != req.params.userId) return res.sendStatus(403);
    db.get('SELECT id FROM teachers WHERE user_id = ?', [req.user.id], (err, teacher) => {
        if (!teacher) return res.json([]);
        db.all('SELECT * FROM assignments WHERE teacher_id = ?', [teacher.id], (err, rows) => res.json(rows));
    });
});

app.listen(3000, () => console.log('Сервер: http://localhost:3000/index.html'));