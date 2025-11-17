
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const db = new sqlite3.Database('college.db');

const SECRET = 'my_super_secret_key_123';

app.use(express.json());
app.use(express.static(__dirname));

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS teachers (
            id INTEGER PRIMARY KEY,
            name TEXT,
            specialization TEXT,
            max_hours INTEGER,
            current_hours INTEGER DEFAULT 0,
            user_id INTEGER UNIQUE
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY,
            name TEXT,
            course INTEGER
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS disciplines (
            id INTEGER PRIMARY KEY,
            name TEXT,
            hours_required INTEGER
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY,
            teacher_id INTEGER,
            group_id INTEGER,
            discipline_id INTEGER,
            hours INTEGER,
            semester INTEGER DEFAULT 1
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS reserves (
            id INTEGER PRIMARY KEY,
            teacher_id INTEGER,
            discipline_id INTEGER,
            hours INTEGER
        )
    `);

    // Создаём администратора если его нет
    db.get(`SELECT * FROM users WHERE username = 'admin'`, async (err, row) => {
        if (!row) {
            const hash = await bcrypt.hash('123', 10);
            db.run(
                `INSERT INTO users (username, password, role) VALUES (?, ?, ?)`,
                ['admin', hash, 'admin']
            );
            console.log('Администратор создан: admin / 123');
        }
    });
});

function auth(req, res, next) {
    const header = req.headers['authorization'];
    if (!header) return res.status(401).json({ message: 'Нет токена' });

    const token = header.split(' ')[1];
    jwt.verify(token, SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Неверный токен' });
        req.user = user;
        next();
    });
}

function onlyAdmin(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Доступ запрещён' });
    next();
}

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (!user) return res.status(400).json({ message: 'Неверные данные' });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({ message: 'Неверные данные' });

        const token = jwt.sign(
            { id: user.id, role: user.role },
            SECRET,
            { expiresIn: '6h' }
        );

        res.json({
            token,
            role: user.role,
            userId: user.id
        });
    });
});

// Регистрация только преподавателей
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;

    const hash = await bcrypt.hash(password, 10);

    db.run(
        `INSERT INTO users (username, password, role) VALUES (?, ?, ?)`,
        [username, hash, 'teacher'],
        function (err) {
            if (err) return res.status(400).json({ message: 'Пользователь уже существует' });

            // Создаем профиль преподавателя
            db.run(
                `INSERT INTO teachers (name, specialization, max_hours, current_hours, user_id)
                 VALUES (?, ?, ?, ?, ?)`,
                [username, 'Не указано', 720, 0, this.lastID]
            );

            res.json({ message: 'Преподаватель зарегистрирован' });
        }
    );
});

// Профили
app.get('/api/profile', auth, (req, res) => {
    db.get(`SELECT id, username, role FROM users WHERE id = ?`, [req.user.id], (err, user) => {
        res.json(user);
    });
});

app.post('/api/change-password', auth, (req, res) => {
    const { oldPassword, newPassword } = req.body;

    db.get(`SELECT * FROM users WHERE id = ?`, [req.user.id], async (err, user) => {
        const valid = await bcrypt.compare(oldPassword, user.password);

        if (!valid) return res.status(400).json({ message: 'Старый пароль неверный' });

        const hash = await bcrypt.hash(newPassword, 10);

        db.run(
            `UPDATE users SET password = ? WHERE id = ?`,
            [hash, user.id],
            () => res.json({ message: 'Пароль обновлён' })
        );
    });
});

// админ
app.get('/api/teachers', auth, onlyAdmin, (req, res) => {
    db.all(`SELECT * FROM teachers`, (err, rows) => res.json(rows));
});

app.post('/api/teachers', auth, onlyAdmin, (req, res) => {
    const { name, specialization, max_hours } = req.body;

    db.run(
        `INSERT INTO teachers (name, specialization, max_hours, current_hours)
         VALUES (?, ?, ?, ?)`,
        [name, specialization, max_hours, 0],
        function () {
            res.json({ id: this.lastID });
        }
    );
});

