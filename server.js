
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

function onlyAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin')
    return res.status(403).json({ message: 'Доступ запрещён' });

  next();
}

// Вход в систему
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    async (err, user) => {
      if (err) return res.status(500).json({ message: 'Ошибка сервера' });
      if (!user) return res.status(400).json({ message: 'Неверный логин или пароль' });

      const ok = await bcrypt.compare(password, user.password);
      if (!ok) return res.status(400).json({ message: 'Неверный логин или пароль' });

      // Генерация JWT
      const token = jwt.sign({ id: user.id, role: user.role }, SECRET, { expiresIn: '6h' });

      res.json({ token, role: user.role, userId: user.id });
    }
  );
});

// Регистрация преподавателя
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: 'Неверные данные' });

  try {
    const hash = await bcrypt.hash(password, 10);

    db.run(
      `INSERT INTO users (username, password, role) VALUES (?, ?, ?)`,
      [username, hash, 'teacher'],
      function (err) {
        if (err)
          return res.status(400).json({ message: 'Пользователь уже существует' });

        const userId = this.lastID;

        // Создаём профиль преподавателя
        db.run(
          `INSERT INTO teachers (name, specialization, max_hours, current_hours, user_id)
           VALUES (?, ?, ?, ?, ?)`,
          [username, 'Не указано', 500, 0, userId],
          () => res.json({ message: 'Преподаватель зарегистрирован', userId })
        );
      }
    );
  } catch {
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Профиль текущего пользователя
app.get('/api/profile', authenticateToken, (req, res) => {
  db.get(
    `SELECT id, username, role FROM users WHERE id = ?`,
    [req.user.id],
    (err, row) => res.json(row || {})
  );
});

// Смена пароля
app.post('/api/change-password', authenticateToken, (req, res) => {
  const { oldPassword, newPassword } = req.body;

  db.get(`SELECT * FROM users WHERE id = ?`, [req.user.id], async (err, user) => {
    const ok = await bcrypt.compare(oldPassword, user.password);
    if (!ok) return res.status(400).json({ message: 'Старый пароль неверный' });

    const hash = await bcrypt.hash(newPassword, 10);

    db.run(
      `UPDATE users SET password = ? WHERE id = ?`,
      [hash, req.user.id],
      () => res.json({ message: 'Пароль обновлён' })
    );
  });
});




// Преподавателя(только для админа)
app.get('/api/teachers', authenticateToken, onlyAdmin, (req, res) => {
  db.all(`SELECT * FROM teachers`, (err, rows) => res.json(rows || []));
});

app.post('/api/teachers', authenticateToken, onlyAdmin, (req, res) => {
  const { name, specialization, max_hours } = req.body;

  db.run(
    `INSERT INTO teachers (name, specialization, max_hours, current_hours)
     VALUES (?, ?, ?, 0)`,
    [name, specialization, max_hours],
    function () {
      res.json({ id: this.lastID });
    }
  );
});

app.put('/api/teachers/:id', authenticateToken, onlyAdmin, (req, res) => {
  const { name, specialization, max_hours } = req.body;

  db.run(
    `UPDATE teachers SET name = ?, specialization = ?, max_hours = ? WHERE id = ?`,
    [name, specialization, max_hours, req.params.id],
    () => res.json({})
  );
});

app.delete('/api/teachers/:id', authenticateToken, onlyAdmin, (req, res) => {
  db.run(`DELETE FROM teachers WHERE id = ?`, [req.params.id], () => res.json({}));
});


//Группы
app.get('/api/groups', authenticateToken, onlyAdmin, (req, res) => {
  db.all(`SELECT * FROM groups`, (err, rows) => res.json(rows || []));
});

app.post('/api/groups', authenticateToken, onlyAdmin, (req, res) => {
  const { name, course } = req.body;

  db.run(
    `INSERT INTO groups (name, course) VALUES (?, ?)`,
    [name, course],
    function () {
      res.json({ id: this.lastID });
    }
  );
});

app.put('/api/groups/:id', authenticateToken, onlyAdmin, (req, res) => {
  const { name, course } = req.body;

  db.run(
    `UPDATE groups SET name = ?, course = ? WHERE id = ?`,
    [name, course, req.params.id],
    () => res.json({})
  );
});

app.delete('/api/groups/:id', authenticateToken, onlyAdmin, (req, res) => {
  db.run(`DELETE FROM groups WHERE id = ?`, [req.params.id], () => res.json({}));
});


// Дисциплины
app.get('/api/disciplines', authenticateToken, onlyAdmin, (req, res) => {
  db.all(`SELECT * FROM disciplines`, (err, rows) => res.json(rows || []));
});

app.post('/api/disciplines', authenticateToken, onlyAdmin, (req, res) => {
  const { name, hours_required } = req.body;

  db.run(
    `INSERT INTO disciplines (name, hours_required) VALUES (?, ?)`,
    [name, hours_required],
    function () {
      res.json({ id: this.lastID });
    }
  );
});

app.put('/api/disciplines/:id', authenticateToken, onlyAdmin, (req, res) => {
  const { name, hours_required } = req.body;

  db.run(
    `UPDATE disciplines SET name = ?, hours_required = ? WHERE id = ?`,
    [name, hours_required, req.params.id],
    () => res.json({})
  );
});

app.delete('/api/disciplines/:id', authenticateToken, onlyAdmin, (req, res) => {
  db.run(
    `DELETE FROM disciplines WHERE id = ?`,
    [req.params.id],
    () => res.json({})
  );
});


//  Нагрузка+резерв
// Получение всех назначений
app.get('/api/assignments', authenticateToken, onlyAdmin, (req, res) => {
  db.all(`SELECT * FROM assignments`, (err, rows) => res.json(rows || []));
});

// Логика назначения нагрузки
app.post('/api/assign', authenticateToken, onlyAdmin, (req, res) => {
  const { teacher_id, group_id, discipline_id, hours } = req.body;
  const h = Number(hours);

  // Проверка на корректность
  if (!teacher_id || !group_id || !discipline_id || h <= 0)
    return res.status(400).json({ message: 'Неверные данные' });

  // Находим преподавателя
  db.get(
    `SELECT * FROM teachers WHERE id = ?`,
    [teacher_id],
    (err, t) => {
      if (!t) return res.status(400).json({ message: 'Преподаватель не найден' });

      // Вычисляем доступные часы
      const available = Math.max(0, t.max_hours - t.current_hours);

      let assigned = 0;
      let reserved = 0;

      // 1. Полностью помещаем в расписание
      if (h <= available) {
        assigned = h;

        db.run(
          `INSERT INTO assignments (teacher_id, group_id, discipline_id, hours)
           VALUES (?, ?, ?, ?)`,
          [teacher_id, group_id, discipline_id, h]
        );

        db.run(
          `UPDATE teachers SET current_hours = current_hours + ? WHERE id = ?`,
          [h, teacher_id]
        );
      }

      // 2. Часть в расписание, часть в резерв
      else {
        assigned = available;
        reserved = h - available;

        if (available > 0) {
          db.run(
            `INSERT INTO assignments (teacher_id, group_id, discipline_id, hours)
             VALUES (?, ?, ?, ?)`,
            [teacher_id, group_id, discipline_id, available]
          );

          db.run(
            `UPDATE teachers SET current_hours = current_hours + ? WHERE id = ?`,
            [available, teacher_id]
          );
        }

        // Остаток уходит в резерв
        db.run(
          `INSERT INTO reserves (teacher_id, discipline_id, hours)
           VALUES (?, ?, ?)`,
          [teacher_id, discipline_id, reserved]
        );

        // Создаём уведомление
        db.run(
          `INSERT INTO notifications (message) VALUES (?)`,
          [`Нагрузка превышена у преподавателя id=${teacher_id}. ${reserved} ч. в резерве.`]
        );
      }

      res.json({ assigned, reserved });
    }
  );
});
// Удаление назначения
app.delete('/api/assignments/:id', authenticateToken, onlyAdmin, (req, res) => {
  const id = req.params.id;

  db.get(
    `SELECT * FROM assignments WHERE id = ?`,
    [id],
    (err, a) => {
      if (!a) return res.status(400).json({ message: 'Назначение не найдено' });
      // Возвращаем часы
      db.run(
        `DELETE FROM assignments WHERE id = ?`,
        [id],
        () => {
          db.run(
            `UPDATE teachers SET current_hours = current_hours - ? WHERE id = ?`,
            [a.hours, a.teacher_id],
            () => res.json({})
          );
        }
      );
    }
  );
});

// Резерв
app.get('/api/reserves', authenticateToken, onlyAdmin, (req, res) => {
  db.all(`SELECT * FROM reserves`, (err, rows) => res.json(rows || []));
});

app.delete('/api/reserves/:id', authenticateToken, onlyAdmin, (req, res) => {
  db.run(`DELETE FROM reserves WHERE id = ?`, [req.params.id], () =>
    res.json({})
  );
});