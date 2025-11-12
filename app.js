let token = localStorage.getItem('token');     // Токен для запросов
let role = localStorage.getItem('role');       // Роль: admin / teacher
let userId = localStorage.getItem('userId');   // ID текущего пользователя

// Сообщения 
window.showMessage = function(msg) {
    const div = document.getElementById('messages');
    div.textContent = msg;
    div.style.display = 'block';
    setTimeout(() => div.style.display = 'none', 5000); // Автоскрытие
};

// Переключение форм 
window.showRegister = function() {
    document.getElementById('auth').classList.add('hidden');
    document.getElementById('register').classList.remove('hidden');
};

window.showLogin = function() {
    document.getElementById('register').classList.add('hidden');
    document.getElementById('auth').classList.remove('hidden');
};
 
window.logout = function() {
    localStorage.clear();
    location.reload();
};


// Вход
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (data.token) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('role', data.role);
        localStorage.setItem('userId', data.userId);
        token = data.token;
        role = data.role;
        userId = data.userId;
        initApp();
    } else {
        showMessage(data.message || 'Ошибка входа');
    }
});

// Регистрация
document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('regUsername').value;
    const password = document.getElementById('regPassword').value;
    const role = document.getElementById('regRole').value;
    const res = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, role })
    });
    const data = await res.json();
    if (data.success) {
        showMessage('Успешно! Войдите.');
        showLogin();
    } else {
        showMessage(data.message || 'Ошибка');
    }
});
//Переключение разделов
window.showSection = function(id) {
    // Скрываем все разделы
    document.querySelectorAll('.section:not(#auth, #register)').forEach(sec => sec.classList.add('hidden'));
    document.getElementById(id).classList.remove('hidden');

    if (role !== 'admin' && id !== 'myLoad') {
        showMessage('Доступ запрещён');
        showSection('myLoad');
        return;
    }
    if (id === 'teachers') loadTeachers();
    if (id === 'groups') loadGroups();
    if (id === 'disciplines') loadDisciplines();
    if (id === 'assignments') loadAssignments();
    if (id === 'reserves') loadReserves();
    if (id === 'myLoad') loadMyAssignments();
    if (id === 'assignments' || id === 'reserves') populateSelects();
};

async function loadTeachers() {
    const res = await fetch('/api/teachers', { headers: { Authorization: `Bearer ${token}` } });
    if (res.status === 401) return logout();
    const data = await res.json();
    const tbody = document.querySelector('#teachersTable tbody');
    tbody.innerHTML = '';
    data.forEach(t => {
        tbody.innerHTML += `<tr>
            <td>${t.id}</td>
            <td>${t.name}</td>
            <td>${t.specialization}</td>
            <td>${t.max_hours}</td>
            <td>${t.current_hours}</td>
            <td><button type="button" onclick="removeTeacher(${t.id})">Удалить</button></td>
        </tr>`;
    });
}
async function loadGroups() {
    const res = await fetch('/api/groups', { headers: { Authorization: `Bearer ${token}` } });
    if (res.status === 401) return logout();
    const data = await res.json();
    const tbody = document.querySelector('#groupsTable tbody');
    tbody.innerHTML = '';
    data.forEach(g => {
        tbody.innerHTML += `<tr>
            <td>${g.id}</td>
            <td>${g.name}</td>
            <td>${g.course}</td>
            <td><button type="button" onclick="removeGroup(${g.id})">Удалить</button></td>
        </tr>`;
    });
}

async function loadDisciplines() {
    const res = await fetch('/api/disciplines', { headers: { Authorization: `Bearer ${token}` } });
    if (res.status === 401) return logout();
    const data = await res.json();
    const tbody = document.querySelector('#disciplinesTable tbody');
    tbody.innerHTML = '';
    data.forEach(d => {
        tbody.innerHTML += `<tr>
            <td>${d.id}</td>
            <td>${d.name}</td>
            <td>${d.hours_required}</td>
            <td><button type="button" onclick="removeDiscipline(${d.id})">Удалить</button></td>
        </tr>`;
    });
}
// Загрузка назначений 
async function loadAssignments() {
    const res = await fetch('/api/assignments', { headers: { Authorization: `Bearer ${token}` } });
    if (res.status === 401) return logout();
    const assignments = await res.json();

    const [teachersRes, groupsRes, disciplinesRes] = await Promise.all([
        fetch('/api/teachers', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/groups', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/disciplines', { headers: { Authorization: `Bearer ${token}` } })
    ]);

    const teachers = await teachersRes.json();
    const groups = await groupsRes.json();
    const disciplines = await disciplinesRes.json();

    const teacherMap = Object.fromEntries(teachers.map(t => [t.id, t.name]));
    const groupMap = Object.fromEntries(groups.map(g => [g.id, g.name]));
    const disciplineMap = Object.fromEntries(disciplines.map(d => [d.id, d.name]));

    const tbody = document.querySelector('#assignmentsTable tbody');
    tbody.innerHTML = '';
    assignments.forEach(a => {
        tbody.innerHTML += `<tr>
            <td>${a.id}</td>
            <td>${teacherMap[a.teacher_id] || '—'}</td>
            <td>${groupMap[a.group_id] || '—'}</td>
            <td>${disciplineMap[a.discipline_id] || '—'}</td>
            <td>${a.hours}</td>
            <td><button type="button" onclick="removeAssignment(${a.id})">Снять</button></td>
        </tr>`;
    });
}

async function loadReserves() {
    const res = await fetch('/api/reserves', { headers: { Authorization: `Bearer ${token}` } });
    if (res.status === 401) return logout();
    const reserves = await res.json();

    const [teachersRes, disciplinesRes] = await Promise.all([
        fetch('/api/teachers', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/disciplines', { headers: { Authorization: `Bearer ${token}` } })
    ]);

    const teachers = await teachersRes.json();
    const disciplines = await disciplinesRes.json();

    const teacherMap = Object.fromEntries(teachers.map(t => [t.id, t.name]));
    const disciplineMap = Object.fromEntries(disciplines.map(d => [d.id, d.name]));

    const tbody = document.querySelector('#reservesTable tbody');
    tbody.innerHTML = '';
    reserves.forEach(r => {
        tbody.innerHTML += `<tr>
            <td>${r.id}</td>
            <td>${teacherMap[r.teacher_id] || '—'}</td>
            <td>${disciplineMap[r.discipline_id] || '—'}</td>
            <td>${r.hours}</td>
            <td><button type="button" onclick="removeReserve(${r.id})">Удалить</button></td>
        </tr>`;
    });
}
//Моя нагрузка (для преподавателя) 
async function loadMyAssignments() {
    const res = await fetch(`/api/my-assignments/${userId}`, { headers: { Authorization: `Bearer ${token}` } });
    if (res.status === 401) return logout();
    const data = await res.json();
    const tbody = document.querySelector('#myAssignmentsTable tbody');
    tbody.innerHTML = '';
    data.forEach(a => {
        tbody.innerHTML += `<tr>
            <td>${a.id}</td>
            <td>${a.group_id}</td>
            <td>${a.discipline_id}</td>
            <td>${a.hours}</td>
        </tr>`;
    });
}

// Заполнение списков
async function populateSelects() {
    const [tRes, gRes, dRes] = await Promise.all([
        fetch('/api/teachers', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/groups', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/disciplines', { headers: { Authorization: `Bearer ${token}` } })
    ]);
    const teachers = await tRes.json();
    const groups = await gRes.json();
    const disciplines = await dRes.json();

    const assignTeacher = document.getElementById('assignTeacher');
    const reserveTeacher = document.getElementById('reserveTeacher');
    assignTeacher.innerHTML = reserveTeacher.innerHTML = teachers.map(t => `<option value="${t.id}">${t.name}</option>`).join('');
    document.getElementById('assignGroup').innerHTML = groups.map(g => `<option value="${g.id}">${g.name}</option>`).join('');
    document.getElementById('assignDiscipline').innerHTML = disciplines.map(d => `<option value="${d.id}">${d.name}</option>`).join('');
    document.getElementById(' RauerveDiscipline').innerHTML = disciplines.map(d => `<option value="${d.id}">${d.name}</option>`).join('');
}
// Добавление преподавателя
document.getElementById('addTeacherForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (role !== 'admin') return showMessage('Нет доступа');
    const name = document.getElementById('teacherName').value;
    const spec = document.getElementById('teacherSpec').value;
    const maxHours = document.getElementById('teacherMaxHours').value;
    await fetch('/api/teachers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name, specialization: spec, max_hours: maxHours, current_hours: 0 })
    });
    loadTeachers();
});

// Добавление группы 
document.getElementById('addGroupForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (role !== 'admin') return showMessage('Нет доступа');
    const name = document.getElementById('groupName').value;
    const course = document.getElementById('groupCourse').value;
    await fetch('/api/groups', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name, course })
    });
    loadGroups();
});

// Добавление дисциплины
document.getElementById('addDisciplineForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (role !== 'admin') return showMessage('Нет доступа');
    const name = document.getElementById('disciplineName').value;
    const hours = document.getElementById('disciplineHours').value;
    await fetch('/api/disciplines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name, hours_required: hours })
    });
    loadDisciplines();
});

// Назначение нагрузки
document.getElementById('assignLoadForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (role !== 'admin') return showMessage('Нет доступа');
    const teacherId = document.getElementById('assignTeacher').value;
    const groupId = document.getElementById('assignGroup').value;
    const disciplineId = document.getElementById('assignDiscipline').value;
    const hours = document.getElementById('assignHours').value;
    const res = await fetch('/api/assign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ teacher_id: teacherId, group_id: groupId, discipline_id: disciplineId, hours })
    });
    const result = await res.json();
    if (result.message) showMessage(result.message);
    if (result.reserveMessage) showMessage(result.reserveMessage);
    loadAssignments();
    loadTeachers();
});

// Добавление в резерв
document.getElementById('addReserveForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (role !== 'admin') return showMessage('Нет доступа');
    const teacherId = document.getElementById('reserveTeacher').value;
    const disciplineId = document.getElementById('reserveDiscipline').value;
    const hours = document.getElementById('reserveHours').value;
    await fetch('/api/reserves', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ teacher_id: teacherId, discipline_id: disciplineId, hours })
    });
    loadReserves();
});

// Удаление
window.removeTeacher = async (id) => { if (role !== 'admin') return; await fetch(`/api/teachers/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } }); loadTeachers(); };
window.removeGroup = async (id) => { if (role !== 'admin') return; await fetch(`/api/groups/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } }); loadGroups(); };
window.removeDiscipline = async (id) => { if (role !== 'admin') return; await fetch(`/api/disciplines/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } }); loadDisciplines(); };
window.removeAssignment = async (id) => { 
    if (role !== 'admin') return; 
    const res = await fetch(`/api/assignments/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } }); 
    const result = await res.json(); 
    if (result.reserveMessage) showMessage(result.reserveMessage); 
    loadAssignments(); 
    loadTeachers(); 
};
window.removeReserve = async (id) => { if (role !== 'admin') return; await fetch(`/api/reserves/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } }); loadReserves(); };

// Отчёты 
window.generateCurrentLoadReport = async () => {
    if (role !== 'admin') return showMessage('Нет доступа');
    const res = await fetch('/api/reports/current', { headers: { Authorization: `Bearer ${token}` } });
    const report = await res.json();
    document.getElementById('reportOutput').innerHTML = '<pre>' + JSON.stringify(report, null, 2) + '</pre>';
};

window.generateSemesterReport = async () => {
    if (role !== 'admin') return showMessage('Нет доступа');
    const res = await fetch('/api/reports/semester?semester=1', { headers: { Authorization: `Bearer ${token}` } });
    const report = await res.json();
    document.getElementById('reportOutput').innerHTML = '<pre>' + JSON.stringify(report, null, 2) + '</pre>';
};

// Инициализация
function initApp() {
    if (token) {
        document.getElementById('auth').classList.add('hidden');
        document.getElementById('register').classList.add('hidden');
        document.getElementById('mainNav').classList.remove('hidden');
        document.getElementById('mainContent').classList.remove('hidden');
        if (role === 'admin') {
            showSection('teachers');
        } else {
            showSection('myLoad');
            loadMyAssignments();
        }
    } else {
        document.getElementById('auth').classList.remove('hidden');
    }
}

initApp(); 