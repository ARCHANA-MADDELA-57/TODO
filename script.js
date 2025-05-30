document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('registerForm');
    const loginForm = document.getElementById('loginForm');
    const addTaskForm = document.getElementById('addTaskForm');
    const taskList = document.getElementById('taskList');
    const logoutButton = document.getElementById('logoutButton');
    const messageElement = document.getElementById('message');
    const welcomeMessageElement = document.getElementById('welcomeMessage');

    const backendBaseUrl = 'http://127.0.0.1:5000'; // Replace with your backend URL

    // --- Helper functions ---
    function showMessage(element, text, isError = true) {
        element.textContent = text;
        element.style.color = isError ? 'red' : 'green';
    }

    function clearMessage(element) {
        element.textContent = '';
    }

    async function fetchData(url, options = {}) {
        const token = localStorage.getItem('token');
        if (token) {
            options.headers = {
                ...options.headers,
                'Authorization': `Bearer ${token}`
            };
        }
        try {
            const response = await fetch(url, options);
            if (response.status === 401 || response.status === 403) {
                // Unauthorized or Forbidden - token expired or invalid
                alert('Session expired. Please log in again.');
                localStorage.removeItem('token');
                window.location.href = 'login.html';
                return null;
            }
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.message || 'Something went wrong');
            }
            return data;
        } catch (error) {
            console.error('Fetch error:', error);
            showMessage(messageElement, error.message, true);
            return null;
        }
    }

    // --- Registration ---
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            clearMessage(messageElement);

            const username = registerForm.username.value;
            const email = registerForm.email.value;
            const password = registerForm.password.value;
            const confirmPassword = registerForm.confirmPassword.value;

            if (password !== confirmPassword) {
                showMessage(messageElement, 'Passwords do not match.', true);
                return;
            }

            const data = await fetchData(`${backendBaseUrl}/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, password })
            });

            if (data) {
                showMessage(messageElement, 'Registration successful! Redirecting to login...', false);
                setTimeout(() => {
                    window.location.href = 'login.html';
                }, 2000);
            }
        });
    }

    // --- Login ---
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            clearMessage(messageElement);

            const identifier = loginForm.loginIdentifier.value;
            const password = loginForm.loginPassword.value;

            const data = await fetchData(`${backendBaseUrl}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identifier, password })
            });

            if (data && data.token) {
                localStorage.setItem('token', data.token);
                showMessage(messageElement, 'Login successful! Redirecting to dashboard...', false);
                setTimeout(() => {
                    window.location.href = 'dashboard.html';
                }, 1500);
            } else if (data && data.message) {
                 showMessage(messageElement, data.message, true); // Display error message from backend
            }
        });
    }

    // --- Dashboard (To-Do List) ---
    if (taskList) {
        const token = localStorage.getItem('token');
        if (!token) {
            window.location.href = 'login.html'; // Redirect if not logged in
            return;
        }

        const username = parseJwt(token).username; // Get username from token
        if (welcomeMessageElement) {
            welcomeMessageElement.textContent = `Welcome, ${username}!`;
        }

        async function fetchTasks() {
            const data = await fetchData(`${backendBaseUrl}/tasks`);
            if (data && data.tasks) {
                renderTasks(data.tasks);
            }
        }

        function renderTasks(tasks) {
            taskList.innerHTML = '';
            if (tasks.length === 0) {
                taskList.innerHTML = '<p>No tasks yet! Add one above.</p>';
                return;
            }
            tasks.forEach(task => {
                const li = document.createElement('li');
                li.className = `task-item ${task.completed ? 'completed' : ''}`;
                li.innerHTML = `
                    <span>${task.task_description}</span>
                    <div>
                        <button class="complete-button" data-id="${task.id}" data-completed="${task.completed ? 'true' : 'false'}">
                            ${task.completed ? 'Undo' : 'Complete'}
                        </button>
                        <button class="delete-button" data-id="${task.id}">Delete</button>
                    </div>
                `;
                taskList.appendChild(li);
            });
        }

        // Add Task
        addTaskForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const newTaskDescription = document.getElementById('newTask').value.trim();
            if (newTaskDescription) {
                const data = await fetchData(`${backendBaseUrl}/tasks`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ task_description: newTaskDescription })
                });
                if (data) {
                    document.getElementById('newTask').value = '';
                    fetchTasks();
                }
            }
        });

        // Complete/Delete Task
        taskList.addEventListener('click', async (e) => {
            if (e.target.classList.contains('complete-button')) {
                const taskId = e.target.dataset.id;
                const currentCompleted = e.target.dataset.completed === 'true';
                const data = await fetchData(`${backendBaseUrl}/tasks/${taskId}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ completed: !currentCompleted })
                });
                if (data) {
                    fetchTasks();
                }
            } else if (e.target.classList.contains('delete-button')) {
                const taskId = e.target.dataset.id;
                const data = await fetchData(`${backendBaseUrl}/tasks/${taskId}`, {
                    method: 'DELETE'
                });
                if (data) {
                    fetchTasks();
                }
            }
        });

        // Initial task load
        fetchTasks();
    }

    // --- Logout ---
    if (logoutButton) {
        logoutButton.addEventListener('click', () => {
            localStorage.removeItem('token');
            window.location.href = 'login.html';
        });
    }

    // --- JWT Token Parsing (simplified, for displaying username) ---
    function parseJwt (token) {
        try {
            const base64Url = token.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));

            return JSON.parse(jsonPayload);
        } catch (e) {
            return {}; // Return empty object on error
        }
    };
});