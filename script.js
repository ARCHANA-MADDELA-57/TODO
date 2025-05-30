document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('registerForm');
    const loginForm = document.getElementById('loginForm');
    const addTaskForm = document.getElementById('addTaskForm');
    const taskList = document.getElementById('taskList');
    const logoutButton = document.getElementById('logoutButton');
    const messageElement = document.getElementById('message'); // Used on login/register
    const welcomeMessageElement = document.getElementById('welcomeMessage'); // Used on dashboard

    const backendBaseUrl = 'http://127.0.0.1:5000'; // <<<< ENSURE THIS IS YOUR FLASK SERVER URL

    // --- Helper functions ---
    function showMessage(element, text, isError = true) {
        if (element) { // Check if element exists before manipulating (for different pages)
            element.textContent = text;
            element.style.color = isError ? 'red' : 'green';
        } else {
            console.warn(`Message element not found: ${text}`);
        }
    }

    function clearMessage(element) {
        if (element) {
            element.textContent = '';
        }
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
            // On dashboard, messageElement might be null, so use alert
            if (messageElement) {
                showMessage(messageElement, error.message, true);
            } else {
                alert(`Error: ${error.message}`);
            }
            return null;
        }
    }

    // Simplified JWT Token Parsing (for displaying username)
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

    // --- Registration Form Logic ---
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

    // --- Login Form Logic ---
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

    // --- Dashboard (To-Do List) Logic ---
    if (taskList) { // This block runs only on dashboard.html
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

        // Function to render tasks dynamically
        function renderTasks(tasks) {
            taskList.innerHTML = ''; // Clear existing tasks
            if (tasks.length === 0) {
                taskList.innerHTML = '<p>No tasks yet! Add one above.</p>';
                return;
            }
            tasks.forEach(task => {
                const li = document.createElement('li');
                li.className = `task-item ${task.completed ? 'completed' : ''}`;
                li.dataset.taskId = task.id; // Store task ID for easy access

                li.innerHTML = `
                    <span class="task-description-text">${task.task_description}</span>
                    <input type="text" class="edit-input" value="${task.task_description}">
                    <div class="action-buttons">
                        <button class="edit-button button" data-id="${task.id}">Edit</button>
                        <button class="save-button button" data-id="${task.id}">Save</button>
                        <button class="cancel-button button" data-id="${task.id}">Cancel</button>
                        <button class="complete-button button" data-id="${task.id}" data-completed="${task.completed ? 'true' : 'false'}">
                            ${task.completed ? 'Undo' : 'Complete'}
                        </button>
                        <button class="delete-button button" data-id="${task.id}">Delete</button>
                    </div>
                `;
                taskList.appendChild(li);
            });
        }

        // Add Task - Form Submission
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
                    document.getElementById('newTask').value = ''; // Clear input field
                    fetchTasks(); // Re-fetch and render tasks
                }
            }
        });

        // Event Delegation for Complete, Delete, Edit, Save, Cancel buttons
        taskList.addEventListener('click', async (e) => {
            const target = e.target;
            const taskId = target.dataset.id;
            const listItem = target.closest('.task-item'); // Get the parent <li> element

            if (!listItem || !taskId) return; // Not a task item or missing ID

            // --- Complete/Undo Task ---
            if (target.classList.contains('complete-button')) {
                const currentCompleted = target.dataset.completed === 'true';
                const data = await fetchData(`${backendBaseUrl}/tasks/${taskId}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ completed: !currentCompleted })
                });
                if (data) {
                    fetchTasks();
                }
            }
            // --- Delete Task ---
            else if (target.classList.contains('delete-button')) {
                const data = await fetchData(`${backendBaseUrl}/tasks/${taskId}`, {
                    method: 'DELETE'
                });
                if (data) {
                    fetchTasks();
                }
            }
            // --- Edit Task (start editing mode) ---
            else if (target.classList.contains('edit-button')) {
                listItem.classList.add('editing'); // Add 'editing' class to <li>
                const editInput = listItem.querySelector('.edit-input');
                editInput.focus(); // Focus on the input field
                editInput.setSelectionRange(editInput.value.length, editInput.value.length); // Place cursor at end
            }
            // --- Save Edited Task ---
            else if (target.classList.contains('save-button')) {
                const newDescription = listItem.querySelector('.edit-input').value.trim();
                if (newDescription === '') {
                    alert('Task description cannot be empty!');
                    return;
                }
                const data = await fetchData(`${backendBaseUrl}/tasks/${taskId}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ task_description: newDescription })
                });
                if (data) {
                    listItem.classList.remove('editing'); // Exit editing mode
                    fetchTasks(); // Re-fetch to update UI with new description
                }
            }
            // --- Cancel Editing ---
            else if (target.classList.contains('cancel-button')) {
                listItem.classList.remove('editing'); // Exit editing mode
                // No need to revert input value, fetchTasks will refresh if needed
                fetchTasks(); // Ensure UI consistency
            }
        });

        // Optional: Allow saving on Enter key press in edit mode input
        taskList.addEventListener('keypress', async (e) => {
            if (e.key === 'Enter' && e.target.classList.contains('edit-input')) {
                e.preventDefault(); // Prevent default form submission if input is inside a form
                const listItem = e.target.closest('.task-item');
                const taskId = listItem.dataset.taskId; // Use data-taskId from li
                const newDescription = e.target.value.trim();

                if (newDescription === '') {
                    alert('Task description cannot be empty!');
                    return;
                }

                const data = await fetchData(`${backendBaseUrl}/tasks/${taskId}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ task_description: newDescription })
                });
                if (data) {
                    listItem.classList.remove('editing');
                    fetchTasks();
                }
            }
        });

        // Initial task load when dashboard loads
        fetchTasks();
    }

    // --- Logout Button Logic ---
    if (logoutButton) {
        logoutButton.addEventListener('click', () => {
            localStorage.removeItem('token');
            window.location.href = 'login.html';
        });
    }
});
