document.addEventListener('DOMContentLoaded', function () {
    const sidebar = document.getElementById('sidebar');
    const content = document.getElementById('content');
    const topbar = document.querySelector('.topbar');
    const sidebarToggle = document.getElementById('sidebarToggle');

    // Sidebar Toggle Logic
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', function () {
            sidebar.classList.toggle('collapsed');
            content.classList.toggle('expanded');
            topbar.classList.toggle('expanded');

            // Save state to localStorage
            localStorage.setItem('sidebarCollapsed', sidebar.classList.contains('collapsed'));
        });
    }

    // Restore Sidebar State
    const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
    if (isCollapsed && sidebar) {
        sidebar.classList.add('collapsed');
        content.classList.add('expanded');
        topbar.classList.add('expanded');
    }

    // Chart.js Default Styling
    if (window.Chart) {
        Chart.defaults.color = '#e1e4e8';
        Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.1)';
        Chart.defaults.font.family = "'Inter', sans-serif";
    }

    // Tooltip initialization (standard Bootstrap)
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });

    // --- New Feature Integrations ---

    // 1. Scan Button Logic
    const btnScan = document.getElementById('btnScan');
    if (btnScan) {
        btnScan.addEventListener('click', function () {
            btnScan.disabled = true;
            btnScan.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>SCANNING...';

            fetch('/api/scan', { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    setTimeout(() => {
                        btnScan.disabled = false;
                        btnScan.innerHTML = '<i class="bi bi-lightning-charge-fill me-1 text-warning"></i> SCAN NOW';
                        alert('Scan Completed: ' + data.message);
                        fetchNotifications(); // Refresh notifications
                    }, 2000); // Simulate network delay
                })
                .catch(err => {
                    btnScan.disabled = false;
                    btnScan.innerHTML = '<i class="bi bi-lightning-charge-fill me-1 text-warning"></i> SCAN NOW';
                    console.error('Scan failed:', err);
                });
        });
    }

    // 2. Notification System
    const notifList = document.getElementById('notifList');
    const notifBadge = document.getElementById('notifBadge');
    const markReadBtn = document.getElementById('markRead');

    function fetchNotifications() {
        if (!notifList) return;

        fetch('/api/notifications')
            .then(res => res.json())
            .then(data => {
                if (data.length === 0) {
                    notifList.innerHTML = '<div class="p-4 text-center text-bright small">No new notifications</div>';
                    notifBadge.classList.add('d-none');
                    return;
                }

                let unreadCount = data.filter(n => !n.is_read).length;
                if (unreadCount > 0) {
                    notifBadge.classList.remove('d-none');
                } else {
                    notifBadge.classList.add('d-none');
                }

                notifList.innerHTML = data.map(n => `
                    <div class="px-3 py-2 border-bottom border-secondary border-opacity-25 notification-item ${n.is_read ? '' : 'unread'}">
                        <div class="d-flex gap-2">
                            <i class="bi bi-info-circle text-${n.type || 'info'}"></i>
                            <div>
                                <div class="text-main small fw-bold">${n.message}</div>
                                <div class="text-bright x-small">${n.created_at.substring(11, 19)}</div>
                            </div>
                        </div>
                    </div>
                `).join('');
            });
    }

    if (markReadBtn) {
        markReadBtn.addEventListener('click', function (e) {
            e.preventDefault();
            e.stopPropagation();
            fetch('/api/notifications/read', { method: 'POST' })
                .then(() => fetchNotifications());
        });
    }

    // Initial fetch and poll every 30s
    if (notifList) {
        fetchNotifications();
        setInterval(fetchNotifications, 30000);
    }

    // 3. User Management Logic
    const userModalEl = document.getElementById('userModal');
    let userModal = null;
    if (userModalEl) {
        userModal = bootstrap.Modal.getOrCreateInstance(userModalEl);
    }
    const userForm = document.getElementById('userForm');
    const saveUserBtn = document.getElementById('saveUserBtn');
    const btnAddUser = document.getElementById('btnAddUser');

    if (btnAddUser) {
        btnAddUser.addEventListener('click', () => {
            userForm.reset();
            document.getElementById('userId').value = '';
            document.getElementById('userModalLabel').innerText = 'Add New Analyst';
            document.getElementById('password').required = true;
            document.getElementById('passwordLabel').innerText = 'Password';
            document.getElementById('passwordHint').innerText = '';
            userModal.show();
        });
    }

    if (saveUserBtn) {
        saveUserBtn.addEventListener('click', () => {
            const userId = document.getElementById('userId').value;
            const formData = new FormData(userForm);
            const url = userId ? `/api/users/update/${userId}` : '/api/users/add';

            fetch(url, {
                method: 'POST',
                body: formData
            })
                .then(res => res.json())
                .then(data => {
                    if (data.status === 'success') {
                        alert(data.message);
                        location.reload();
                    } else {
                        alert('Error: ' + data.message);
                    }
                });
        });
    }

    window.editUser = function (id, username, role) {
        if (!userModal) return;
        document.getElementById('userId').value = id;
        document.getElementById('username').value = username;
        document.getElementById('role').value = role;
        document.getElementById('password').required = false;
        document.getElementById('passwordLabel').innerText = 'New Password';
        document.getElementById('passwordHint').innerText = 'Leave blank to keep current';
        document.getElementById('userModalLabel').innerText = 'Edit Analyst';
        userModal.show();
    };

    window.deleteUser = function (id, username) {
        if (confirm(`Are you sure you want to delete user ${username}?`)) {
            fetch(`/api/users/delete/${id}`, { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    if (data.status === 'success') {
                        alert(data.message);
                        location.reload();
                    } else {
                        alert('Error: ' + data.message);
                    }
                });
        }
    };
});
