// ============================================
// ADMIN PANEL - SCRIPT
// ============================================

// Konfigurasi
const ADMIN_API_BASE = '/api/admin';
const ADMIN_TOKEN_STORAGE_KEY = 'robin_admin_token';

// State aplikasi admin
let adminState = {
    token: null,
    users: [],
    filteredUsers: [],
    currentPage: 1,
    pageSize: 10,
    currentTab: 'dashboard',
    searchQuery: '',
    userFilter: 'all'
};

// ============================================
// CORE FUNCTIONS
// ============================================

/**
 * Initialize admin panel
 */
async function initAdminPanel() {
    console.log('Initializing Admin Panel...');
    
    // Check if admin is logged in
    const token = localStorage.getItem(ADMIN_TOKEN_STORAGE_KEY);
    
    if (!token) {
        // Not logged in, show login screen
        showLoginScreen();
        return;
    }
    
    adminState.token = token;
    
    // If on admin page, initialize dashboard
    if (window.location.pathname.includes('admin.html')) {
        await initAdminDashboard();
    }
}

/**
 * Show login screen
 */
function showLoginScreen() {
    const loginSection = document.getElementById('adminLogin');
    const dashboardSection = document.getElementById('adminDashboard');
    
    if (loginSection) loginSection.style.display = 'block';
    if (dashboardSection) dashboardSection.style.display = 'none';
    
    // Add login event listener
    const loginBtn = document.getElementById('adminLoginBtn');
    if (loginBtn) {
        loginBtn.onclick = handleAdminLogin;
    }
    
    // Allow Enter key to login
    const passwordInput = document.getElementById('adminPassword');
    if (passwordInput) {
        passwordInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                handleAdminLogin();
            }
        });
    }
}

/**
 * Initialize admin dashboard
 */
async function initAdminDashboard() {
    console.log('Initializing Admin Dashboard...');
    
    // Show dashboard
    const loginSection = document.getElementById('adminLogin');
    const dashboardSection = document.getElementById('adminDashboard');
    
    if (loginSection) loginSection.style.display = 'none';
    if (dashboardSection) dashboardSection.style.display = 'block';
    
    // Initialize UI
    initAdminUI();
    
    // Load initial data
    await loadDashboardData();
    await loadUsers();
    
    // Setup event listeners
    setupAdminEventListeners();
    
    // Start timers
    startAdminTimers();
    
    // Show dashboard tab
    switchTab('dashboard');
}

/**
 * Initialize admin UI
 */
function initAdminUI() {
    // Update time
    updateAdminTime();
}

/**
 * Setup admin event listeners
 */
function setupAdminEventListeners() {
    // Login button
    const loginBtn = document.getElementById('adminLoginBtn');
    if (loginBtn) {
        loginBtn.addEventListener('click', handleAdminLogin);
    }
    
    // Logout button
    const logoutBtn = document.getElementById('adminLogoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleAdminLogout);
    }
    
    // Refresh button
    const refreshBtn = document.getElementById('refreshDashboard');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            loadDashboardData();
            loadUsers();
            showToast('Dashboard refreshed', 'success');
        });
    }
    
    // Navigation tabs
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.addEventListener('click', function() {
            const tabId = this.getAttribute('data-tab');
            switchTab(tabId);
        });
    });
    
    // User management
    const userSearch = document.getElementById('userSearch');
    if (userSearch) {
        userSearch.addEventListener('input', function() {
            adminState.searchQuery = this.value.toLowerCase();
            filterUsers();
        });
    }
    
    const userFilter = document.getElementById('userFilter');
    if (userFilter) {
        userFilter.addEventListener('change', function() {
            adminState.userFilter = this.value;
            filterUsers();
        });
    }
    
    // Create user form
    const createUserBtn = document.getElementById('createUserBtn');
    if (createUserBtn) {
        createUserBtn.addEventListener('click', createUser);
    }
    
    const generatePasswordBtn = document.getElementById('generatePassword');
    if (generatePasswordBtn) {
        generatePasswordBtn.addEventListener('click', generatePassword);
    }
    
    const resetFormBtn = document.getElementById('resetForm');
    if (resetFormBtn) {
        resetFormBtn.addEventListener('click', resetCreateUserForm);
    }
    
    // System settings
    const saveSettingsBtn = document.getElementById('saveSettings');
    if (saveSettingsBtn) {
        saveSettingsBtn.addEventListener('click', saveSettings);
    }
    
    // Danger zone buttons
    const clearAllSessionsBtn = document.getElementById('clearAllSessions');
    if (clearAllSessionsBtn) {
        clearAllSessionsBtn.addEventListener('click', () => {
            showConfirmModal(
                'Clear All Sessions',
                'Are you sure you want to clear all user sessions? This will log out all users.',
                clearAllSessions
            );
        });
    }
    
    const resetAllPasswordsBtn = document.getElementById('resetAllPasswords');
    if (resetAllPasswordsBtn) {
        resetAllPasswordsBtn.addEventListener('click', () => {
            showConfirmModal(
                'Reset All Passwords',
                'WARNING: This will reset ALL user passwords to default "password123". This action is irreversible!',
                resetAllPasswords
            );
        });
    }
    
    // Pagination
    const usersPrevPageBtn = document.getElementById('usersPrevPage');
    const usersNextPageBtn = document.getElementById('usersNextPage');
    if (usersPrevPageBtn) {
        usersPrevPageBtn.addEventListener('click', () => changeUsersPage(-1));
    }
    if (usersNextPageBtn) {
        usersNextPageBtn.addEventListener('click', () => changeUsersPage(1));
    }
    
    // Toast close
    const toastClose = document.getElementById('toastClose');
    if (toastClose) {
        toastClose.addEventListener('click', hideToast);
    }
    
    // Modal close buttons
    document.querySelectorAll('.modal-close, .btn-modal-cancel').forEach(btn => {
        btn.addEventListener('click', hideModal);
    });
}

/**
 * Start admin timers
 */
function startAdminTimers() {
    // Update time every second
    setInterval(updateAdminTime, 1000);
}

// ============================================
// API FUNCTIONS
// ============================================

/**
 * Make admin API request
 */
async function adminApiRequest(method, endpoint, data = null) {
    const url = endpoint.startsWith('http') ? endpoint : endpoint;
    
    const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminState.token}`
    };
    
    const options = {
        method,
        headers
    };
    
    if (data && (method === 'POST' || method === 'PUT')) {
        options.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(url, options);
        
        // Handle 401 Unauthorized
        if (response.status === 401) {
            showToast('Admin session expired. Please login again.', 'error');
            setTimeout(handleAdminLogout, 2000);
            throw new Error('Unauthorized');
        }
        
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.error || `HTTP ${response.status}`);
        }
        
        return result;
        
    } catch (error) {
        console.error('Admin API request failed:', error);
        throw error;
    }
}

/**
 * Handle admin login
 */
async function handleAdminLogin() {
    const username = document.getElementById('adminUsername')?.value.trim().toLowerCase();
    const password = document.getElementById('adminPassword')?.value;
    
    if (!username || !password) {
        showToast('Please enter username and password', 'warning');
        return;
    }
    
    const loginBtn = document.getElementById('adminLoginBtn');
    const originalText = loginBtn.innerHTML;
    loginBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Logging in...';
    loginBtn.disabled = true;
    
    try {
        const response = await fetch(`${ADMIN_API_BASE}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const result = await response.json();
        
        if (result.success) {
            // Save token
            localStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, result.token);
            adminState.token = result.token;
            
            // Show success message
            showToast('Admin login successful!', 'success');
            
            // Initialize dashboard
            setTimeout(() => {
                initAdminDashboard();
            }, 500);
            
        } else {
            showToast(result.error || 'Login failed', 'error');
        }
        
    } catch (error) {
        showToast(error.message || 'Login failed', 'error');
    } finally {
        loginBtn.innerHTML = originalText;
        loginBtn.disabled = false;
    }
}

/**
 * Handle admin logout
 */
async function handleAdminLogout() {
    try {
        await adminApiRequest('POST', `${ADMIN_API_BASE}/logout`);
    } catch (error) {
        // Ignore errors on logout
    }
    
    // Clear token and redirect
    localStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
    window.location.reload();
}

/**
 * Load dashboard data
 */
async function loadDashboardData() {
    try {
        const response = await adminApiRequest('GET', `${ADMIN_API_BASE}/dashboard`);
        
        if (response.success) {
            updateDashboardUI(response);
        }
        
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        showToast('Failed to load dashboard data', 'error');
    }
}

/**
 * Load users
 */
async function loadUsers() {
    try {
        const response = await adminApiRequest('GET', `${ADMIN_API_BASE}/users`);
        
        if (response.success) {
            adminState.users = response.users;
            filterUsers();
        }
        
    } catch (error) {
        console.error('Error loading users:', error);
        showToast('Failed to load users', 'error');
    }
}

/**
 * Create new user
 */
async function createUser() {
    const username = document.getElementById('newUsername')?.value.trim().toLowerCase();
    const password = document.getElementById('newPassword')?.value;
    const plan = document.getElementById('userPlan')?.value;
    const days = parseInt(document.getElementById('daysDuration')?.value);
    const notes = document.getElementById('notes')?.value.trim();
    
    // Validation
    if (!username || username.length < 3) {
        showToast('Username must be at least 3 characters', 'warning');
        return;
    }
    
    if (!password || password.length < 4) {
        showToast('Password must be at least 4 characters', 'warning');
        return;
    }
    
    if (!days && days !== 0) {
        showToast('Please select a duration', 'warning');
        return;
    }
    
    const createBtn = document.getElementById('createUserBtn');
    const originalText = createBtn.innerHTML;
    createBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating...';
    createBtn.disabled = true;
    
    try {
        const response = await adminApiRequest('POST', `${ADMIN_API_BASE}/create_user`, {
            username,
            password,
            days,
            plan
        });
        
        if (response.success) {
            showToast(`User ${username} created successfully`, 'success');
            
            // Update user preview
            updateUserPreview(response.user);
            
            // Reset form
            resetCreateUserForm();
            
            // Reload users list
            await loadUsers();
            
            // Switch to users tab
            switchTab('users');
        }
        
    } catch (error) {
        showToast(`Failed to create user: ${error.message}`, 'error');
    } finally {
        createBtn.innerHTML = originalText;
        createBtn.disabled = false;
    }
}

/**
 * Delete user
 */
async function deleteUser(username) {
    showConfirmModal(
        'Delete User',
        `Are you sure you want to delete user "${username}"? This action cannot be undone!`,
        async () => {
            try {
                const response = await adminApiRequest('POST', `${ADMIN_API_BASE}/delete_user`, {
                    username
                });
                
                if (response.success) {
                    showToast(`User ${username} deleted successfully`, 'success');
                    await loadUsers();
                }
                
            } catch (error) {
                showToast(`Failed to delete user: ${error.message}`, 'error');
            }
        }
    );
}

/**
 * Renew user subscription
 */
async function renewUser(username, days = 30) {
    const daysInput = prompt(`Enter number of days to add for user "${username}":`, days);
    
    if (!daysInput || isNaN(daysInput) || parseInt(daysInput) <= 0) {
        showToast('Invalid number of days', 'warning');
        return;
    }
    
    const daysToAdd = parseInt(daysInput);
    
    try {
        const response = await adminApiRequest('POST', `${ADMIN_API_BASE}/renew_user`, {
            username,
            days: daysToAdd
        });
        
        if (response.success) {
            showToast(`User ${username} renewed for ${daysToAdd} days`, 'success');
            await loadUsers();
        }
        
    } catch (error) {
        showToast(`Failed to renew user: ${error.message}`, 'error');
    }
}

/**
 * Save system settings
 */
async function saveSettings() {
    const siteTitle = document.getElementById('siteTitle')?.value.trim();
    const globalWebhook = document.getElementById('globalWebhook')?.value.trim();
    const currentPass = document.getElementById('currentAdminPass')?.value;
    const newPass = document.getElementById('newAdminPass')?.value;
    const confirmPass = document.getElementById('confirmAdminPass')?.value;
    
    const data = {};
    
    if (siteTitle) {
        data.site_title = siteTitle;
    }
    
    if (globalWebhook !== undefined) {
        data.webhook_url = globalWebhook;
    }
    
    // Handle password change
    if (newPass) {
        if (newPass !== confirmPass) {
            showToast('New passwords do not match', 'error');
            return;
        }
        
        if (!currentPass) {
            showToast('Please enter current password to change password', 'warning');
            return;
        }
        
        data.admin_password = newPass;
        // Note: In production, you should also send current password for verification
    }
    
    const saveBtn = document.getElementById('saveSettings');
    const originalText = saveBtn.innerHTML;
    saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
    saveBtn.disabled = true;
    
    try {
        const response = await adminApiRequest('POST', `${ADMIN_API_BASE}/update_config`, data);
        
        if (response.success) {
            showToast('Settings saved successfully', 'success');
            
            // Clear password fields
            const currentPassInput = document.getElementById('currentAdminPass');
            const newPassInput = document.getElementById('newAdminPass');
            const confirmPassInput = document.getElementById('confirmAdminPass');
            
            if (currentPassInput) currentPassInput.value = '';
            if (newPassInput) newPassInput.value = '';
            if (confirmPassInput) confirmPassInput.value = '';
        }
        
    } catch (error) {
        showToast(`Failed to save settings: ${error.message}`, 'error');
    } finally {
        saveBtn.innerHTML = originalText;
        saveBtn.disabled = false;
    }
}

/**
 * Clear all sessions
 */
async function clearAllSessions() {
    // This is a placeholder - implement based on your backend
    showToast('All sessions cleared', 'success');
}

/**
 * Reset all passwords
 */
async function resetAllPasswords() {
    // This is a placeholder - implement based on your backend
    showToast('All passwords reset', 'success');
}

// ============================================
// UI UPDATE FUNCTIONS
// ============================================

/**
 * Update dashboard UI
 */
function updateDashboardUI(data) {
    const stats = data.stats;
    const config = data.config;
    
    // Update stats
    const totalUsers = document.getElementById('totalUsers');
    const activeUsers = document.getElementById('activeUsers');
    const expiredUsers = document.getElementById('expiredUsers');
    const todayLogins = document.getElementById('todayLogins');
    
    if (totalUsers) totalUsers.textContent = stats.total_users?.toLocaleString() || '0';
    if (activeUsers) activeUsers.textContent = stats.active_users?.toLocaleString() || '0';
    if (expiredUsers) expiredUsers.textContent = stats.expired_users?.toLocaleString() || '0';
    if (todayLogins) todayLogins.textContent = stats.today_logins?.toLocaleString() || '0';
    
    // Update system info
    const systemVersion = document.getElementById('systemVersion');
    const webhookStatus = document.getElementById('webhookStatus');
    const memoryUsage = document.getElementById('memoryUsage');
    
    if (systemVersion) systemVersion.textContent = data.api_version || 'v2.0';
    if (webhookStatus) webhookStatus.textContent = config.webhook_enabled ? 'Enabled' : 'Disabled';
    if (memoryUsage) memoryUsage.textContent = `${Math.round(stats.memory_usage / 1024)} KB`;
    
    // Update site title in form
    const siteTitleInput = document.getElementById('siteTitle');
    if (siteTitleInput && config.site_title) {
        siteTitleInput.value = config.site_title;
    }
    
    // Update global webhook in form
    const globalWebhookInput = document.getElementById('globalWebhook');
    if (globalWebhookInput && config.webhook_enabled) {
        // Note: You might want to store webhook URL in a secure way
        globalWebhookInput.placeholder = 'Webhook is configured';
    }
}

/**
 * Filter users based on search and filter
 */
function filterUsers() {
    const { searchQuery, userFilter } = adminState;
    
    adminState.filteredUsers = adminState.users.filter(user => {
        // Apply search filter
        if (searchQuery && !user.username.toLowerCase().includes(searchQuery)) {
            return false;
        }
        
        // Apply status filter
        switch (userFilter) {
            case 'active':
                return user.active;
            case 'expired':
                return !user.active;
            case 'premium':
                return user.plan === 'premium' || user.plan === 'ultimate';
            default:
                return true;
        }
    });
    
    updateUsersTable();
}

/**
 * Update users table
 */
function updateUsersTable() {
    const tableBody = document.getElementById('usersTableBody');
    const noUsersMessage = document.getElementById('noUsersMessage');
    const prevPageBtn = document.getElementById('usersPrevPage');
    const nextPageBtn = document.getElementById('usersNextPage');
    const pageInfo = document.getElementById('usersPageInfo');
    
    if (!tableBody || !noUsersMessage) return;
    
    // Show/hide no users message
    if (adminState.filteredUsers.length === 0) {
        tableBody.innerHTML = '';
        noUsersMessage.style.display = 'block';
        if (prevPageBtn) prevPageBtn.style.display = 'none';
        if (nextPageBtn) nextPageBtn.style.display = 'none';
        if (pageInfo) pageInfo.style.display = 'none';
        return;
    }
    
    noUsersMessage.style.display = 'none';
    if (prevPageBtn) prevPageBtn.style.display = 'block';
    if (nextPageBtn) nextPageBtn.style.display = 'block';
    if (pageInfo) pageInfo.style.display = 'block';
    
    // Calculate pagination
    const totalPages = Math.ceil(adminState.filteredUsers.length / adminState.pageSize);
    const startIndex = (adminState.currentPage - 1) * adminState.pageSize;
    const endIndex = Math.min(startIndex + adminState.pageSize, adminState.filteredUsers.length);
    const pageUsers = adminState.filteredUsers.slice(startIndex, endIndex);
    
    // Generate table rows
    let html = '';
    
    pageUsers.forEach(user => {
        const statusBadge = user.active ? 
            '<span class="badge badge-valid">Active</span>' : 
            '<span class="badge badge-invalid">Expired</span>';
        
        const planBadge = user.plan === 'premium' ? 
            '<span class="badge badge-valid">Premium</span>' : 
            (user.plan === 'ultimate' ? 
                '<span class="badge" style="background: rgba(155, 89, 182, 0.2); color: #9b59b6; border: 1px solid rgba(155, 89, 182, 0.3);">Ultimate</span>' : 
                '<span class="badge" style="background: rgba(52, 152, 219, 0.2); color: #3498db; border: 1px solid rgba(52, 152, 219, 0.3);">Basic</span>');
        
        html += `
            <tr>
                <td><strong>${user.username}</strong></td>
                <td>${planBadge}</td>
                <td>${statusBadge}</td>
                <td>${user.created_date}</td>
                <td>${user.expiry_date}</td>
                <td><span style="color: ${user.days_left > 7 ? '#2ecc71' : (user.days_left > 0 ? '#f39c12' : '#e74c3c')}">
                    ${user.days_left > 0 ? `${user.days_left} days` : 'Expired'}
                </span></td>
                <td>${user.last_login_date}</td>
                <td>
                    <div class="user-actions">
                        <button class="btn-action btn-renew" onclick="renewUser('${user.username}')" title="Renew Subscription">
                            <i class="fas fa-calendar-plus"></i>
                        </button>
                        <button class="btn-action btn-edit" onclick="editUser('${user.username}')" title="Edit User">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="btn-action btn-delete" onclick="deleteUser('${user.username}')" title="Delete User">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    });
    
    tableBody.innerHTML = html;
    
    // Update pagination
    if (prevPageBtn) {
        prevPageBtn.disabled = adminState.currentPage <= 1;
    }
    
    if (nextPageBtn) {
        nextPageBtn.disabled = adminState.currentPage >= totalPages;
    }
    
    if (pageInfo) {
        pageInfo.textContent = `Page ${adminState.currentPage} of ${totalPages}`;
    }
}

/**
 * Change users page
 */
function changeUsersPage(delta) {
    const totalPages = Math.ceil(adminState.filteredUsers.length / adminState.pageSize);
    const newPage = adminState.currentPage + delta;
    
    if (newPage >= 1 && newPage <= totalPages) {
        adminState.currentPage = newPage;
        updateUsersTable();
    }
}

/**
 * Switch tab
 */
function switchTab(tabId) {
    // Update active tab
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.classList.remove('active');
        if (tab.getAttribute('data-tab') === tabId) {
            tab.classList.add('active');
        }
    });
    
    // Show/hide tab content
    document.querySelectorAll('.admin-tab').forEach(tab => {
        tab.classList.remove('active');
        if (tab.id === `tab-${tabId}`) {
            tab.classList.add('active');
        }
    });
    
    // Update state
    adminState.currentTab = tabId;
    
    // Load tab-specific data
    switch (tabId) {
        case 'dashboard':
            loadDashboardData();
            break;
        case 'users':
            loadUsers();
            break;
        case 'logs':
            loadLogs();
            break;
    }
}

/**
 * Load logs (placeholder)
 */
async function loadLogs() {
    // This is a placeholder - implement based on your backend
    const logsBody = document.getElementById('logsTableBody');
    if (logsBody) {
        logsBody.innerHTML = `
            <tr>
                <td>${new Date().toLocaleTimeString()}</td>
                <td><span class="badge badge-valid">Login</span></td>
                <td>admin</td>
                <td>Logged into admin panel</td>
                <td>System initialization</td>
                <td>127.0.0.1</td>
            </tr>
        `;
    }
}

/**
 * Update admin time
 */
function updateAdminTime() {
    const adminServerTime = document.getElementById('adminServerTime');
    if (adminServerTime) {
        adminServerTime.textContent = new Date().toLocaleDateString('id-ID', {
            weekday: 'long',
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }
}

/**
 * Generate random password
 */
function generatePassword() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';
    
    for (let i = 0; i < 12; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    const newPasswordInput = document.getElementById('newPassword');
    if (newPasswordInput) {
        newPasswordInput.value = password;
    }
    
    // Show preview
    const usernameInput = document.getElementById('newUsername');
    updateUserPreview({
        username: usernameInput ? usernameInput.value || 'newuser' : 'newuser',
        password: password
    });
}

/**
 * Reset create user form
 */
function resetCreateUserForm() {
    const newUsernameInput = document.getElementById('newUsername');
    const newPasswordInput = document.getElementById('newPassword');
    const userPlanSelect = document.getElementById('userPlan');
    const daysDurationSelect = document.getElementById('daysDuration');
    const notesTextarea = document.getElementById('notes');
    
    if (newUsernameInput) newUsernameInput.value = '';
    if (newPasswordInput) newPasswordInput.value = '';
    if (userPlanSelect) userPlanSelect.value = 'basic';
    if (daysDurationSelect) daysDurationSelect.value = '30';
    if (notesTextarea) notesTextarea.value = '';
    
    // Hide preview
    const preview = document.getElementById('userPreview');
    if (preview) {
        preview.style.display = 'none';
    }
}

/**
 * Update user preview
 */
function updateUserPreview(user) {
    const preview = document.getElementById('userPreview');
    if (!preview) return;
    
    const previewUsername = document.getElementById('previewUsername');
    const previewPassword = document.getElementById('previewPassword');
    const previewPlan = document.getElementById('previewPlan');
    const previewExpiry = document.getElementById('previewExpiry');
    const previewUrl = document.getElementById('previewUrl');
    
    if (previewUsername) previewUsername.textContent = user.username || 'N/A';
    if (previewPassword) previewPassword.textContent = user.password ? '••••••••' : 'N/A';
    if (previewPlan) previewPlan.textContent = user.plan ? user.plan.charAt(0).toUpperCase() + user.plan.slice(1) : 'Basic';
    if (previewExpiry) previewExpiry.textContent = user.expiry_date || 'N/A';
    if (previewUrl) previewUrl.textContent = `${window.location.origin}/index.html`;
    
    preview.style.display = 'block';
}

/**
 * Edit user (placeholder)
 */
function editUser(username) {
    showToast(`Edit user ${username} - Feature coming soon!`, 'info');
}

// ============================================
// MODAL FUNCTIONS
// ============================================

/**
 * Show confirm modal
 */
function showConfirmModal(title, message, onConfirm) {
    const modal = document.getElementById('userActionsModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');
    const confirmBtn = modal.querySelector('.btn-modal-confirm');
    
    if (!modal || !modalTitle || !modalBody) return;
    
    modalTitle.textContent = title;
    modalBody.innerHTML = `<p>${message}</p>`;
    
    // Update confirm button
    confirmBtn.onclick = () => {
        if (onConfirm) onConfirm();
        hideModal();
    };
    
    // Show modal
    modal.classList.add('show');
}

/**
 * Hide modal
 */
function hideModal() {
    const modal = document.getElementById('userActionsModal');
    if (modal) {
        modal.classList.remove('show');
    }
}

// ============================================
// TOAST NOTIFICATION
// ============================================

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    const toastMessage = document.getElementById('toastMessage');
    const toastIcon = document.getElementById('toastIcon');
    
    if (!toast || !toastMessage || !toastIcon) return;
    
    // Set message
    toastMessage.textContent = message;
    
    // Set icon and color based on type
    let icon = 'fa-info-circle';
    
    switch (type) {
        case 'success':
            icon = 'fa-check-circle';
            break;
        case 'error':
            icon = 'fa-times-circle';
            break;
        case 'warning':
            icon = 'fa-exclamation-triangle';
            break;
        case 'info':
            icon = 'fa-info-circle';
            break;
    }
    
    toastIcon.className = `fas ${icon}`;
    
    // Set toast class
    toast.className = 'toast';
    toast.classList.add(type);
    
    // Show toast
    setTimeout(() => {
        toast.classList.add('show');
    }, 10);
    
    // Auto hide after 5 seconds
    setTimeout(() => {
        hideToast();
    }, 5000);
}

/**
 * Hide toast notification
 */
function hideToast() {
    const toast = document.getElementById('toast');
    if (toast) {
        toast.classList.remove('show');
    }
}

// ============================================
// INITIALIZATION
// ============================================

// Initialize admin panel when DOM is loaded
document.addEventListener('DOMContentLoaded', initAdminPanel);

// Global functions untuk dipanggil dari inline onclick
window.renewUser = renewUser;
window.editUser = editUser;
window.deleteUser = deleteUser;