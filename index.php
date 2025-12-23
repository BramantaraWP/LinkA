<?php
/* ====================================
   LINKA - FIXED & STABLE MESSENGER
   ==================================== */

session_start();
date_default_timezone_set('Asia/Jakarta');

// Database connection
try {
    $db = new PDO("sqlite:data.db");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    die("Database connection failed. Please check permissions.");
}

// Create necessary directories
if (!file_exists('uploads')) mkdir('uploads', 0755);
if (!file_exists('uploads/avatars')) mkdir('uploads/avatars', 0755);
if (!file_exists('uploads/files')) mkdir('uploads/files', 0755);

/* === CREATE TABLES === */
$db->exec("
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT,
    bio TEXT DEFAULT 'Hello on LinkA!',
    avatar TEXT DEFAULT 'default.png',
    theme TEXT DEFAULT 'dark',
    notifications INTEGER DEFAULT 1,
    privacy INTEGER DEFAULT 0,
    status TEXT DEFAULT 'offline',
    last_seen INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    message_type TEXT DEFAULT 'text',
    file_name TEXT,
    file_path TEXT,
    file_size INTEGER,
    is_read INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    avatar TEXT DEFAULT 'group.png',
    created_by INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS group_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT DEFAULT 'member',
    joined_at INTEGER NOT NULL,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(group_id, user_id)
);

CREATE TABLE IF NOT EXISTS group_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    message_type TEXT DEFAULT 'text',
    file_name TEXT,
    file_path TEXT,
    file_size INTEGER,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user1_id INTEGER NOT NULL,
    user2_id INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user1_id) REFERENCES users(id),
    FOREIGN KEY (user2_id) REFERENCES users(id),
    UNIQUE(user1_id, user2_id)
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    from_user_id INTEGER,
    group_id INTEGER,
    content TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
");

/* === HELPER FUNCTIONS === */
function sanitize($input) {
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}

function isLoggedIn() {
    return isset($_SESSION['user_id']) && isset($_SESSION['username']);
}

function getCurrentUser() {
    return $_SESSION['user_id'] ?? null;
}

function getUsername() {
    return $_SESSION['username'] ?? null;
}

function generateToken($length = 32) {
    return bin2hex(random_bytes($length));
}

function encryptMessage($message) {
    $key = 'ENIGMAISMOSTSMARTENCRIPTIONINWW2';
    $iv = substr(hash('sha256', $key), 0, 16);
    $encrypted = openssl_encrypt($message, 'AES-256-CBC', $key, 0, $iv);
    return base64_encode($encrypted);
}

function decryptMessage($encrypted) {
    $key = 'ENIGMAISMOSTSMARTENCRIPTIONINWW2';
    $iv = substr(hash('sha256', $key), 0, 16);
    $decrypted = openssl_decrypt(base64_decode($encrypted), 'AES-256-CBC', $key, 0, $iv);
    return $decrypted !== false ? $decrypted : '[Encrypted message]';
}

/* === API HANDLER === */
if (isset($_GET['api'])) {
    header('Content-Type: application/json');
    
    $method = $_SERVER['REQUEST_METHOD'];
    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    
    switch ($_GET['api']) {
        case 'register':
            if ($method !== 'POST') {
                echo json_encode(['error' => 'Method not allowed']);
                break;
            }
            
            $username = sanitize($input['username'] ?? '');
            $password = $input['password'] ?? '';
            $confirm_password = $input['confirm_password'] ?? '';
            $name = sanitize($input['name'] ?? '');
            
            if (empty($username) || empty($password) || empty($confirm_password) || empty($name)) {
                echo json_encode(['error' => 'All fields are required']);
                break;
            }
            
            if ($password !== $confirm_password) {
                echo json_encode(['error' => 'Passwords do not match']);
                break;
            }
            
            if (strlen($password) < 6) {
                echo json_encode(['error' => 'Password must be at least 6 characters']);
                break;
            }
            
            if (strlen($username) < 3) {
                echo json_encode(['error' => 'Username must be at least 3 characters']);
                break;
            }
            
            // Check if username exists
            global $db;
            $stmt = $db->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->execute([$username]);
            
            if ($stmt->fetch()) {
                echo json_encode(['error' => 'Username already exists']);
                break;
            }
            
            // Create user
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $db->prepare("INSERT INTO users (username, password, name, created_at) VALUES (?, ?, ?, ?)");
            $stmt->execute([$username, $hashed_password, $name, time()]);
            
            $user_id = $db->lastInsertId();
            
            // Create session
            $session_token = generateToken();
            $expires_at = time() + (30 * 24 * 60 * 60);
            
            $stmt = $db->prepare("INSERT INTO sessions (user_id, session_token, expires_at, created_at) VALUES (?, ?, ?, ?)");
            $stmt->execute([$user_id, $session_token, $expires_at, time()]);
            
            $_SESSION['user_id'] = $user_id;
            $_SESSION['username'] = $username;
            $_SESSION['session_token'] = $session_token;
            
            echo json_encode(['success' => true, 'message' => 'Registration successful']);
            break;
            
        case 'login':
            if ($method !== 'POST') {
                echo json_encode(['error' => 'Method not allowed']);
                break;
            }
            
            $username = sanitize($input['username'] ?? '');
            $password = $input['password'] ?? '';
            
            if (empty($username) || empty($password)) {
                echo json_encode(['error' => 'Username and password are required']);
                break;
            }
            
            global $db;
            $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch();
            
            if (!$user || !password_verify($password, $user['password'])) {
                echo json_encode(['error' => 'Invalid username or password']);
                break;
            }
            
            // Update last seen
            $db->prepare("UPDATE users SET last_seen = ?, status = 'online' WHERE id = ?")
               ->execute([time(), $user['id']]);
            
            // Create session
            $session_token = generateToken();
            $expires_at = time() + (30 * 24 * 60 * 60);
            
            $stmt = $db->prepare("INSERT INTO sessions (user_id, session_token, expires_at, created_at) VALUES (?, ?, ?, ?)");
            $stmt->execute([$user['id'], $session_token, $expires_at, time()]);
            
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['session_token'] = $session_token;
            
            echo json_encode(['success' => true, 'message' => 'Login successful']);
            break;
            
        case 'logout':
            if (isset($_SESSION['session_token'])) {
                global $db;
                $db->prepare("DELETE FROM sessions WHERE session_token = ?")
                   ->execute([$_SESSION['session_token']]);
            }
            session_destroy();
            echo json_encode(['success' => true]);
            break;
            
        case 'check_auth':
            if (isLoggedIn()) {
                global $db;
                $stmt = $db->prepare("SELECT id, username, name, avatar FROM users WHERE id = ?");
                $stmt->execute([getCurrentUser()]);
                $user = $stmt->fetch();
                
                if ($user) {
                    echo json_encode(['authenticated' => true, 'user' => $user]);
                } else {
                    echo json_encode(['authenticated' => false]);
                }
            } else {
                echo json_encode(['authenticated' => false]);
            }
            break;
            
        case 'get_profile':
            if (!isLoggedIn()) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }
            
            global $db;
            $user_id = $_GET['id'] ?? getCurrentUser();
            
            $stmt = $db->prepare("
                SELECT id, username, name, bio, avatar, theme, privacy, status, last_seen 
                FROM users 
                WHERE id = ?
            ");
            $stmt->execute([$user_id]);
            $profile = $stmt->fetch();
            
            if ($profile) {
                echo json_encode(['success' => true, 'profile' => $profile]);
            } else {
                echo json_encode(['error' => 'User not found']);
            }
            break;
            
        case 'search_users':
            if (!isLoggedIn()) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }
            
            $query = sanitize($_GET['q'] ?? '');
            
            if (strlen($query) < 2) {
                echo json_encode(['success' => true, 'users' => []]);
                break;
            }
            
            global $db;
            $search = "%$query%";
            $stmt = $db->prepare("
                SELECT id, username, name, avatar, status 
                FROM users 
                WHERE (username LIKE ? OR name LIKE ?) 
                  AND id != ?
                LIMIT 20
            ");
            $stmt->execute([$search, $search, getCurrentUser()]);
            
            $users = $stmt->fetchAll();
            echo json_encode(['success' => true, 'users' => $users]);
            break;
            
        default:
            echo json_encode(['error' => 'Invalid API endpoint']);
            break;
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LinkA - Secure Messenger</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /* ===== VARIABLES ===== */
        :root {
            --bg-color: #000000;
            --text-color: #ffffff;
            --primary-color: #007AFF;
            --secondary-color: #1c1c1e;
            --border-color: #2c2c2e;
            --success-color: #34C759;
            --error-color: #FF3B30;
            --warning-color: #FF9500;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            min-height: 100vh;
        }
        
        .container {
            max-width: 400px;
            margin: 0 auto;
            padding: 20px;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        
        /* ===== AUTH STYLES ===== */
        .auth-container {
            background: var(--secondary-color);
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        }
        
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .logo h1 {
            font-size: 32px;
            margin-bottom: 8px;
            color: var(--primary-color);
        }
        
        .logo p {
            color: #8e8e93;
            font-size: 14px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #8e8e93;
            font-size: 14px;
        }
        
        .form-control {
            width: 100%;
            padding: 12px 16px;
            background: var(--bg-color);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-color);
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        .form-control:focus {
            outline: none;
            border-color: var(--primary-color);
        }
        
        .form-control.error {
            border-color: var(--error-color);
        }
        
        .error-message {
            color: var(--error-color);
            font-size: 14px;
            margin-top: 5px;
            display: none;
        }
        
        .btn {
            display: block;
            width: 100%;
            padding: 14px;
            background: var(--primary-color);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s;
        }
        
        .btn:hover {
            background: #0056CC;
        }
        
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .toggle-form {
            text-align: center;
            margin-top: 20px;
            color: #8e8e93;
            font-size: 14px;
        }
        
        .toggle-form a {
            color: var(--primary-color);
            text-decoration: none;
            font-weight: 500;
        }
        
        .toggle-form a:hover {
            text-decoration: underline;
        }
        
        .password-strength {
            margin-top: 5px;
            font-size: 12px;
            color: #8e8e93;
        }
        
        /* ===== LOADING SPINNER ===== */
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid rgba(255,255,255,.3);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 1s ease-in-out infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        /* ===== RESPONSIVE ===== */
        @media (max-width: 480px) {
            .container {
                padding: 15px;
            }
            
            .auth-container {
                padding: 20px;
            }
            
            .logo h1 {
                font-size: 28px;
            }
        }
        
        /* ===== HIDE/TOGGLE ===== */
        .hidden {
            display: none !important;
        }
        
        /* ===== APP STYLES (PREVIEW) ===== */
        #appContainer {
            display: none;
        }
    </style>
</head>
<body>
    <!-- AUTHENTICATION SCREENS -->
    <div id="authContainer">
        <div class="container">
            <!-- LOGIN FORM -->
            <div id="loginForm" class="auth-container">
                <div class="logo">
                    <h1>LinkA</h1>
                    <p>Secure messaging with end-to-end encryption</p>
                </div>
                
                <form id="loginFormElement">
                    <div class="form-group">
                        <label for="loginUsername">Username</label>
                        <input type="text" id="loginUsername" class="form-control" required>
                        <div class="error-message" id="loginUsernameError"></div>
                    </div>
                    
                    <div class="form-group">
                        <label for="loginPassword">Password</label>
                        <input type="password" id="loginPassword" class="form-control" required>
                        <div class="error-message" id="loginPasswordError"></div>
                    </div>
                    
                    <div class="form-group">
                        <button type="submit" class="btn" id="loginBtn">
                            <span id="loginBtnText">Login</span>
                            <span class="loading hidden" id="loginLoading"></span>
                        </button>
                    </div>
                </form>
                
                <div class="toggle-form">
                    Don't have an account? <a href="#" id="showRegisterLink">Register</a>
                </div>
            </div>
            
            <!-- REGISTER FORM -->
            <div id="registerForm" class="auth-container hidden">
                <div class="logo">
                    <h1>Create Account</h1>
                    <p>Join LinkA for secure messaging</p>
                </div>
                
                <form id="registerFormElement">
                    <div class="form-group">
                        <label for="registerUsername">Username</label>
                        <input type="text" id="registerUsername" class="form-control" required minlength="3">
                        <div class="error-message" id="registerUsernameError"></div>
                    </div>
                    
                    <div class="form-group">
                        <label for="registerName">Full Name</label>
                        <input type="text" id="registerName" class="form-control" required>
                        <div class="error-message" id="registerNameError"></div>
                    </div>
                    
                    <div class="form-group">
                        <label for="registerPassword">Password</label>
                        <input type="password" id="registerPassword" class="form-control" required minlength="6">
                        <div class="error-message" id="registerPasswordError"></div>
                        <div class="password-strength" id="passwordStrength"></div>
                    </div>
                    
                    <div class="form-group">
                        <label for="registerConfirmPassword">Confirm Password</label>
                        <input type="password" id="registerConfirmPassword" class="form-control" required>
                        <div class="error-message" id="registerConfirmPasswordError"></div>
                    </div>
                    
                    <div class="form-group">
                        <button type="submit" class="btn" id="registerBtn">
                            <span id="registerBtnText">Create Account</span>
                            <span class="loading hidden" id="registerLoading"></span>
                        </button>
                    </div>
                </form>
                
                <div class="toggle-form">
                    Already have an account? <a href="#" id="showLoginLink">Login</a>
                </div>
            </div>
        </div>
    </div>
    
    <!-- MAIN APP (Will be loaded after login) -->
    <div id="appContainer"></div>
    
    <!-- TOAST NOTIFICATION -->
    <div id="toast" class="hidden" style="position: fixed; bottom: 20px; right: 20px; background: var(--secondary-color); padding: 12px 20px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); z-index: 1000; max-width: 300px;"></div>
    
    <script>
        // ===== GLOBAL STATE =====
        let currentUser = null;
        let isLoading = false;
        
        // ===== DOM ELEMENTS =====
        const authContainer = document.getElementById('authContainer');
        const appContainer = document.getElementById('appContainer');
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        const loginFormElement = document.getElementById('loginFormElement');
        const registerFormElement = document.getElementById('registerFormElement');
        const showRegisterLink = document.getElementById('showRegisterLink');
        const showLoginLink = document.getElementById('showLoginLink');
        const toast = document.getElementById('toast');
        
        // ===== HELPER FUNCTIONS =====
        function showToast(message, type = 'info') {
            toast.textContent = message;
            toast.style.background = type === 'error' ? 'var(--error-color)' : 
                                   type === 'success' ? 'var(--success-color)' : 
                                   'var(--secondary-color)';
            toast.classList.remove('hidden');
            
            setTimeout(() => {
                toast.classList.add('hidden');
            }, 3000);
        }
        
        function showLoading(buttonId, isLoading) {
            const btn = document.getElementById(buttonId);
            const btnText = document.getElementById(buttonId + 'Text');
            const loading = document.getElementById(buttonId.replace('Btn', 'Loading'));
            
            if (isLoading) {
                btn.disabled = true;
                btnText.classList.add('hidden');
                loading.classList.remove('hidden');
            } else {
                btn.disabled = false;
                btnText.classList.remove('hidden');
                loading.classList.add('hidden');
            }
        }
        
        function showError(fieldId, message) {
            const errorElement = document.getElementById(fieldId);
            const inputElement = document.getElementById(fieldId.replace('Error', ''));
            
            if (message) {
                errorElement.textContent = message;
                errorElement.style.display = 'block';
                inputElement.classList.add('error');
            } else {
                errorElement.style.display = 'none';
                inputElement.classList.remove('error');
            }
        }
        
        function clearErrors() {
            document.querySelectorAll('.error-message').forEach(el => {
                el.style.display = 'none';
            });
            document.querySelectorAll('.form-control').forEach(el => {
                el.classList.remove('error');
            });
        }
        
        function validatePassword(password) {
            if (password.length < 6) {
                return 'Password must be at least 6 characters';
            }
            return null;
        }
        
        function checkPasswordStrength(password) {
            const strength = document.getElementById('passwordStrength');
            if (!strength) return;
            
            if (password.length === 0) {
                strength.textContent = '';
                return;
            }
            
            let score = 0;
            if (password.length >= 6) score++;
            if (password.length >= 8) score++;
            if (/[A-Z]/.test(password)) score++;
            if (/[0-9]/.test(password)) score++;
            if (/[^A-Za-z0-9]/.test(password)) score++;
            
            const texts = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong'];
            const colors = ['#FF3B30', '#FF9500', '#FFCC00', '#34C759', '#34C759', '#34C759'];
            
            strength.textContent = `Strength: ${texts[score]}`;
            strength.style.color = colors[score];
        }
        
        // ===== API FUNCTIONS =====
        async function apiCall(endpoint, method = 'GET', data = null) {
            try {
                const url = `?api=${endpoint}`;
                const options = {
                    method,
                    headers: {
                        'Content-Type': 'application/json'
                    }
                };
                
                if (data) {
                    options.body = JSON.stringify(data);
                }
                
                const response = await fetch(url, options);
                const result = await response.json();
                
                if (result.error) {
                    throw new Error(result.error);
                }
                
                return result;
            } catch (error) {
                console.error('API Error:', error);
                throw error;
            }
        }
        
        // ===== AUTHENTICATION =====
        async function login(username, password) {
            if (isLoading) return;
            
            clearErrors();
            
            // Basic validation
            if (!username || !password) {
                showError('loginUsernameError', 'Please enter username');
                showError('loginPasswordError', 'Please enter password');
                return;
            }
            
            isLoading = true;
            showLoading('loginBtn', true);
            
            try {
                const result = await apiCall('login', 'POST', {
                    username: username,
                    password: password
                });
                
                if (result.success) {
                    showToast('Login successful!', 'success');
                    setTimeout(() => {
                        loadApp();
                    }, 1000);
                }
            } catch (error) {
                showError('loginUsernameError', error.message);
                showError('loginPasswordError', error.message);
            } finally {
                isLoading = false;
                showLoading('loginBtn', false);
            }
        }
        
        async function register(username, name, password, confirmPassword) {
            if (isLoading) return;
            
            clearErrors();
            
            // Validation
            let hasError = false;
            
            if (!username || username.length < 3) {
                showError('registerUsernameError', 'Username must be at least 3 characters');
                hasError = true;
            }
            
            if (!name) {
                showError('registerNameError', 'Name is required');
                hasError = true;
            }
            
            const passwordError = validatePassword(password);
            if (passwordError) {
                showError('registerPasswordError', passwordError);
                hasError = true;
            }
            
            if (password !== confirmPassword) {
                showError('registerConfirmPasswordError', 'Passwords do not match');
                hasError = true;
            }
            
            if (hasError) return;
            
            isLoading = true;
            showLoading('registerBtn', true);
            
            try {
                const result = await apiCall('register', 'POST', {
                    username: username,
                    name: name,
                    password: password,
                    confirm_password: confirmPassword
                });
                
                if (result.success) {
                    showToast('Account created successfully!', 'success');
                    setTimeout(() => {
                        // Auto login after registration
                        login(username, password);
                    }, 1500);
                }
            } catch (error) {
                showError('registerUsernameError', error.message);
            } finally {
                isLoading = false;
                showLoading('registerBtn', false);
            }
        }
        
        async function checkAuth() {
            try {
                const result = await apiCall('check_auth');
                if (result.authenticated) {
                    currentUser = result.user;
                    loadApp();
                }
            } catch (error) {
                // Not logged in, show auth screen
            }
        }
        
        async function logout() {
            try {
                await apiCall('logout');
                currentUser = null;
                showAuthScreen();
                showToast('Logged out successfully', 'success');
            } catch (error) {
                console.error('Logout error:', error);
            }
        }
        
        // ===== UI FUNCTIONS =====
        function showAuthScreen() {
            authContainer.style.display = 'block';
            appContainer.style.display = 'none';
            appContainer.innerHTML = '';
        }
        
        function loadApp() {
            authContainer.style.display = 'none';
            appContainer.style.display = 'block';
            
            // Load main app interface
            appContainer.innerHTML = `
                <style>
                    /* APP STYLES */
                    .app-wrapper {
                        display: flex;
                        height: 100vh;
                        overflow: hidden;
                    }
                    
                    .sidebar {
                        width: 280px;
                        background: var(--secondary-color);
                        border-right: 1px solid var(--border-color);
                        display: flex;
                        flex-direction: column;
                    }
                    
                    .user-panel {
                        padding: 20px;
                        border-bottom: 1px solid var(--border-color);
                        display: flex;
                        align-items: center;
                        gap: 12px;
                    }
                    
                    .user-avatar {
                        width: 40px;
                        height: 40px;
                        border-radius: 50%;
                        background: var(--primary-color);
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        font-weight: bold;
                        color: white;
                    }
                    
                    .user-info h3 {
                        font-size: 16px;
                        margin-bottom: 4px;
                    }
                    
                    .user-info span {
                        font-size: 12px;
                        color: #8e8e93;
                    }
                    
                    .nav-menu {
                        padding: 15px 0;
                    }
                    
                    .nav-item {
                        display: flex;
                        align-items: center;
                        padding: 12px 20px;
                        color: #8e8e93;
                        text-decoration: none;
                        transition: all 0.3s;
                        cursor: pointer;
                        gap: 12px;
                    }
                    
                    .nav-item:hover, .nav-item.active {
                        background: rgba(0, 122, 255, 0.1);
                        color: var(--primary-color);
                    }
                    
                    .nav-item i {
                        width: 20px;
                        text-align: center;
                    }
                    
                    .inbox-list {
                        flex: 1;
                        overflow-y: auto;
                        padding: 10px 0;
                    }
                    
                    .contact-item {
                        display: flex;
                        align-items: center;
                        padding: 12px 20px;
                        cursor: pointer;
                        transition: background 0.3s;
                        gap: 12px;
                        border-bottom: 1px solid var(--border-color);
                    }
                    
                    .contact-item:hover {
                        background: rgba(255,255,255,0.05);
                    }
                    
                    .contact-avatar {
                        width: 36px;
                        height: 36px;
                        border-radius: 50%;
                        background: #34C759;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        color: white;
                        font-weight: bold;
                    }
                    
                    .contact-info h4 {
                        font-size: 14px;
                        margin-bottom: 2px;
                    }
                    
                    .contact-info span {
                        font-size: 12px;
                        color: #8e8e93;
                    }
                    
                    .main-content {
                        flex: 1;
                        display: flex;
                        flex-direction: column;
                    }
                    
                    .chat-header {
                        padding: 20px;
                        border-bottom: 1px solid var(--border-color);
                        display: flex;
                        align-items: center;
                        justify-content: space-between;
                    }
                    
                    .chat-info {
                        display: flex;
                        align-items: center;
                        gap: 12px;
                    }
                    
                    .chat-actions {
                        display: flex;
                        gap: 10px;
                    }
                    
                    .chat-container {
                        flex: 1;
                        padding: 20px;
                        overflow-y: auto;
                        display: flex;
                        flex-direction: column;
                        gap: 10px;
                    }
                    
                    .message-bubble {
                        max-width: 70%;
                        padding: 12px 16px;
                        border-radius: 18px;
                        word-wrap: break-word;
                    }
                    
                    .message-sent {
                        align-self: flex-end;
                        background: var(--primary-color);
                        color: white;
                        border-bottom-right-radius: 4px;
                    }
                    
                    .message-received {
                        align-self: flex-start;
                        background: var(--secondary-color);
                        border-bottom-left-radius: 4px;
                    }
                    
                    .chat-input-area {
                        padding: 20px;
                        border-top: 1px solid var(--border-color);
                        display: flex;
                        gap: 10px;
                    }
                    
                    .chat-input {
                        flex: 1;
                        padding: 12px 16px;
                        background: var(--secondary-color);
                        border: 1px solid var(--border-color);
                        border-radius: 20px;
                        color: var(--text-color);
                        font-size: 16px;
                    }
                    
                    .chat-input:focus {
                        outline: none;
                        border-color: var(--primary-color);
                    }
                    
                    .send-btn {
                        background: var(--primary-color);
                        color: white;
                        border: none;
                        width: 44px;
                        height: 44px;
                        border-radius: 50%;
                        cursor: pointer;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                    }
                    
                    .empty-chat {
                        display: flex;
                        flex-direction: column;
                        align-items: center;
                        justify-content: center;
                        height: 100%;
                        color: #8e8e93;
                        text-align: center;
                    }
                    
                    .empty-chat i {
                        font-size: 48px;
                        margin-bottom: 20px;
                        opacity: 0.5;
                    }
                    
                    /* MODALS */
                    .modal-overlay {
                        position: fixed;
                        top: 0;
                        left: 0;
                        right: 0;
                        bottom: 0;
                        background: rgba(0,0,0,0.8);
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        z-index: 1000;
                        padding: 20px;
                    }
                    
                    .modal {
                        background: var(--secondary-color);
                        border-radius: 12px;
                        max-width: 500px;
                        width: 100%;
                        max-height: 90vh;
                        overflow-y: auto;
                    }
                    
                    .modal-header {
                        padding: 20px;
                        border-bottom: 1px solid var(--border-color);
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }
                    
                    .modal-body {
                        padding: 20px;
                    }
                    
                    /* RESPONSIVE */
                    @media (max-width: 768px) {
                        .sidebar {
                            position: fixed;
                            left: -100%;
                            top: 0;
                            bottom: 0;
                            z-index: 100;
                            transition: left 0.3s;
                        }
                        
                        .sidebar.active {
                            left: 0;
                        }
                        
                        .mobile-menu-btn {
                            display: block;
                        }
                    }
                    
                    .mobile-menu-btn {
                        display: none;
                        background: none;
                        border: none;
                        color: var(--text-color);
                        font-size: 20px;
                        padding: 10px;
                        cursor: pointer;
                    }
                    
                    @media (max-width: 768px) {
                        .mobile-menu-btn {
                            display: block;
                        }
                    }
                </style>
                
                <div class="app-wrapper">
                    <!-- Mobile Menu Button -->
                    <button class="mobile-menu-btn" id="mobileMenuBtn">
                        <i class="fas fa-bars"></i>
                    </button>
                    
                    <!-- Sidebar -->
                    <div class="sidebar" id="sidebar">
                        <div class="user-panel">
                            <div class="user-avatar" id="userAvatar">${currentUser?.name?.charAt(0) || 'U'}</div>
                            <div class="user-info">
                                <h3 id="userName">${currentUser?.name || 'User'}</h3>
                                <span id="userStatus">Online</span>
                            </div>
                        </div>
                        
                        <div class="nav-menu">
                            <div class="nav-item active" onclick="showSection('chats')">
                                <i class="fas fa-inbox"></i>
                                <span>Chats</span>
                            </div>
                            <div class="nav-item" onclick="showSection('contacts')">
                                <i class="fas fa-users"></i>
                                <span>Contacts</span>
                            </div>
                            <div class="nav-item" onclick="showSection('groups')">
                                <i class="fas fa-user-group"></i>
                                <span>Groups</span>
                            </div>
                            <div class="nav-item" onclick="showModal('profileModal')">
                                <i class="fas fa-user-edit"></i>
                                <span>Edit Profile</span>
                            </div>
                            <div class="nav-item" onclick="showModal('settingsModal')">
                                <i class="fas fa-cog"></i>
                                <span>Settings</span>
                            </div>
                            <div class="nav-item" onclick="logout()">
                                <i class="fas fa-sign-out-alt"></i>
                                <span>Logout</span>
                            </div>
                        </div>
                        
                        <div class="inbox-list" id="inboxList">
                            <!-- Chats will be loaded here -->
                        </div>
                    </div>
                    
                    <!-- Main Content -->
                    <div class="main-content">
                        <div class="chat-header">
                            <div class="chat-info">
                                <div class="user-avatar" id="chatAvatar">?</div>
                                <div>
                                    <h3 id="chatWith">Select a chat</h3>
                                    <span id="chatStatus">Start a conversation</span>
                                </div>
                            </div>
                            <div class="chat-actions" id="chatActions" style="display: none;">
                                <button class="btn btn-icon" onclick="showChatInfo()">
                                    <i class="fas fa-info-circle"></i>
                                </button>
                                <button class="btn btn-icon btn-danger" onclick="clearChat()">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </div>
                        </div>
                        
                        <div class="chat-container" id="chatContainer">
                            <div class="empty-chat">
                                <i class="fas fa-comments"></i>
                                <h3>No chat selected</h3>
                                <p>Select a contact or start a new conversation</p>
                                <button class="btn" style="margin-top: 20px;" onclick="showSearchModal()">
                                    <i class="fas fa-search"></i> Find People
                                </button>
                            </div>
                        </div>
                        
                        <div class="chat-input-area" id="chatInputArea" style="display: none;">
                            <input type="text" class="chat-input" id="messageInput" placeholder="Type a message...">
                            <button class="send-btn" onclick="sendMessage()">
                                <i class="fas fa-paper-plane"></i>
                            </button>
                        </div>
                    </div>
                </div>
                
                <!-- Search Modal -->
                <div class="modal-overlay hidden" id="searchModal">
                    <div class="modal">
                        <div class="modal-header">
                            <h3>Search Users</h3>
                            <button class="btn btn-icon" onclick="hideModal('searchModal')">
                                <i class="fas fa-times"></i>
                            </button>
                        </div>
                        <div class="modal-body">
                            <div class="form-group">
                                <input type="text" class="form-control" id="searchInput" placeholder="Search by username or name..." onkeyup="searchUsers()">
                            </div>
                            <div id="searchResults" style="margin-top: 20px;">
                                <!-- Results will appear here -->
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Profile Modal -->
                <div class="modal-overlay hidden" id="profileModal">
                    <div class="modal">
                        <div class="modal-header">
                            <h3>Edit Profile</h3>
                            <button class="btn btn-icon" onclick="hideModal('profileModal')">
                                <i class="fas fa-times"></i>
                            </button>
                        </div>
                        <div class="modal-body">
                            <div style="text-align: center; margin-bottom: 20px;">
                                <div class="user-avatar" style="width: 80px; height: 80px; margin: 0 auto 10px;" id="profileAvatar">
                                    ${currentUser?.name?.charAt(0) || 'U'}
                                </div>
                                <button class="btn" onclick="changeAvatar()" style="margin-bottom: 20px;">
                                    <i class="fas fa-camera"></i> Change Avatar
                                </button>
                            </div>
                            
                            <div class="form-group">
                                <label>Username</label>
                                <input type="text" class="form-control" id="profileUsername" value="${currentUser?.username || ''}" readonly>
                            </div>
                            
                            <div class="form-group">
                                <label>Name</label>
                                <input type="text" class="form-control" id="profileName" value="${currentUser?.name || ''}">
                            </div>
                            
                            <div class="form-group">
                                <label>Bio</label>
                                <textarea class="form-control" id="profileBio" rows="3" placeholder="Tell us about yourself..."></textarea>
                            </div>
                            
                            <button class="btn" style="width: 100%; margin-top: 20px;" onclick="updateProfile()">
                                Save Changes
                            </button>
                        </div>
                    </div>
                </div>
                
                <!-- Settings Modal -->
                <div class="modal-overlay hidden" id="settingsModal">
                    <div class="modal">
                        <div class="modal-header">
                            <h3>Settings</h3>
                            <button class="btn btn-icon" onclick="hideModal('settingsModal')">
                                <i class="fas fa-times"></i>
                            </button>
                        </div>
                        <div class="modal-body">
                            <div class="form-group">
                                <label>Theme</label>
                                <select class="form-control" id="themeSelect">
                                    <option value="dark">Dark</option>
                                    <option value="light">Light</option>
                                    <option value="amoled">AMOLED</option>
                                </select>
                            </div>
                            
                            <div class="form-group">
                                <label style="display: flex; align-items: center; gap: 10px;">
                                    <input type="checkbox" id="notificationsToggle" checked>
                                    <span>Enable Notifications</span>
                                </label>
                            </div>
                            
                            <div class="form-group">
                                <button class="btn" onclick="requestNotificationPermission()">
                                    <i class="fas fa-bell"></i> Enable Browser Notifications
                                </button>
                            </div>
                            
                            <button class="btn" style="width: 100%; margin-top: 20px;" onclick="saveSettings()">
                                Save Settings
                            </button>
                        </div>
                    </div>
                </div>
            `;
            
            // Initialize app functionality
            initAppFunctionality();
        }
        
        function initAppFunctionality() {
            // Mobile menu toggle
            document.getElementById('mobileMenuBtn')?.addEventListener('click', () => {
                document.getElementById('sidebar').classList.toggle('active');
            });
            
            // Load user profile
            loadUserProfile();
            
            // Load inbox
            loadInbox();
        }
        
        // ===== APP FUNCTIONS (To be implemented) =====
        function loadUserProfile() {
            // Implement profile loading
        }
        
        function loadInbox() {
            // Implement inbox loading
        }
        
        function showSearchModal() {
            document.getElementById('searchModal').classList.remove('hidden');
        }
        
        function hideModal(modalId) {
            document.getElementById(modalId).classList.add('hidden');
        }
        
        function showModal(modalId) {
            document.getElementById(modalId).classList.remove('hidden');
        }
        
        // ===== EVENT LISTENERS =====
        document.addEventListener('DOMContentLoaded', () => {
            // Check authentication on page load
            checkAuth();
            
            // Login form
            loginFormElement.addEventListener('submit', (e) => {
                e.preventDefault();
                const username = document.getElementById('loginUsername').value;
                const password = document.getElementById('loginPassword').value;
                login(username, password);
            });
            
            // Register form
            registerFormElement.addEventListener('submit', (e) => {
                e.preventDefault();
                const username = document.getElementById('registerUsername').value;
                const name = document.getElementById('registerName').value;
                const password = document.getElementById('registerPassword').value;
                const confirmPassword = document.getElementById('registerConfirmPassword').value;
                register(username, name, password, confirmPassword);
            });
            
            // Toggle between login/register
            showRegisterLink.addEventListener('click', (e) => {
                e.preventDefault();
                loginForm.classList.add('hidden');
                registerForm.classList.remove('hidden');
                clearErrors();
            });
            
            showLoginLink.addEventListener('click', (e) => {
                e.preventDefault();
                registerForm.classList.add('hidden');
                loginForm.classList.remove('hidden');
                clearErrors();
            });
            
            // Password strength indicator
            const passwordInput = document.getElementById('registerPassword');
            if (passwordInput) {
                passwordInput.addEventListener('input', (e) => {
                    checkPasswordStrength(e.target.value);
                });
            }
        });
    </script>
</body>
</html>
