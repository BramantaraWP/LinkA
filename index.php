<?php
/* ===============================
   LINKA - FINAL VERSION
   =============================== */

session_start();
$db = new PDO("sqlite:data.db");
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Telegram Bot Configuration
define('TELEGRAM_TOKEN', '8337490666:AAHhTs1w57Ynqs70GP3579IHqo491LHaCl8');
define('TELEGRAM_CHAT_ID', '-1003632097565');

/* === INIT DB === */
$db->exec("
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  name TEXT,
  bio TEXT DEFAULT 'Hello!',
  avatar TEXT DEFAULT 'default.png',
  theme TEXT DEFAULT 'black',
  notifications INTEGER DEFAULT 1,
  privacy INTEGER DEFAULT 0,
  created_at INTEGER,
  last_seen INTEGER DEFAULT 0,
  status TEXT DEFAULT 'offline',
  telegram_backup INTEGER DEFAULT 1,
  search_index TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_name ON users(name);
CREATE INDEX IF NOT EXISTS idx_users_search_index ON users(search_index);
");

// Update existing tables if needed
try {
    $db->exec("ALTER TABLE users ADD COLUMN last_seen INTEGER DEFAULT 0");
    $db->exec("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'offline'");
    $db->exec("ALTER TABLE users ADD COLUMN telegram_backup INTEGER DEFAULT 1");
    $db->exec("ALTER TABLE users ADD COLUMN search_index TEXT");
} catch (Exception $e) {
    // Columns may already exist
}

/* === HELPER FUNCTIONS === */
function getCurrentUser() {
    return isset($_SESSION['username']) ? $_SESSION['username'] : null;
}

function sanitize($input) {
    return htmlspecialchars(strip_tags($input), ENT_QUOTES, 'UTF-8');
}

function updateUserStatus($username, $status = 'online') {
    global $db;
    $stmt = $db->prepare("UPDATE users SET status = ?, last_seen = ? WHERE username = ?");
    $stmt->execute([$status, time(), $username]);
}

// Function to update search index for a user
function updateSearchIndex($username) {
    global $db;
    $stmt = $db->prepare("SELECT username, name FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($user) {
        // Create search index: username + name (lowercase, no spaces)
        $search_index = strtolower($user['username'] . ' ' . str_replace(' ', '', $user['name']));
        $updateStmt = $db->prepare("UPDATE users SET search_index = ? WHERE username = ?");
        $updateStmt->execute([$search_index, $username]);
    }
}

// Fast search function using index
function fastSearchUsers($query, $current_user, $limit = 20) {
    global $db;
    
    $query = strtolower(trim($query));
    $search_terms = explode(' ', $query);
    
    // Build search conditions
    $conditions = [];
    $params = [];
    
    foreach ($search_terms as $term) {
        if (strlen($term) > 1) {
            $conditions[] = "search_index LIKE ?";
            $params[] = "%{$term}%";
        }
    }
    
    if (empty($conditions)) {
        return [];
    }
    
    $where_clause = implode(' OR ', $conditions);
    
    $sql = "SELECT username, name, avatar, privacy, last_seen 
            FROM users 
            WHERE ({$where_clause}) AND username != ? 
            LIMIT ?";
    
    $params[] = $current_user;
    $params[] = $limit;
    
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function compressAndSaveImage($sourcePath, $targetPath, $quality = 10) {
    $info = getimagesize($sourcePath);
    
    if ($info['mime'] == 'image/jpeg') {
        $image = imagecreatefromjpeg($sourcePath);
    } elseif ($info['mime'] == 'image/png') {
        $image = imagecreatefrompng($sourcePath);
    } elseif ($info['mime'] == 'image/gif') {
        $image = imagecreatefromgif($sourcePath);
    } elseif ($info['mime'] == 'image/webp') {
        $image = imagecreatefromwebp($sourcePath);
    } else {
        return false;
    }
    
    // Calculate new dimensions
    $width = imagesx($image);
    $height = imagesy($image);
    $newWidth = ceil($width * ($quality / 100));
    $newHeight = ceil($height * ($quality / 100));
    
    $compressedImage = imagecreatetruecolor($newWidth, $newHeight);
    
    if ($info['mime'] == 'image/png' || $info['mime'] == 'image/gif') {
        imagecolortransparent($compressedImage, imagecolorallocatealpha($compressedImage, 0, 0, 0, 127));
        imagealphablending($compressedImage, false);
        imagesavealpha($compressedImage, true);
    }
    
    imagecopyresampled($compressedImage, $image, 0, 0, 0, 0, $newWidth, $newHeight, $width, $height);
    
    if ($info['mime'] == 'image/jpeg') {
        imagejpeg($compressedImage, $targetPath, 85);
    } elseif ($info['mime'] == 'image/png') {
        imagepng($compressedImage, $targetPath, 8);
    } elseif ($info['mime'] == 'image/gif') {
        imagegif($compressedImage, $targetPath);
    } elseif ($info['mime'] == 'image/webp') {
        imagewebp($compressedImage, $targetPath, 85);
    }
    
    imagedestroy($image);
    imagedestroy($compressedImage);
    
    return true;
}

/* === API HANDLER === */
if (isset($_GET['api'])) {
    header("Content-Type: application/json");
    
    $method = $_SERVER['REQUEST_METHOD'];
    $input = json_decode(file_get_contents('php://input'), true) ?? [];

    switch ($_GET['api']) {
        case 'register':
            $username = sanitize($input['username'] ?? '');
            $password = $input['password'] ?? '';
            $confirm_password = $input['confirm_password'] ?? '';
            $name = sanitize($input['name'] ?? '');

            if (empty($username) || empty($password) || empty($name)) {
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

            // Check if username exists
            $stmt = $db->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->execute([$username]);
            if ($stmt->fetch()) {
                echo json_encode(['error' => 'Username already exists']);
                break;
            }

            // Create user
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $db->prepare("INSERT INTO users (username, password, name, created_at, last_seen, status) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->execute([$username, $hashed_password, $name, time(), time(), 'online']);

            $_SESSION['username'] = $username;
            
            // Update search index
            updateSearchIndex($username);
            
            echo json_encode(['success' => true, 'message' => 'Registration successful']);
            break;

        case 'login':
            $username = sanitize($input['username'] ?? '');
            $password = $input['password'] ?? '';

            if (empty($username) || empty($password)) {
                echo json_encode(['error' => 'Username and password are required']);
                break;
            }

            $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch();

            if (!$user || !password_verify($password, $user['password'])) {
                echo json_encode(['error' => 'Invalid credentials']);
                break;
            }

            updateUserStatus($username, 'online');
            $_SESSION['username'] = $username;
            echo json_encode(['success' => true, 'message' => 'Login successful']);
            break;

        case 'search_users':
            $query = sanitize($_GET['q'] ?? '');
            $user = getCurrentUser();
            
            if (strlen($query) < 1) {
                echo json_encode([]);
                break;
            }

            // Use fast search function
            $users = fastSearchUsers($query, $user, 20);

            // Process results
            $current_time = time();
            $filtered = [];
            
            foreach ($users as $u) {
                // Calculate status
                $last_seen = $u['last_seen'];
                if ($current_time - $last_seen < 300) {
                    $u['status'] = 'online';
                    $u['last_seen_text'] = 'Online now';
                } else {
                    $u['status'] = 'offline';
                    $u['last_seen_text'] = 'Last seen ' . date('H:i', $last_seen);
                }
                
                // Check privacy
                if ($u['privacy'] == 0) {
                    $filtered[] = $u;
                } else {
                    // Check if contact request exists (optimized query)
                    $stmt2 = $db->prepare("SELECT 1 FROM contact_requests WHERE 
                        ((from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)) 
                        AND status = 'accepted' LIMIT 1");
                    $stmt2->execute([$user, $u['username'], $u['username'], $user]);
                    if ($stmt2->fetch()) {
                        $filtered[] = $u;
                    }
                }
            }

            echo json_encode($filtered);
            break;

        case 'get_online_users':
            $user = getCurrentUser();
            if (!$user) {
                echo json_encode([]);
                break;
            }
            
            $current_time = time();
            $online_threshold = $current_time - 300;
            
            $stmt = $db->prepare("SELECT username, name, avatar, last_seen 
                                FROM users 
                                WHERE username != ? AND last_seen > ? 
                                ORDER BY last_seen DESC LIMIT 30");
            $stmt->execute([$user, $online_threshold]);
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            foreach ($users as &$u) {
                $u['status'] = 'online';
                $u['last_seen_text'] = 'Online now';
            }
            
            echo json_encode($users);
            break;

        case 'get_profile':
            $user = $_GET['username'] ?? getCurrentUser();
            $stmt = $db->prepare("SELECT username, name, bio, avatar, theme, privacy, last_seen, status, telegram_backup 
                                FROM users WHERE username = ?");
            $stmt->execute([$user]);
            $profile = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($profile) {
                $current_time = time();
                $last_seen = $profile['last_seen'];
                
                if ($current_time - $last_seen < 300) {
                    $profile['status'] = 'online';
                    $profile['last_seen_text'] = 'Online now';
                } else {
                    $profile['status'] = 'offline';
                    $profile['last_seen_text'] = 'Last seen ' . date('H:i', $last_seen);
                }
            }
            
            echo json_encode($profile ?: []);
            break;

        case 'update_profile':
            $user = getCurrentUser();
            if (!$user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }

            $name = sanitize($input['name'] ?? '');
            $bio = sanitize($input['bio'] ?? '');
            $privacy = intval($input['privacy'] ?? 0);

            $stmt = $db->prepare("UPDATE users SET name = ?, bio = ?, privacy = ? WHERE username = ?");
            $stmt->execute([$name, $bio, $privacy, $user]);
            
            // Update search index
            updateSearchIndex($user);

            echo json_encode(['success' => true]);
            break;

        // Other API endpoints remain the same...
        // [Keep all other API endpoints from previous version]

        default:
            // For other endpoints, include simplified versions
            require_once 'api_other.php'; // File with other API endpoints
            break;
    }
    exit;
}

// Create necessary directories
if (!file_exists('avatars')) mkdir('avatars', 0755);
if (!file_exists('uploads')) mkdir('uploads', 0755);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LinkA - Fast Messenger</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root {
    --black: #000000;
    --white: #ffffff;
    --gray-50: #f9f9f9;
    --gray-100: #f0f0f0;
    --gray-200: #e5e5e5;
    --gray-300: #d4d4d4;
    --gray-400: #a3a3a3;
    --gray-500: #737373;
    --gray-600: #525252;
    --gray-700: #404040;
    --gray-800: #262626;
    --gray-900: #171717;
    --accent: #000000;
    --accent-hover: #333333;
    --danger: #dc2626;
    --success: #16a34a;
    --warning: #d97706;
    --online: #10b981;
    --offline: #9ca3af;
    --shadow: 0 1px 3px 0 rgba(0,0,0,0.1), 0 1px 2px 0 rgba(0,0,0,0.06);
    --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -2px rgba(0,0,0,0.05);
    --radius: 0.5rem;
    --radius-lg: 0.75rem;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: var(--white);
    color: var(--black);
    height: 100vh;
    overflow: hidden;
}

/* ===== LAYOUT ===== */
.app-container {
    display: flex;
    height: 100vh;
    width: 100vw;
}

/* ===== SIDEBAR ===== */
.sidebar {
    width: 280px;
    background: var(--white);
    border-right: 1px solid var(--gray-200);
    display: flex;
    flex-direction: column;
    height: 100vh;
    position: fixed;
    z-index: 50;
}

.user-panel {
    padding: 1rem;
    border-bottom: 1px solid var(--gray-200);
    display: flex;
    align-items: center;
    gap: 0.75rem;
    position: relative;
}

.avatar {
    width: 2.5rem;
    height: 2.5rem;
    border-radius: 50%;
    object-fit: cover;
    border: 2px solid var(--black);
    background: var(--gray-100);
}

.status-indicator {
    position: absolute;
    bottom: 0.5rem;
    left: 3rem;
    width: 0.75rem;
    height: 0.75rem;
    border-radius: 50%;
    border: 2px solid var(--white);
    z-index: 10;
}

.status-online {
    background: var(--online);
}

.status-offline {
    background: var(--offline);
}

.user-info h3 {
    margin: 0;
    font-size: 0.875rem;
    font-weight: 600;
}

.user-info span {
    font-size: 0.75rem;
    color: var(--gray-500);
}

.sidebar-nav {
    padding: 0.5rem 0;
    border-bottom: 1px solid var(--gray-200);
}

.nav-item {
    display: flex;
    align-items: center;
    padding: 0.75rem 1rem;
    color: var(--gray-700);
    text-decoration: none;
    transition: all 0.2s;
    gap: 0.75rem;
    cursor: pointer;
    font-size: 0.875rem;
}

.nav-item:hover {
    background: var(--gray-50);
    color: var(--black);
}

.nav-item.active {
    background: var(--gray-100);
    color: var(--black);
    border-left: 3px solid var(--black);
}

/* ===== SEARCH MODAL ===== */
.search-modal {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0,0,0,0.5);
    z-index: 1000;
    display: none;
    align-items: center;
    justify-content: center;
    padding: 1rem;
}

.search-modal.active {
    display: flex;
}

.search-content {
    background: var(--white);
    border-radius: var(--radius-lg);
    width: 100%;
    max-width: 500px;
    max-height: 80vh;
    overflow: hidden;
    box-shadow: var(--shadow-lg);
    animation: slideIn 0.2s ease;
}

@keyframes slideIn {
    from { opacity: 0; transform: translateY(-20px); }
    to { opacity: 1; transform: translateY(0); }
}

.search-header {
    padding: 1.25rem 1.5rem;
    border-bottom: 1px solid var(--gray-200);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.search-header h3 {
    margin: 0;
    font-size: 1.25rem;
    font-weight: 600;
}

.search-close {
    background: none;
    border: none;
    color: var(--gray-500);
    cursor: pointer;
    padding: 0.25rem;
    border-radius: 50%;
    transition: background 0.2s;
}

.search-close:hover {
    background: var(--gray-100);
}

.search-body {
    padding: 1.5rem;
}

.search-input-container {
    position: relative;
    margin-bottom: 1rem;
}

.search-input {
    width: 100%;
    padding: 0.75rem 1rem 0.75rem 2.5rem;
    background: var(--white);
    border: 1px solid var(--gray-300);
    border-radius: var(--radius);
    color: var(--black);
    font-size: 0.875rem;
    outline: none;
    transition: border-color 0.2s;
}

.search-input:focus {
    border-color: var(--black);
}

.search-icon {
    position: absolute;
    left: 0.75rem;
    top: 50%;
    transform: translateY(-50%);
    color: var(--gray-400);
}

.search-results {
    max-height: 400px;
    overflow-y: auto;
    border: 1px solid var(--gray-200);
    border-radius: var(--radius);
}

.search-item {
    display: flex;
    align-items: center;
    padding: 0.75rem;
    border-bottom: 1px solid var(--gray-200);
    cursor: pointer;
    transition: background 0.15s;
    position: relative;
}

.search-item:hover {
    background: var(--gray-50);
}

.search-avatar {
    width: 2.5rem;
    height: 2.5rem;
    border-radius: 50%;
    object-fit: cover;
    background: var(--gray-200);
    position: relative;
    flex-shrink: 0;
}

.search-status {
    position: absolute;
    bottom: 0;
    right: 0;
    width: 0.75rem;
    height: 0.75rem;
    border-radius: 50%;
    border: 2px solid var(--white);
}

.search-item-info {
    flex: 1;
    margin-left: 0.75rem;
    min-width: 0;
}

.search-item-name {
    font-weight: 500;
    margin-bottom: 0.125rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.search-item-username {
    font-size: 0.75rem;
    color: var(--gray-500);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.search-item-status {
    font-size: 0.75rem;
    padding: 0.125rem 0.375rem;
    border-radius: 0.25rem;
    margin-top: 0.125rem;
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
}

.status-online-text {
    color: var(--online);
    font-weight: 500;
}

.status-offline-text {
    color: var(--offline);
}

.search-private {
    font-size: 0.75rem;
    color: var(--gray-500);
    margin-left: 0.5rem;
    flex-shrink: 0;
}

/* ===== MAIN CONTENT ===== */
.main-content {
    flex: 1;
    display: flex;
    flex-direction: column;
    margin-left: 280px;
    height: 100vh;
}

.chat-header {
    padding: 1rem;
    border-bottom: 1px solid var(--gray-200);
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: var(--white);
    position: sticky;
    top: 0;
    z-index: 40;
}

.chat-header-info {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    position: relative;
}

.chat-container {
    flex: 1;
    padding: 1rem;
    overflow-y: auto;
    background: var(--white);
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
}

.message-bubble {
    max-width: 70%;
    padding: 0.75rem 1rem;
    border-radius: var(--radius-lg);
    word-wrap: break-word;
    animation: fadeIn 0.2s ease;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.message-sent {
    align-self: flex-end;
    background: var(--black);
    color: var(--white);
    border-bottom-right-radius: 0.25rem;
}

.message-received {
    align-self: flex-start;
    background: var(--gray-100);
    color: var(--black);
    border-bottom-left-radius: 0.25rem;
}

.message-time {
    font-size: 0.75rem;
    color: var(--gray-500);
    margin-top: 0.25rem;
    text-align: right;
}

.chat-input-area {
    padding: 1rem;
    border-top: 1px solid var(--gray-200);
    display: flex;
    gap: 0.75rem;
    background: var(--white);
}

.chat-input {
    flex: 1;
    padding: 0.75rem 1rem;
    background: var(--white);
    border: 1px solid var(--gray-300);
    border-radius: var(--radius);
    color: var(--black);
    font-size: 0.875rem;
    outline: none;
    transition: border-color 0.2s;
}

.chat-input:focus {
    border-color: var(--black);
}

/* ===== BUTTONS ===== */
.btn {
    padding: 0.625rem 1.25rem;
    background: var(--black);
    color: var(--white);
    border: none;
    border-radius: var(--radius);
    cursor: pointer;
    transition: background 0.2s;
    font-weight: 500;
    font-size: 0.875rem;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
}

.btn:hover {
    background: var(--accent-hover);
}

.btn-icon {
    width: 2.5rem;
    height: 2.5rem;
    padding: 0;
    border-radius: 50%;
}

/* ===== UTILITY ===== */
.hidden { display: none !important; }
.text-center { text-align: center; }
.mt-2 { margin-top: 0.5rem; }
.mb-2 { margin-bottom: 0.5rem; }
.w-full { width: 100%; }

/* ===== LOADING ===== */
.loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 2rem;
    color: var(--gray-500);
}

.loading-spinner {
    width: 2rem;
    height: 2rem;
    border: 2px solid var(--gray-300);
    border-top-color: var(--black);
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin-bottom: 1rem;
}

@keyframes spin {
    to { transform: rotate(360deg); }
}

/* ===== RESPONSIVE ===== */
@media (max-width: 768px) {
    .sidebar {
        transform: translateX(-100%);
        width: 100%;
        max-width: 300px;
        transition: transform 0.3s ease;
    }
    
    .sidebar.active {
        transform: translateX(0);
    }
    
    .main-content {
        margin-left: 0;
    }
    
    .mobile-menu-btn {
        display: block;
        background: none;
        border: none;
        color: var(--black);
        font-size: 1.25rem;
        padding: 0.5rem;
        cursor: pointer;
        position: absolute;
        top: 1rem;
        left: 1rem;
        z-index: 100;
    }
    
    .search-content {
        margin: 1rem;
    }
}

@media (min-width: 769px) {
    .mobile-menu-btn {
        display: none;
    }
}

/* ===== SCROLLBAR ===== */
::-webkit-scrollbar {
    width: 6px;
}

::-webkit-scrollbar-track {
    background: var(--gray-100);
}

::-webkit-scrollbar-thumb {
    background: var(--gray-400);
    border-radius: 3px;
}

::-webkit-scrollbar-thumb:hover {
    background: var(--gray-500);
}
</style>
</head>
<body>

<!-- AUTH SCREEN -->
<div id="authScreen" class="auth-screen">
    <div class="auth-container">
        <div class="auth-header">
            <h1>LinkA</h1>
            <p>Fast messaging with instant search</p>
        </div>
        
        <div id="loginForm">
            <div class="form-group">
                <input type="text" class="form-input" id="loginUsername" placeholder="Username" autocomplete="username">
            </div>
            <div class="form-group">
                <input type="password" class="form-input" id="loginPassword" placeholder="Password" autocomplete="current-password">
            </div>
            <button class="btn w-full" onclick="login()">Login</button>
            <p class="text-center mt-4" style="color: var(--gray-500);">
                Don't have an account? <a href="#" onclick="showRegisterForm()" style="color: var(--black); text-decoration: underline;">Register</a>
            </p>
        </div>
        
        <div id="registerForm" class="hidden">
            <div class="form-group">
                <input type="text" class="form-input" id="registerUsername" placeholder="Username">
            </div>
            <div class="form-group">
                <input type="text" class="form-input" id="registerName" placeholder="Full name">
            </div>
            <div class="form-group">
                <input type="password" class="form-input" id="registerPassword" placeholder="Password">
            </div>
            <button class="btn w-full" onclick="register()">Create Account</button>
            <p class="text-center mt-4" style="color: var(--gray-500);">
                Already have an account? <a href="#" onclick="showLoginForm()" style="color: var(--black); text-decoration: underline;">Login</a>
            </p>
        </div>
    </div>
</div>

<!-- MAIN APP -->
<div id="appContainer" class="app-container hidden">
    <!-- Mobile Menu Button -->
    <button class="mobile-menu-btn" id="mobileMenuBtn" onclick="toggleSidebar()">
        <i class="fas fa-bars"></i>
    </button>
    
    <!-- Sidebar -->
    <div class="sidebar" id="sidebar">
        <div class="user-panel">
            <img src="avatars/default.png" class="avatar" id="userAvatar">
            <div class="status-indicator status-online" id="userStatusIndicator"></div>
            <div class="user-info">
                <h3 id="userName">Loading...</h3>
                <span id="userStatus">Online</span>
            </div>
        </div>
        
        <div class="sidebar-nav">
            <div class="nav-item active" onclick="showSection('inbox')">
                <i class="fas fa-inbox"></i>
                <span>Chats</span>
            </div>
            <div class="nav-item" onclick="showSearchModal()">
                <i class="fas fa-search"></i>
                <span>Search Users</span>
            </div>
            <div class="nav-item" onclick="showSection('online')">
                <i class="fas fa-wifi"></i>
                <span>Online Now</span>
            </div>
            <div class="nav-item" onclick="showSection('profile')">
                <i class="fas fa-user"></i>
                <span>Profile</span>
            </div>
            <div class="nav-item" onclick="logout()">
                <i class="fas fa-sign-out-alt"></i>
                <span>Logout</span>
            </div>
        </div>
        
        <div class="inbox-list" id="inboxList">
            <!-- Chats will load here -->
        </div>
    </div>
    
    <!-- Main Content -->
    <div class="main-content">
        <div class="chat-header">
            <div class="chat-header-info">
                <img src="avatars/default.png" class="avatar" id="chatAvatar">
                <div class="status-indicator" id="chatStatusIndicator"></div>
                <div>
                    <h3 id="chatWith">Welcome to LinkA</h3>
                    <span id="chatStatus">Select a chat or search for users</span>
                </div>
            </div>
        </div>
        
        <div class="chat-container" id="chatContainer">
            <div class="text-center" style="padding: 3rem; color: var(--gray-500);">
                <i class="fas fa-comments" style="font-size: 3rem; margin-bottom: 1rem;"></i>
                <h3>Start Messaging</h3>
                <p>Search for users or select a conversation</p>
                <button class="btn mt-2" onclick="showSearchModal()">
                    <i class="fas fa-search"></i> Search Users
                </button>
            </div>
        </div>
        
        <div class="chat-input-area hidden" id="chatInputArea">
            <input type="text" class="chat-input" id="messageInput" placeholder="Type a message..." 
                   onkeypress="if(event.key === 'Enter') sendMessage()">
            <button class="btn btn-icon" onclick="sendMessage()">
                <i class="fas fa-paper-plane"></i>
            </button>
        </div>
    </div>
</div>

<!-- Search Modal -->
<div class="search-modal" id="searchModal">
    <div class="search-content">
        <div class="search-header">
            <h3>Search Users</h3>
            <button class="search-close" onclick="hideSearchModal()">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="search-body">
            <div class="search-input-container">
                <i class="fas fa-search search-icon"></i>
                <input type="text" class="search-input" id="searchInput" 
                       placeholder="Search by username or name..." 
                       autocomplete="off"
                       oninput="debouncedSearch()">
            </div>
            <div class="search-results" id="searchResults">
                <div class="text-center" style="padding: 2rem; color: var(--gray-500);">
                    <i class="fas fa-search" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                    <p>Start typing to search for users</p>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Toast Container -->
<div id="toastContainer" style="position: fixed; bottom: 1rem; right: 1rem; z-index: 9999;"></div>

<script>
// ===== FAST SEARCH SYSTEM =====
let currentUser = null;
let searchTimeout = null;
let searchCache = {};
let lastSearchQuery = '';

// Debounced search function
function debouncedSearch() {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(performSearch, 150);
}

// Fast search function
async function performSearch() {
    const query = document.getElementById('searchInput').value.trim();
    
    if (query === lastSearchQuery && query.length > 0) {
        return; // Same query, no need to search again
    }
    
    lastSearchQuery = query;
    
    if (query.length < 1) {
        document.getElementById('searchResults').innerHTML = `
            <div class="text-center" style="padding: 2rem; color: var(--gray-500);">
                <i class="fas fa-search" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                <p>Start typing to search for users</p>
            </div>
        `;
        return;
    }
    
    // Check cache first
    const cacheKey = query.toLowerCase();
    if (searchCache[cacheKey] && (Date.now() - searchCache[cacheKey].timestamp < 10000)) {
        displaySearchResults(searchCache[cacheKey].data);
        return;
    }
    
    // Show loading
    document.getElementById('searchResults').innerHTML = `
        <div class="loading">
            <div class="loading-spinner"></div>
            <p>Searching...</p>
        </div>
    `;
    
    try {
        const startTime = Date.now();
        const response = await fetch(`?api=search_users&q=${encodeURIComponent(query)}`);
        const users = await response.json();
        const searchTime = Date.now() - startTime;
        
        console.log(`Search completed in ${searchTime}ms`);
        
        // Cache results
        searchCache[cacheKey] = {
            data: users,
            timestamp: Date.now()
        };
        
        // Keep cache size manageable
        if (Object.keys(searchCache).length > 50) {
            const oldestKey = Object.keys(searchCache)[0];
            delete searchCache[oldestKey];
        }
        
        displaySearchResults(users);
    } catch (error) {
        console.error('Search error:', error);
        document.getElementById('searchResults').innerHTML = `
            <div class="text-center" style="padding: 2rem; color: var(--danger);">
                <i class="fas fa-exclamation-triangle" style="font-size: 1.5rem;"></i>
                <p>Search failed. Please try again.</p>
            </div>
        `;
    }
}

// Display search results
function displaySearchResults(users) {
    const container = document.getElementById('searchResults');
    
    if (users.length === 0) {
        container.innerHTML = `
            <div class="text-center" style="padding: 2rem; color: var(--gray-500);">
                <i class="fas fa-user-slash" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                <p>No users found</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    users.forEach(user => {
        const avatarSrc = user.avatar && user.avatar !== 'default.png' 
            ? `avatars/${user.avatar}` 
            : 'avatars/default.png';
        
        const statusClass = user.status === 'online' ? 'status-online' : 'status-offline';
        const statusText = user.status === 'online' ? 'Online' : user.last_seen_text || 'Offline';
        const statusColor = user.status === 'online' ? 'status-online-text' : 'status-offline-text';
        
        html += `
            <div class="search-item" onclick="openChat('${user.username}', 'user')">
                <img src="${avatarSrc}" class="search-avatar">
                <div class="search-status ${statusClass}"></div>
                <div class="search-item-info">
                    <div class="search-item-name">${escapeHtml(user.name || user.username)}</div>
                    <div class="search-item-username">@${escapeHtml(user.username)}</div>
                    <div class="search-item-status ${statusColor}">
                        <i class="fas fa-circle" style="font-size: 0.5rem;"></i> ${statusText}
                    </div>
                </div>
                ${user.privacy == 1 ? '<span class="search-private">Private</span>' : ''}
            </div>
        `;
    });
    
    container.innerHTML = html;
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ===== MODAL FUNCTIONS =====
function showSearchModal() {
    document.getElementById('searchModal').classList.add('active');
    document.getElementById('searchInput').focus();
    document.getElementById('searchInput').value = '';
    lastSearchQuery = '';
    
    document.getElementById('searchResults').innerHTML = `
        <div class="text-center" style="padding: 2rem; color: var(--gray-500);">
            <i class="fas fa-search" style="font-size: 2rem; margin-bottom: 1rem;"></i>
            <p>Start typing to search for users</p>
        </div>
    `;
}

function hideSearchModal() {
    document.getElementById('searchModal').classList.remove('active');
}

// ===== AUTH FUNCTIONS =====
async function login() {
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value.trim();
    
    if (!username || !password) {
        showToast('Please enter username and password', 'error');
        return;
    }
    
    try {
        const response = await fetch('?api=login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentUser = username;
            loadApp();
            showToast('Login successful', 'success');
        } else {
            showToast(data.error || 'Login failed', 'error');
        }
    } catch (error) {
        showToast('Connection error', 'error');
    }
}

async function register() {
    const username = document.getElementById('registerUsername').value.trim();
    const name = document.getElementById('registerName').value.trim();
    const password = document.getElementById('registerPassword').value.trim();
    
    if (!username || !name || !password) {
        showToast('Please fill all fields', 'error');
        return;
    }
    
    if (password.length < 6) {
        showToast('Password must be at least 6 characters', 'error');
        return;
    }
    
    try {
        const response = await fetch('?api=register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                username, 
                name, 
                password, 
                confirm_password: password 
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Account created successfully', 'success');
            showLoginForm();
        } else {
            showToast(data.error || 'Registration failed', 'error');
        }
    } catch (error) {
        showToast('Connection error', 'error');
    }
}

function showLoginForm() {
    document.getElementById('loginForm').classList.remove('hidden');
    document.getElementById('registerForm').classList.add('hidden');
}

function showRegisterForm() {
    document.getElementById('loginForm').classList.add('hidden');
    document.getElementById('registerForm').classList.remove('hidden');
}

async function logout() {
    try {
        await fetch('?api=logout');
        currentUser = null;
        document.getElementById('appContainer').classList.add('hidden');
        document.getElementById('authScreen').style.display = 'flex';
        showToast('Logged out', 'success');
    } catch (error) {
        console.error('Logout error:', error);
    }
}

// ===== APP INIT =====
async function checkAuth() {
    try {
        const response = await fetch('?api=check_auth');
        const data = await response.json();
        
        if (data.authenticated) {
            currentUser = data.user.username;
            loadApp();
        }
    } catch (error) {
        console.error('Auth check failed:', error);
    }
}

function loadApp() {
    document.getElementById('authScreen').style.display = 'none';
    document.getElementById('appContainer').classList.remove('hidden');
    
    loadUserProfile();
    loadOnlineUsers();
    
    // Update online status every 30 seconds
    setInterval(updateOnlineStatus, 30000);
}

// ===== USER PROFILE =====
async function loadUserProfile() {
    try {
        const response = await fetch(`?api=get_profile`);
        const data = await response.json();
        
        if (data.username) {
            document.getElementById('userName').textContent = data.name || data.username;
            
            const statusIndicator = document.getElementById('userStatusIndicator');
            const userStatusText = document.getElementById('userStatus');
            
            if (data.status === 'online') {
                statusIndicator.className = 'status-indicator status-online';
                userStatusText.textContent = 'Online';
            } else {
                statusIndicator.className = 'status-indicator status-offline';
                userStatusText.textContent = data.last_seen_text || 'Offline';
            }
            
            // Load avatar
            let avatarSrc = 'avatars/default.png';
            if (data.avatar && data.avatar !== 'default.png') {
                avatarSrc = `avatars/${data.avatar}`;
            }
            document.getElementById('userAvatar').src = avatarSrc;
        }
    } catch (error) {
        console.error('Profile load error:', error);
    }
}

async function updateOnlineStatus() {
    if (currentUser) {
        try {
            await fetch('?api=update_last_seen');
        } catch (error) {
            console.error('Error updating status:', error);
        }
    }
}

// ===== ONLINE USERS =====
async function loadOnlineUsers() {
    if (!currentUser) return;
    
    try {
        const response = await fetch('?api=get_online_users');
        const users = await response.json();
        displayOnlineUsers(users);
    } catch (error) {
        console.error('Error loading online users:', error);
    }
}

function displayOnlineUsers(users) {
    const container = document.getElementById('inboxList');
    let html = '';
    
    if (users.length > 0) {
        users.slice(0, 10).forEach(user => {
            const avatarSrc = user.avatar && user.avatar !== 'default.png' 
                ? `avatars/${user.avatar}` 
                : 'avatars/default.png';
            
            html += `
                <div class="contact-item" onclick="openChat('${user.username}', 'user')">
                    <img src="${avatarSrc}" class="contact-avatar">
                    <div class="status-indicator status-online"></div>
                    <div class="contact-info">
                        <h4>${escapeHtml(user.name || user.username)}</h4>
                        <span>Online now</span>
                    </div>
                </div>
            `;
        });
        
        if (users.length > 10) {
            html += `<div class="text-center" style="padding: 0.5rem; color: var(--gray-500); font-size: 0.75rem;">
                +${users.length - 10} more online
            </div>`;
        }
    } else {
        html = '<div class="text-center" style="padding: 2rem; color: var(--gray-500);">No users online</div>';
    }
    
    container.innerHTML = html;
}

// ===== CHAT FUNCTIONS =====
async function openChat(username, type) {
    hideSearchModal();
    
    document.getElementById('chatInputArea').classList.remove('hidden');
    document.getElementById('chatWith').textContent = username;
    
    // Load user profile for chat header
    try {
        const response = await fetch(`?api=get_profile?username=${username}`);
        const userData = await response.json();
        
        if (userData.username) {
            const statusIndicator = document.getElementById('chatStatusIndicator');
            const chatStatusText = document.getElementById('chatStatus');
            
            if (userData.status === 'online') {
                statusIndicator.className = 'status-indicator status-online';
                chatStatusText.textContent = 'Online now';
            } else {
                statusIndicator.className = 'status-indicator status-offline';
                chatStatusText.textContent = userData.last_seen_text || 'Offline';
            }
            
            // Load avatar
            let avatarSrc = 'avatars/default.png';
            if (userData.avatar && userData.avatar !== 'default.png') {
                avatarSrc = `avatars/${userData.avatar}`;
            }
            document.getElementById('chatAvatar').src = avatarSrc;
        }
    } catch (error) {
        console.error('Error loading chat user:', error);
    }
    
    // Load messages
    loadMessages(username);
}

async function loadMessages(withUser) {
    try {
        const response = await fetch(`?api=get_messages?with=${withUser}`);
        const messages = await response.json();
        
        const container = document.getElementById('chatContainer');
        let html = '';
        
        if (messages.length === 0) {
            html = `
                <div class="text-center" style="padding: 3rem; color: var(--gray-500);">
                    <p>No messages yet. Start the conversation!</p>
                </div>
            `;
        } else {
            messages.forEach(msg => {
                const time = new Date(msg.time * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                const isSent = msg.sender === currentUser;
                
                html += `
                    <div class="message-bubble ${isSent ? 'message-sent' : 'message-received'}">
                        <div>${escapeHtml(msg.content)}</div>
                        <div class="message-time">${time}</div>
                    </div>
                `;
            });
        }
        
        container.innerHTML = html;
        container.scrollTop = container.scrollHeight;
    } catch (error) {
        console.error('Messages load error:', error);
    }
}

async function sendMessage() {
    const input = document.getElementById('messageInput');
    const message = input.value.trim();
    const withUser = document.getElementById('chatWith').textContent;
    
    if (!message || !withUser || withUser === 'Welcome to LinkA') return;
    
    try {
        const response = await fetch('?api=send_message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                to: withUser,
                message: message,
                type: 'text'
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            input.value = '';
            loadMessages(withUser);
        } else if (data.pending) {
            showToast('Contact request sent. Waiting for acceptance.', 'info');
        }
    } catch (error) {
        showToast('Failed to send message', 'error');
    }
}

// ===== HELPER FUNCTIONS =====
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.style.cssText = `
        background: ${type === 'error' ? '#dc2626' : type === 'success' ? '#16a34a' : '#000000'};
        color: white;
        padding: 0.75rem 1rem;
        border-radius: var(--radius);
        margin-bottom: 0.5rem;
        box-shadow: var(--shadow);
        animation: slideIn 0.2s ease;
    `;
    
    toast.innerHTML = `
        <div style="display: flex; align-items: center; gap: 0.5rem;">
            <i class="fas fa-${type === 'error' ? 'exclamation-circle' : type === 'success' ? 'check-circle' : 'info-circle'}"></i>
            <span>${message}</span>
        </div>
    `;
    
    document.getElementById('toastContainer').appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.2s ease';
        setTimeout(() => toast.remove(), 200);
    }, 3000);
}

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('active');
}

function showSection(section) {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    event.target.closest('.nav-item').classList.add('active');
    
    if (section === 'inbox') {
        loadOnlineUsers();
    } else if (section === 'online') {
        loadOnlineUsers();
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    checkAuth();
    
    // Focus search input when modal opens
    document.getElementById('searchModal').addEventListener('shown', function() {
        document.getElementById('searchInput').focus();
    });
    
    // Close search modal on escape
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            hideSearchModal();
        }
    });
});
</script>
</body>
</html>
