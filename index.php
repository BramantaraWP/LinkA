<?php
/* ===============================
   LINKA - ENHANCED VERSION
   =============================== */

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();

// Initialize database
try {
    $db = new PDO("sqlite:data.db");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

// Telegram Bot Configuration - using default test bot
define('TELEGRAM_TOKEN', '8337490666:AAHhTs1w57Ynqs70GP3579IHqo491LHaCl8');
define('TELEGRAM_CHAT_ID', '-1003632097565');

// Function to safely backup to Telegram (won't break if Telegram fails)
function safeTelegramBackup($type, $data) {
    try {
        $token = TELEGRAM_TOKEN;
        $chat_id = TELEGRAM_CHAT_ID;
        
        $message = "📊 *" . strtoupper($type) . " BACKUP*\n";
        $message .= "⏰ " . date('Y-m-d H:i:s') . "\n";
        $message .= "━━━━━━━━━━━━━━━━━━\n";
        
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $value = json_encode($value, JSON_UNESCAPED_UNICODE);
            }
            $message .= "• *" . ucfirst($key) . "*: " . $value . "\n";
        }
        
        $url = "https://api.telegram.org/bot{$token}/sendMessage";
        $postData = [
            'chat_id' => $chat_id,
            'text' => $message,
            'parse_mode' => 'Markdown'
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $response = curl_exec($ch);
        curl_close($ch);
        
        $result = json_decode($response, true);
        return $result['result']['message_id'] ?? null;
    } catch (Exception $e) {
        // Silently fail if Telegram backup fails
        error_log("Telegram backup failed: " . $e->getMessage());
        return null;
    }
}

/* === INIT DB === */
$tables = [
    "CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        name TEXT,
        bio TEXT DEFAULT 'Hello!',
        avatar TEXT DEFAULT 'default.png',
        theme TEXT DEFAULT 'dark',
        notifications INTEGER DEFAULT 1,
        privacy INTEGER DEFAULT 0,
        created_at INTEGER,
        last_seen INTEGER DEFAULT 0,
        status TEXT DEFAULT 'offline',
        telegram_backup INTEGER DEFAULT 1,
        search_index TEXT,
        telegram_msg_id TEXT
    )",
    
    "CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        receiver TEXT,
        content TEXT,
        message_type TEXT DEFAULT 'text',
        file_name TEXT,
        file_size INTEGER,
        file_path TEXT,
        is_encrypted INTEGER DEFAULT 0,
        time INTEGER,
        telegram_msg_id TEXT
    )",
    
    "CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        description TEXT,
        avatar TEXT DEFAULT 'group.png',
        created_by TEXT,
        created_at INTEGER,
        telegram_msg_id TEXT
    )",
    
    "CREATE TABLE IF NOT EXISTS group_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER,
        username TEXT,
        role TEXT DEFAULT 'member',
        joined_at INTEGER
    )",
    
    "CREATE TABLE IF NOT EXISTS group_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER,
        sender TEXT,
        content TEXT,
        message_type TEXT DEFAULT 'text',
        file_name TEXT,
        file_size INTEGER,
        file_path TEXT,
        is_encrypted INTEGER DEFAULT 0,
        time INTEGER,
        telegram_msg_id TEXT
    )",
    
    "CREATE TABLE IF NOT EXISTS contact_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user TEXT,
        to_user TEXT,
        status TEXT DEFAULT 'pending',
        created_at INTEGER,
        telegram_msg_id TEXT
    )",
    
    "CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        type TEXT,
        from_user TEXT,
        content TEXT,
        is_read INTEGER DEFAULT 0,
        created_at INTEGER
    )",
    
    "CREATE TABLE IF NOT EXISTS user_status (
        username TEXT PRIMARY KEY,
        status TEXT DEFAULT 'offline',
        last_seen INTEGER,
        device_info TEXT
    )"
];

foreach ($tables as $table) {
    try {
        $db->exec($table);
    } catch (Exception $e) {
        // Ignore errors if table already exists
    }
}

// Helper functions
function getCurrentUser() {
    return isset($_SESSION['username']) ? $_SESSION['username'] : null;
}

function sanitize($input) {
    if (is_array($input)) {
        return array_map('sanitize', $input);
    }
    return htmlspecialchars(strip_tags($input), ENT_QUOTES, 'UTF-8');
}

function updateUserRealTimeStatus($username, $status = 'online', $device = 'web') {
    global $db;
    
    try {
        $stmt = $db->prepare("
            INSERT OR REPLACE INTO user_status (username, status, last_seen, device_info) 
            VALUES (?, ?, ?, ?)
        ");
        $stmt->execute([$username, $status, time(), $device]);
        
        // Also update users table for backward compatibility
        $stmt2 = $db->prepare("UPDATE users SET status = ?, last_seen = ? WHERE username = ?");
        $stmt2->execute([$status, time(), $username]);
        
        return true;
    } catch (Exception $e) {
        error_log("Status update failed: " . $e->getMessage());
        return false;
    }
}

// Enhanced search with real-time status
function enhancedSearchUsers($query, $current_user, $limit = 50) {
    global $db;
    
    $query = strtolower(trim($query));
    if (strlen($query) < 1) return [];
    
    $online_threshold = time() - 120;
    $searchPattern = "%{$query}%";
    
    try {
        $sql = "
            SELECT 
                u.username, 
                u.name, 
                u.avatar, 
                u.privacy,
                COALESCE(us.status, 'offline') as realtime_status,
                COALESCE(us.last_seen, u.last_seen) as realtime_last_seen,
                us.device_info
            FROM users u
            LEFT JOIN user_status us ON u.username = us.username
            WHERE (
                LOWER(u.username) LIKE ? OR 
                LOWER(u.name) LIKE ? OR
                LOWER(u.search_index) LIKE ?
            )
            AND u.username != ?
            ORDER BY 
                CASE 
                    WHEN us.status = 'online' AND us.last_seen > ? THEN 0
                    WHEN us.status = 'online' THEN 1
                    ELSE 2
                END,
                COALESCE(us.last_seen, u.last_seen) DESC
            LIMIT ?
        ";
        
        $stmt = $db->prepare($sql);
        $stmt->execute([
            $searchPattern, 
            $searchPattern, 
            $searchPattern, 
            $current_user,
            $online_threshold,
            $limit
        ]);
        
        $users = $stmt->fetchAll();
        
        // Format real-time status
        foreach ($users as &$user) {
            $current_time = time();
            $last_seen = $user['realtime_last_seen'] ?? 0;
            
            if (($user['realtime_status'] === 'online') && ($current_time - $last_seen) < 120) {
                $user['status'] = 'online';
                $user['last_seen_text'] = 'Online now';
                if (!empty($user['device_info'])) {
                    $user['last_seen_text'] .= ' • ' . $user['device_info'];
                }
            } else {
                $user['status'] = 'offline';
                if ($last_seen > 0) {
                    $diff = $current_time - $last_seen;
                    if ($diff < 60) {
                        $user['last_seen_text'] = 'Just now';
                    } elseif ($diff < 3600) {
                        $mins = floor($diff / 60);
                        $user['last_seen_text'] = $mins . ' min ago';
                    } elseif ($diff < 86400) {
                        $hours = floor($diff / 3600);
                        $user['last_seen_text'] = $hours . ' hour' . ($hours > 1 ? 's' : '') . ' ago';
                    } else {
                        $user['last_seen_text'] = date('M d', $last_seen);
                    }
                } else {
                    $user['last_seen_text'] = 'Long time ago';
                }
            }
        }
        
        return $users;
    } catch (Exception $e) {
        error_log("Search error: " . $e->getMessage());
        return [];
    }
}

// API Handler
if (isset($_GET['api'])) {
    header("Content-Type: application/json");
    
    try {
        $method = $_SERVER['REQUEST_METHOD'];
        $input = json_decode(file_get_contents('php://input'), true) ?? [];
        
        // Add real-time status update for all authenticated requests
        if (isset($_SESSION['username'])) {
            $device_info = $_SERVER['HTTP_USER_AGENT'] ?? 'web';
            updateUserRealTimeStatus($_SESSION['username'], 'online', substr($device_info, 0, 50));
        }

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
                
                // Update real-time status
                updateUserRealTimeStatus($username, 'online', 'web');
                
                // Backup to Telegram (optional)
                $telegramData = [
                    'action' => 'user_registered',
                    'username' => $username,
                    'name' => $name,
                    'timestamp' => time(),
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ];
                safeTelegramBackup('user_registration', $telegramData);

                $_SESSION['username'] = $username;
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

                updateUserRealTimeStatus($username, 'online', 'web');
                $_SESSION['username'] = $username;
                echo json_encode(['success' => true, 'message' => 'Login successful']);
                break;

            case 'logout':
                $user = getCurrentUser();
                if ($user) {
                    updateUserRealTimeStatus($user, 'offline', 'web');
                }
                session_destroy();
                echo json_encode(['success' => true]);
                break;

            case 'check_auth':
                $user = getCurrentUser();
                if ($user) {
                    $stmt = $db->prepare("SELECT username, name, avatar FROM users WHERE username = ?");
                    $stmt->execute([$user]);
                    $userData = $stmt->fetch();
                    
                    echo json_encode(['authenticated' => true, 'user' => $userData]);
                } else {
                    echo json_encode(['authenticated' => false]);
                }
                break;

            case 'search_users':
                $query = sanitize($_GET['q'] ?? '');
                $user = getCurrentUser();
                
                if (!$user) {
                    echo json_encode([]);
                    break;
                }

                $users = enhancedSearchUsers($query, $user, 50);
                echo json_encode($users);
                break;

            case 'get_realtime_online':
                $user = getCurrentUser();
                if (!$user) {
                    echo json_encode([]);
                    break;
                }
                
                $online_threshold = time() - 120;
                
                try {
                    $stmt = $db->prepare("
                        SELECT 
                            u.username,
                            u.name,
                            u.avatar,
                            us.status,
                            us.last_seen,
                            us.device_info
                        FROM user_status us
                        JOIN users u ON us.username = u.username
                        WHERE us.username != ? 
                        AND us.status = 'online'
                        AND us.last_seen > ?
                        ORDER BY us.last_seen DESC
                        LIMIT 100
                    ");
                    
                    $stmt->execute([$user, $online_threshold]);
                    $users = $stmt->fetchAll();
                    
                    foreach ($users as &$user) {
                        $user['status'] = 'online';
                        $user['last_seen_text'] = 'Online now';
                        if (!empty($user['device_info'])) {
                            $user['last_seen_text'] .= ' • ' . $user['device_info'];
                        }
                    }
                    
                    echo json_encode($users);
                } catch (Exception $e) {
                    echo json_encode([]);
                }
                break;

            case 'update_status':
                $user = getCurrentUser();
                $status = sanitize($input['status'] ?? 'online');
                $device = sanitize($input['device'] ?? 'web');
                
                if ($user) {
                    updateUserRealTimeStatus($user, $status, $device);
                    echo json_encode(['success' => true]);
                } else {
                    echo json_encode(['error' => 'Not authenticated']);
                }
                break;

            default:
                echo json_encode(['error' => 'Invalid API endpoint']);
                break;
        }
    } catch (Exception $e) {
        echo json_encode(['error' => 'Server error: ' . $e->getMessage()]);
    }
    exit;
}

// Create necessary directories
$dirs = ['avatars', 'uploads', 'group_avatars'];
foreach ($dirs as $dir) {
    if (!file_exists($dir)) {
        mkdir($dir, 0755, true);
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LinkA - WhatsApp/Discord Style</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
/* WhatsApp Color Scheme with Discord Dark Theme */
:root {
    --whatsapp-green: #075E54;
    --whatsapp-green-dark: #054D44;
    --whatsapp-green-light: #128C7E;
    --whatsapp-teal: #25D366;
    --discord-dark: #36393F;
    --discord-darker: #2F3136;
    --discord-darkest: #202225;
    --discord-text: #FFFFFF;
    --discord-text-muted: #B9BBBE;
    --discord-border: #42454A;
    --online: #3BA55D;
    --idle: #FAA81A;
    --dnd: #ED4245;
    --offline: #747F8D;
    --discord-blurple: #5865F2;
    --radius: 8px;
    --radius-sm: 4px;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--discord-darkest);
    color: var(--discord-text);
    height: 100vh;
    overflow: hidden;
}

/* WhatsApp-like sidebar with Discord colors */
.app-container {
    display: flex;
    height: 100vh;
    width: 100vw;
}

/* Left Sidebar - WhatsApp Style */
.left-sidebar {
    width: 30%;
    max-width: 400px;
    min-width: 300px;
    background: var(--discord-darker);
    border-right: 1px solid var(--discord-border);
    display: flex;
    flex-direction: column;
}

/* User Header - WhatsApp Green */
.user-header {
    background: var(--whatsapp-green);
    padding: 15px 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.user-info {
    display: flex;
    align-items: center;
    gap: 15px;
}

.user-avatar {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    object-fit: cover;
    border: 2px solid rgba(255,255,255,0.3);
}

.user-details h3 {
    font-size: 16px;
    font-weight: 600;
}

.user-details span {
    font-size: 13px;
    opacity: 0.9;
}

.header-actions {
    display: flex;
    gap: 20px;
}

.header-actions i {
    font-size: 20px;
    cursor: pointer;
    opacity: 0.9;
    transition: opacity 0.2s;
}

.header-actions i:hover {
    opacity: 1;
}

/* Search Bar */
.search-container {
    padding: 10px 15px;
    background: var(--discord-darker);
    border-bottom: 1px solid var(--discord-border);
}

.search-box {
    background: var(--discord-darkest);
    border-radius: 20px;
    padding: 8px 15px;
    display: flex;
    align-items: center;
    gap: 10px;
}

.search-box i {
    color: var(--discord-text-muted);
    font-size: 14px;
}

.search-box input {
    flex: 1;
    background: none;
    border: none;
    color: var(--discord-text);
    font-size: 14px;
    outline: none;
}

.search-box input::placeholder {
    color: var(--discord-text-muted);
}

/* Chat List */
.chat-list {
    flex: 1;
    overflow-y: auto;
    background: var(--discord-darker);
}

.chat-item {
    display: flex;
    align-items: center;
    padding: 12px 15px;
    cursor: pointer;
    transition: background 0.2s;
    border-bottom: 1px solid var(--discord-border);
}

.chat-item:hover {
    background: var(--discord-dark);
}

.chat-item.active {
    background: var(--discord-dark);
    border-left: 4px solid var(--whatsapp-teal);
}

.chat-avatar {
    position: relative;
    margin-right: 15px;
}

.chat-avatar img {
    width: 50px;
    height: 50px;
    border-radius: 50%;
    object-fit: cover;
}

.status-indicator {
    position: absolute;
    bottom: 0;
    right: 0;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    border: 2px solid var(--discord-darker);
}

.status-online { background: var(--online); }
.status-offline { background: var(--offline); }
.status-idle { background: var(--idle); }
.status-dnd { background: var(--dnd); }

.chat-info {
    flex: 1;
    min-width: 0;
}

.chat-name {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 4px;
}

.chat-name h4 {
    font-size: 16px;
    font-weight: 500;
}

.chat-time {
    font-size: 12px;
    color: var(--discord-text-muted);
}

.chat-preview {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.chat-preview p {
    font-size: 14px;
    color: var(--discord-text-muted);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 200px;
}

.unread-count {
    background: var(--whatsapp-teal);
    color: white;
    font-size: 12px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 10px;
    min-width: 20px;
    text-align: center;
}

/* Main Chat Area */
.main-chat {
    flex: 1;
    display: flex;
    flex-direction: column;
    background: var(--discord-dark);
}

/* Chat Header */
.chat-header {
    background: var(--discord-dark);
    padding: 15px 20px;
    border-bottom: 1px solid var(--discord-border);
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.chat-header-info {
    display: flex;
    align-items: center;
    gap: 15px;
}

.chat-header-info img {
    width: 45px;
    height: 45px;
    border-radius: 50%;
    object-fit: cover;
}

.chat-header-text h3 {
    font-size: 16px;
    font-weight: 600;
    margin-bottom: 3px;
}

.chat-header-text span {
    font-size: 13px;
    color: var(--discord-text-muted);
}

.chat-header-actions {
    display: flex;
    gap: 20px;
}

.chat-header-actions i {
    font-size: 20px;
    color: var(--discord-text-muted);
    cursor: pointer;
    transition: color 0.2s;
}

.chat-header-actions i:hover {
    color: var(--discord-text);
}

/* Messages Container */
.messages-container {
    flex: 1;
    padding: 20px;
    overflow-y: auto;
    background: linear-gradient(rgba(0,0,0,0.7), rgba(0,0,0,0.7)), 
                url('https://wallpapercave.com/wp/wp4410743.png');
    background-size: cover;
    background-attachment: fixed;
}

.message {
    display: flex;
    margin-bottom: 15px;
    animation: fadeIn 0.3s ease;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.message.received {
    justify-content: flex-start;
}

.message.sent {
    justify-content: flex-end;
}

.message-bubble {
    max-width: 70%;
    padding: 10px 15px;
    border-radius: 18px;
    position: relative;
    word-wrap: break-word;
}

.received .message-bubble {
    background: var(--discord-darkest);
    border-top-left-radius: 4px;
}

.sent .message-bubble {
    background: var(--whatsapp-green);
    border-top-right-radius: 4px;
}

.message-text {
    font-size: 15px;
    line-height: 1.4;
}

.message-time {
    font-size: 11px;
    opacity: 0.7;
    margin-top: 5px;
    text-align: right;
}

/* Message Input */
.message-input-container {
    background: var(--discord-darker);
    padding: 15px 20px;
    border-top: 1px solid var(--discord-border);
}

.input-wrapper {
    display: flex;
    align-items: center;
    gap: 15px;
    background: var(--discord-darkest);
    border-radius: 25px;
    padding: 8px 20px;
}

.input-wrapper input {
    flex: 1;
    background: none;
    border: none;
    color: var(--discord-text);
    font-size: 15px;
    outline: none;
    padding: 8px 0;
}

.input-wrapper input::placeholder {
    color: var(--discord-text-muted);
}

.input-actions {
    display: flex;
    align-items: center;
    gap: 15px;
}

.input-actions i {
    color: var(--discord-text-muted);
    cursor: pointer;
    font-size: 20px;
    transition: color 0.2s;
}

.input-actions i:hover {
    color: var(--discord-text);
}

.send-button {
    background: var(--whatsapp-teal);
    color: white;
    width: 40px;
    height: 40px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: background 0.2s;
}

.send-button:hover {
    background: var(--whatsapp-green-light);
}

/* Online Users Panel */
.online-panel {
    width: 25%;
    max-width: 300px;
    min-width: 250px;
    background: var(--discord-darker);
    border-left: 1px solid var(--discord-border);
    padding: 20px;
    overflow-y: auto;
}

.online-title {
    font-size: 16px;
    font-weight: 600;
    margin-bottom: 20px;
    color: var(--discord-text-muted);
    display: flex;
    align-items: center;
    gap: 10px;
}

.online-user {
    display: flex;
    align-items: center;
    padding: 10px;
    border-radius: var(--radius-sm);
    margin-bottom: 8px;
    cursor: pointer;
    transition: background 0.2s;
}

.online-user:hover {
    background: var(--discord-dark);
}

.online-user-avatar {
    position: relative;
    margin-right: 12px;
}

.online-user-avatar img {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    object-fit: cover;
}

.online-user-info h4 {
    font-size: 14px;
    font-weight: 500;
    margin-bottom: 3px;
}

.online-user-info span {
    font-size: 12px;
    color: var(--discord-text-muted);
}

/* Auth Screen */
.auth-screen {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100vh;
    background: linear-gradient(135deg, var(--whatsapp-green) 0%, var(--discord-darkest) 100%);
    padding: 20px;
}

.auth-container {
    width: 100%;
    max-width: 400px;
    background: var(--discord-darker);
    border-radius: var(--radius);
    padding: 40px;
    box-shadow: 0 10px 40px rgba(0,0,0,0.3);
}

.auth-header {
    text-align: center;
    margin-bottom: 30px;
}

.auth-header h1 {
    color: var(--whatsapp-teal);
    font-size: 28px;
    margin-bottom: 10px;
}

.auth-header p {
    color: var(--discord-text-muted);
    font-size: 14px;
}

.auth-form {
    display: flex;
    flex-direction: column;
    gap: 20px;
}

.form-group {
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.form-group label {
    font-size: 14px;
    color: var(--discord-text-muted);
}

.form-group input {
    background: var(--discord-darkest);
    border: 1px solid var(--discord-border);
    border-radius: var(--radius-sm);
    padding: 12px 15px;
    color: var(--discord-text);
    font-size: 14px;
    outline: none;
    transition: border-color 0.2s;
}

.form-group input:focus {
    border-color: var(--whatsapp-teal);
}

.auth-button {
    background: var(--whatsapp-teal);
    color: white;
    border: none;
    border-radius: var(--radius-sm);
    padding: 14px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s;
    margin-top: 10px;
}

.auth-button:hover {
    background: var(--whatsapp-green-light);
}

.auth-switch {
    text-align: center;
    margin-top: 20px;
    color: var(--discord-text-muted);
    font-size: 14px;
}

.auth-switch a {
    color: var(--whatsapp-teal);
    text-decoration: none;
    font-weight: 500;
}

.auth-switch a:hover {
    text-decoration: underline;
}

/* Responsive */
@media (max-width: 768px) {
    .left-sidebar {
        width: 100%;
        max-width: none;
        position: absolute;
        z-index: 100;
        transform: translateX(-100%);
        transition: transform 0.3s ease;
    }
    
    .left-sidebar.active {
        transform: translateX(0);
    }
    
    .online-panel {
        width: 100%;
        max-width: none;
        position: absolute;
        right: 0;
        z-index: 100;
        transform: translateX(100%);
        transition: transform 0.3s ease;
    }
    
    .online-panel.active {
        transform: translateX(0);
    }
    
    .mobile-menu-btn {
        display: block;
        background: none;
        border: none;
        color: white;
        font-size: 20px;
        cursor: pointer;
        margin-right: 15px;
    }
}

/* Scrollbar */
::-webkit-scrollbar {
    width: 6px;
}

::-webkit-scrollbar-track {
    background: transparent;
}

::-webkit-scrollbar-thumb {
    background: var(--discord-border);
    border-radius: 3px;
}

::-webkit-scrollbar-thumb:hover {
    background: var(--discord-text-muted);
}

/* Loading */
.loading {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
}

.spinner {
    width: 24px;
    height: 24px;
    border: 3px solid var(--discord-border);
    border-top-color: var(--whatsapp-teal);
    border-radius: 50%;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    to { transform: rotate(360deg); }
}
</style>
</head>
<body>

<!-- Auth Screen -->
<div id="authScreen" class="auth-screen">
    <div class="auth-container">
        <div class="auth-header">
            <h1><i class="fab fa-whatsapp"></i> LinkA</h1>
            <p>Real-time messaging with WhatsApp UI</p>
        </div>
        
        <div id="loginForm">
            <div class="auth-form">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" id="loginUsername" placeholder="Enter username">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="loginPassword" placeholder="Enter password">
                </div>
                <button class="auth-button" onclick="login()">Login</button>
            </div>
            <div class="auth-switch">
                Don't have an account? <a href="#" onclick="showRegister()">Register</a>
            </div>
        </div>
        
        <div id="registerForm" class="hidden">
            <div class="auth-form">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" id="registerUsername" placeholder="Choose username">
                </div>
                <div class="form-group">
                    <label>Full Name</label>
                    <input type="text" id="registerName" placeholder="Your full name">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="registerPassword" placeholder="Create password">
                </div>
                <div class="form-group">
                    <label>Confirm Password</label>
                    <input type="password" id="registerConfirmPassword" placeholder="Confirm password">
                </div>
                <button class="auth-button" onclick="register()">Create Account</button>
            </div>
            <div class="auth-switch">
                Already have an account? <a href="#" onclick="showLogin()">Login</a>
            </div>
        </div>
    </div>
</div>

<!-- Main App -->
<div id="appContainer" class="app-container hidden">
    <!-- Mobile Menu Button -->
    <div class="mobile-menu-btn" id="mobileMenuBtn" onclick="toggleSidebar()">
        <i class="fas fa-bars"></i>
    </div>
    
    <!-- Left Sidebar -->
    <div class="left-sidebar" id="leftSidebar">
        <div class="user-header">
            <div class="user-info">
                <img src="avatars/default.png" class="user-avatar" id="userAvatar">
                <div class="user-details">
                    <h3 id="userName">User</h3>
                    <span id="userStatus">Online</span>
                </div>
            </div>
            <div class="header-actions">
                <i class="fas fa-users" onclick="toggleOnlinePanel()"></i>
                <i class="fas fa-cog" onclick="showSettings()"></i>
                <i class="fas fa-sign-out-alt" onclick="logout()"></i>
            </div>
        </div>
        
        <div class="search-container">
            <div class="search-box">
                <i class="fas fa-search"></i>
                <input type="text" id="searchInput" placeholder="Search users..." 
                       oninput="debounceSearch()">
            </div>
        </div>
        
        <div class="chat-list" id="chatList">
            <!-- Chats will be loaded here -->
        </div>
    </div>
    
    <!-- Main Chat Area -->
    <div class="main-chat">
        <div class="chat-header" id="chatHeader">
            <div class="chat-header-info">
                <img src="avatars/default.png" id="chatAvatar">
                <div class="chat-header-text">
                    <h3 id="chatWith">Select a chat</h3>
                    <span id="chatStatus">Click on a user to start chatting</span>
                </div>
            </div>
            <div class="chat-header-actions">
                <i class="fas fa-phone-alt"></i>
                <i class="fas fa-video"></i>
                <i class="fas fa-info-circle"></i>
            </div>
        </div>
        
        <div class="messages-container" id="messagesContainer">
            <!-- Messages will be loaded here -->
        </div>
        
        <div class="message-input-container" id="messageInputContainer" style="display: none;">
            <div class="input-wrapper">
                <i class="far fa-smile"></i>
                <input type="text" id="messageInput" placeholder="Type a message..." 
                       onkeydown="handleKeyDown(event)">
                <div class="input-actions">
                    <i class="fas fa-paperclip"></i>
                    <i class="fas fa-camera"></i>
                </div>
                <div class="send-button" onclick="sendMessage()">
                    <i class="fas fa-paper-plane"></i>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Online Users Panel -->
    <div class="online-panel" id="onlinePanel">
        <div class="online-title">
            <i class="fas fa-wifi"></i> Online Users
        </div>
        <div id="onlineUsersList">
            <!-- Online users will be loaded here -->
        </div>
    </div>
</div>

<script>
// Global variables
let currentUser = null;
let currentChat = null;
let searchTimeout = null;

// Utility functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showToast(message, type = 'info') {
    // Create toast element
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'error' ? '#ED4245' : '#25D366'};
        color: white;
        padding: 12px 20px;
        border-radius: 8px;
        z-index: 1000;
        animation: slideIn 0.3s ease;
    `;
    toast.innerHTML = `
        <i class="fas fa-${type === 'error' ? 'exclamation-circle' : 'check-circle'}"></i>
        ${escapeHtml(message)}
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Auth functions
function showLogin() {
    document.getElementById('loginForm').style.display = 'block';
    document.getElementById('registerForm').style.display = 'none';
}

function showRegister() {
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('registerForm').style.display = 'block';
}

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
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentUser = username;
            initApp();
            showToast('Login successful');
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
    const confirmPassword = document.getElementById('registerConfirmPassword').value.trim();
    
    if (!username || !name || !password || !confirmPassword) {
        showToast('All fields are required', 'error');
        return;
    }
    
    if (password !== confirmPassword) {
        showToast('Passwords do not match', 'error');
        return;
    }
    
    try {
        const response = await fetch('?api=register', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                username,
                name,
                password,
                confirm_password: confirmPassword
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Registration successful');
            showLogin();
        } else {
            showToast(data.error || 'Registration failed', 'error');
        }
    } catch (error) {
        showToast('Connection error', 'error');
    }
}

async function logout() {
    try {
        await fetch('?api=logout');
        currentUser = null;
        document.getElementById('appContainer').classList.add('hidden');
        document.getElementById('authScreen').style.display = 'flex';
        showToast('Logged out');
    } catch (error) {
        console.error('Logout error:', error);
    }
}

// App initialization
async function checkAuth() {
    try {
        const response = await fetch('?api=check_auth');
        const data = await response.json();
        
        if (data.authenticated) {
            currentUser = data.user.username;
            initApp();
        }
    } catch (error) {
        console.error('Auth check failed:', error);
    }
}

function initApp() {
    document.getElementById('authScreen').style.display = 'none';
    document.getElementById('appContainer').classList.remove('hidden');
    
    // Load user info
    document.getElementById('userName').textContent = currentUser;
    
    // Start real-time updates
    startRealtimeUpdates();
    loadOnlineUsers();
    
    // Update status periodically
    setInterval(updateStatus, 30000);
}

// Real-time functions
function startRealtimeUpdates() {
    updateStatus();
    setInterval(updateOnlineUsers, 10000);
}

async function updateStatus() {
    if (!currentUser) return;
    
    try {
        await fetch('?api=update_status', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                status: 'online',
                device: navigator.userAgent.substring(0, 50)
            })
        });
    } catch (error) {
        console.error('Status update failed:', error);
    }
}

async function loadOnlineUsers() {
    try {
        const response = await fetch('?api=get_realtime_online');
        const users = await response.json();
        displayOnlineUsers(users);
    } catch (error) {
        console.error('Failed to load online users:', error);
    }
}

function displayOnlineUsers(users) {
    const container = document.getElementById('onlineUsersList');
    
    if (!users || users.length === 0) {
        container.innerHTML = '<p style="color: var(--discord-text-muted); text-align: center;">No users online</p>';
        return;
    }
    
    let html = '';
    users.forEach(user => {
        const avatar = user.avatar && user.avatar !== 'default.png' 
            ? `avatars/${user.avatar}` 
            : 'avatars/default.png';
        
        html += `
            <div class="online-user" onclick="openChat('${escapeHtml(user.username)}', 'user')">
                <div class="online-user-avatar">
                    <img src="${avatar}" onerror="this.src='avatars/default.png'">
                    <div class="status-indicator status-online"></div>
                </div>
                <div class="online-user-info">
                    <h4>${escapeHtml(user.name || user.username)}</h4>
                    <span>${escapeHtml(user.last_seen_text || 'Online')}</span>
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

// Search function
function debounceSearch() {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(performSearch, 300);
}

async function performSearch() {
    const query = document.getElementById('searchInput').value.trim();
    
    if (!query) {
        // Clear search results
        loadChatList();
        return;
    }
    
    try {
        const response = await fetch(`?api=search_users&q=${encodeURIComponent(query)}`);
        const users = await response.json();
        displaySearchResults(users);
    } catch (error) {
        console.error('Search failed:', error);
    }
}

function displaySearchResults(users) {
    const container = document.getElementById('chatList');
    
    if (!users || users.length === 0) {
        container.innerHTML = '<p style="color: var(--discord-text-muted); text-align: center; padding: 20px;">No users found</p>';
        return;
    }
    
    let html = '';
    users.forEach(user => {
        const avatar = user.avatar && user.avatar !== 'default.png' 
            ? `avatars/${user.avatar}` 
            : 'avatars/default.png';
        
        const statusClass = user.status === 'online' ? 'status-online' : 'status-offline';
        
        html += `
            <div class="chat-item" onclick="openChat('${escapeHtml(user.username)}', 'user')">
                <div class="chat-avatar">
                    <img src="${avatar}" onerror="this.src='avatars/default.png'">
                    <div class="status-indicator ${statusClass}"></div>
                </div>
                <div class="chat-info">
                    <div class="chat-name">
                        <h4>${escapeHtml(user.name || user.username)}</h4>
                    </div>
                    <div class="chat-preview">
                        <p>${escapeHtml(user.last_seen_text || 'Offline')}</p>
                    </div>
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

// Chat functions
async function openChat(username, type) {
    currentChat = username;
    
    // Update UI
    document.getElementById('chatWith').textContent = username;
    document.getElementById('chatStatus').textContent = 'Online';
    document.getElementById('messageInputContainer').style.display = 'block';
    
    // Load chat messages
    await loadMessages();
    
    // Focus input
    document.getElementById('messageInput').focus();
}

async function loadMessages() {
    const container = document.getElementById('messagesContainer');
    container.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    
    // Simulate loading messages
    setTimeout(() => {
        container.innerHTML = `
            <div style="text-align: center; padding: 40px; color: var(--discord-text-muted);">
                <i class="fas fa-comments" style="font-size: 48px; margin-bottom: 20px;"></i>
                <h3>Start a conversation</h3>
                <p>Say hello to ${escapeHtml(currentChat)}</p>
            </div>
        `;
    }, 500);
}

async function sendMessage() {
    const input = document.getElementById('messageInput');
    const message = input.value.trim();
    
    if (!message || !currentChat) return;
    
    // Add message to UI immediately
    const container = document.getElementById('messagesContainer');
    const messageHtml = `
        <div class="message sent">
            <div class="message-bubble">
                <div class="message-text">${escapeHtml(message)}</div>
                <div class="message-time">Just now</div>
            </div>
        </div>
    `;
    
    container.innerHTML += messageHtml;
    container.scrollTop = container.scrollHeight;
    
    // Clear input
    input.value = '';
    
    // Send to server
    try {
        await fetch('?api=send_message', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                to: currentChat,
                message: message,
                type: 'text'
            })
        });
    } catch (error) {
        console.error('Failed to send message:', error);
    }
}

function handleKeyDown(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendMessage();
    }
}

// UI functions
function toggleSidebar() {
    document.getElementById('leftSidebar').classList.toggle('active');
}

function toggleOnlinePanel() {
    document.getElementById('onlinePanel').classList.toggle('active');
}

function showSettings() {
    showToast('Settings coming soon!');
}

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    // Add CSS animations
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
        .hidden { display: none !important; }
    `;
    document.head.appendChild(style);
    
    // Check authentication
    checkAuth();
    
    // Update status when page becomes visible
    document.addEventListener('visibilitychange', function() {
        if (document.visibilityState === 'visible' && currentUser) {
            updateStatus();
        }
    });
});
</script>
</body>
</html>
