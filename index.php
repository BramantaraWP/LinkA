<?php
/* ===============================
   LINKA - ULTIMATE VERSION - FIXED
   =============================== */

// Anti Debugger
if (function_exists('xdebug_disable')) { xdebug_disable(); }
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Security Headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

session_start();

// CSRF Protection
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Database connection dengan path absolut yang lebih aman
try {
    $db_path = dirname(__FILE__) . '/data.db';
    $db = new PDO("sqlite:" . $db_path);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec("PRAGMA journal_mode=WAL;");
    $db->exec("PRAGMA synchronous=NORMAL;");
} catch(PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

// Telegram Bot Configuration
define('TELEGRAM_TOKEN', '8337490666:AAHhTs1w57Ynqs70GP3579IHqo491LHaCl8');
define('TELEGRAM_CHAT_ID', '-1003632097565');

/* === INIT DB === */
$db->exec("
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    bio TEXT DEFAULT 'Hello! I''m using LinkA',
    avatar TEXT DEFAULT 'default.png',
    theme TEXT DEFAULT 'dark',
    notifications INTEGER DEFAULT 1,
    privacy INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_seen INTEGER DEFAULT 0,
    status TEXT DEFAULT 'offline',
    telegram_backup INTEGER DEFAULT 1,
    search_index TEXT,
    session_token TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT UNIQUE,
    sender_id INTEGER,
    receiver_id INTEGER,
    content TEXT,
    message_type TEXT DEFAULT 'text',
    file_name TEXT,
    file_size INTEGER,
    time INTEGER NOT NULL,
    is_read INTEGER DEFAULT 0,
    FOREIGN KEY (sender_id) REFERENCES users(user_id),
    FOREIGN KEY (receiver_id) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS groups (
    group_id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_code TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    avatar TEXT DEFAULT 'group.png',
    created_by INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    is_public INTEGER DEFAULT 0,
    FOREIGN KEY (created_by) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS group_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER,
    user_id INTEGER,
    role TEXT DEFAULT 'member',
    joined_at INTEGER NOT NULL,
    FOREIGN KEY (group_id) REFERENCES groups(group_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    UNIQUE(group_id, user_id)
);

CREATE TABLE IF NOT EXISTS group_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER,
    sender_id INTEGER,
    content TEXT,
    message_type TEXT DEFAULT 'text',
    file_name TEXT,
    file_size INTEGER,
    time INTEGER NOT NULL,
    FOREIGN KEY (group_id) REFERENCES groups(group_id),
    FOREIGN KEY (sender_id) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS contact_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_id INTEGER,
    to_id INTEGER,
    status TEXT DEFAULT 'pending',
    created_at INTEGER NOT NULL,
    FOREIGN KEY (from_id) REFERENCES users(user_id),
    FOREIGN KEY (to_id) REFERENCES users(user_id),
    UNIQUE(from_id, to_id)
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    type TEXT NOT NULL,
    from_id INTEGER,
    content TEXT,
    is_read INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (from_id) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS user_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE,
    theme TEXT DEFAULT 'dark',
    notifications INTEGER DEFAULT 1,
    sound INTEGER DEFAULT 1,
    privacy INTEGER DEFAULT 0,
    last_backup INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_search ON users(search_index);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id);
CREATE INDEX IF NOT EXISTS idx_messages_time ON messages(time);
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);
CREATE INDEX IF NOT EXISTS idx_group_members_group ON group_members(group_id);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
");

// Update existing tables if needed (HAPUS baris ALTER TABLE untuk user_id)
$updates = [
    "ALTER TABLE users ADD COLUMN session_token TEXT",
    "ALTER TABLE messages ADD COLUMN message_id TEXT UNIQUE",
    "ALTER TABLE messages ADD COLUMN is_read INTEGER DEFAULT 0",
    "ALTER TABLE groups ADD COLUMN group_code TEXT UNIQUE NOT NULL DEFAULT ''",
    "ALTER TABLE groups ADD COLUMN is_public INTEGER DEFAULT 0",
    "ALTER TABLE contact_requests ADD COLUMN from_id INTEGER",
    "ALTER TABLE contact_requests ADD COLUMN to_id INTEGER"
];

foreach ($updates as $update) {
    try { 
        $db->exec($update); 
    } catch(Exception $e) { 
        // Ignore error jika kolom sudah ada
    }
}

/* === SECURITY FUNCTIONS === */
function sanitize($input) {
    if (is_array($input)) {
        return array_map('sanitize', $input);
    }
    
    // Remove null bytes
    $input = str_replace(chr(0), '', $input);
    
    // Strip tags but preserve basic formatting
    $allowed_tags = '<b><i><u><strong><em><code><pre><br><p>';
    $input = strip_tags($input, $allowed_tags);
    
    // Convert special characters
    $input = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    
    // Remove excessive whitespace
    $input = preg_replace('/\s+/', ' ', $input);
    
    return trim($input);
}

function validate_csrf() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!hash_equals($_SESSION['csrf_token'], $token)) {
            http_response_code(403);
            die('CSRF validation failed');
        }
    }
}

function generate_id($type = 'message') {
    $prefix = match($type) {
        'message' => 'msg_',
        'group' => 'grp_',
        'user' => 'usr_',
        default => 'id_'
    };
    
    return $prefix . bin2hex(random_bytes(8)) . '_' . time();
}

function compress_image($source, $destination, $quality = 10) {
    // Fallback jika GD tidak tersedia
    if (!function_exists('gd_info')) {
        return copy($source, $destination);
    }
    
    $info = getimagesize($source);
    if (!$info) return false;
    
    $image = match($info[2]) {
        IMAGETYPE_JPEG => imagecreatefromjpeg($source),
        IMAGETYPE_PNG => imagecreatefrompng($source),
        IMAGETYPE_GIF => imagecreatefromgif($source),
        IMAGETYPE_WEBP => imagecreatefromwebp($source),
        default => false
    };
    
    if (!$image) return false;
    
    $width = imagesx($image);
    $height = imagesy($image);
    $newWidth = ceil($width * ($quality / 100));
    $newHeight = ceil($height * ($quality / 100));
    
    $compressed = imagecreatetruecolor($newWidth, $newHeight);
    
    if ($info[2] == IMAGETYPE_PNG || $info[2] == IMAGETYPE_GIF) {
        imagecolortransparent($compressed, imagecolorallocatealpha($compressed, 0, 0, 0, 127));
        imagealphablending($compressed, false);
        imagesavealpha($compressed, true);
    }
    
    imagecopyresampled($compressed, $image, 0, 0, 0, 0, $newWidth, $newHeight, $width, $height);
    
    $result = match($info[2]) {
        IMAGETYPE_JPEG => imagejpeg($compressed, $destination, 85),
        IMAGETYPE_PNG => imagepng($compressed, $destination, 8),
        IMAGETYPE_GIF => imagegif($compressed, $destination),
        IMAGETYPE_WEBP => imagewebp($compressed, $destination, 85),
        default => false
    };
    
    imagedestroy($image);
    imagedestroy($compressed);
    
    return $result;
}

/* === HELPER FUNCTIONS === */
function get_current_user() {
    if (!isset($_SESSION['user_id'])) return null;
    
    global $db;
    $stmt = $db->prepare("SELECT user_id, username, session_token FROM users WHERE user_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();
    
    if (!$user || $user['session_token'] !== ($_SESSION['session_token'] ?? '')) {
        session_destroy();
        return null;
    }
    
    return $user;
}

function update_user_status($user_id, $status = 'online') {
    global $db;
    $stmt = $db->prepare("UPDATE users SET status = ?, last_seen = ? WHERE user_id = ?");
    $stmt->execute([$status, time(), $user_id]);
}

function get_user_by_id($user_id) {
    global $db;
    $stmt = $db->prepare("SELECT user_id, username, name, avatar, bio, status, last_seen FROM users WHERE user_id = ?");
    $stmt->execute([$user_id]);
    return $stmt->fetch();
}

function get_user_by_username($username) {
    global $db;
    $stmt = $db->prepare("SELECT user_id, username, name, avatar, bio, status, last_seen FROM users WHERE username = ?");
    $stmt->execute([$username]);
    return $stmt->fetch();
}

/* === API HANDLER === */
if (isset($_GET['api']) && is_string($_GET['api'])) {
    header("Content-Type: application/json");
    validate_csrf();
    
    $method = $_SERVER['REQUEST_METHOD'];
    $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
    $current_user = get_current_user();

    switch ($_GET['api']) {
        case 'register':
            $username = sanitize($input['username'] ?? '');
            $password = $input['password'] ?? '';
            $name = sanitize($input['name'] ?? '');
            
            if (empty($username) || empty($password) || empty($name)) {
                echo json_encode(['error' => 'All fields are required']);
                break;
            }
            
            if (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
                echo json_encode(['error' => 'Username must be 3-20 characters (letters, numbers, underscore)']);
                break;
            }
            
            if (strlen($password) < 6) {
                echo json_encode(['error' => 'Password must be at least 6 characters']);
                break;
            }
            
            // Check if username exists
            $stmt = $db->prepare("SELECT user_id FROM users WHERE username = ?");
            $stmt->execute([$username]);
            if ($stmt->fetch()) {
                echo json_encode(['error' => 'Username already exists']);
                break;
            }
            
            // Create user
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $session_token = bin2hex(random_bytes(32));
            $search_index = strtolower($username . ' ' . str_replace(' ', '', $name));
            
            $stmt = $db->prepare("INSERT INTO users (username, password, name, created_at, last_seen, status, session_token, search_index) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$username, $hashed_password, $name, time(), time(), 'online', $session_token, $search_index]);
            
            $user_id = $db->lastInsertId();
            
            // Create default settings
            $stmt = $db->prepare("INSERT INTO user_settings (user_id) VALUES (?)");
            $stmt->execute([$user_id]);
            
            $_SESSION['user_id'] = $user_id;
            $_SESSION['session_token'] = $session_token;
            
            echo json_encode(['success' => true, 'user_id' => $user_id]);
            break;

        case 'login':
            $username = sanitize($input['username'] ?? '');
            $password = $input['password'] ?? '';
            
            if (empty($username) || empty($password)) {
                echo json_encode(['error' => 'Username and password are required']);
                break;
            }
            
            $stmt = $db->prepare("SELECT user_id, username, password, session_token FROM users WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch();
            
            if (!$user || !password_verify($password, $user['password'])) {
                echo json_encode(['error' => 'Invalid credentials']);
                break;
            }
            
            // Update session token
            $new_token = bin2hex(random_bytes(32));
            $stmt = $db->prepare("UPDATE users SET session_token = ?, last_seen = ?, status = 'online' WHERE user_id = ?");
            $stmt->execute([$new_token, time(), $user['user_id']]);
            
            $_SESSION['user_id'] = $user['user_id'];
            $_SESSION['session_token'] = $new_token;
            
            echo json_encode(['success' => true, 'user_id' => $user['user_id']]);
            break;

        case 'logout':
            if ($current_user) {
                update_user_status($current_user['user_id'], 'offline');
            }
            session_destroy();
            echo json_encode(['success' => true]);
            break;

        case 'check_auth':
            echo json_encode(['authenticated' => !is_null($current_user)]);
            break;

        case 'get_profile':
            $user_id = $input['user_id'] ?? $current_user['user_id'] ?? null;
            if (!$user_id) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }
            
            $stmt = $db->prepare("
                SELECT u.user_id, u.username, u.name, u.bio, u.avatar, u.created_at, u.last_seen, u.status,
                       us.theme, us.notifications, us.sound, us.privacy
                FROM users u
                LEFT JOIN user_settings us ON u.user_id = us.user_id
                WHERE u.user_id = ?
            ");
            $stmt->execute([$user_id]);
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
                
                $profile['created_date'] = date('Y-m-d', $profile['created_at']);
            }
            
            echo json_encode($profile ?: []);
            break;

        case 'update_profile':
            if (!$current_user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }
            
            $name = sanitize($input['name'] ?? '');
            $bio = sanitize($input['bio'] ?? '');
            
            $stmt = $db->prepare("UPDATE users SET name = ?, bio = ? WHERE user_id = ?");
            $stmt->execute([$name, $bio, $current_user['user_id']]);
            
            // Update search index
            $search_index = strtolower($current_user['username'] . ' ' . str_replace(' ', '', $name));
            $stmt = $db->prepare("UPDATE users SET search_index = ? WHERE user_id = ?");
            $stmt->execute([$search_index, $current_user['user_id']]);
            
            echo json_encode(['success' => true]);
            break;

        case 'update_avatar':
            if (!$current_user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }
            
            if (isset($_FILES['avatar'])) {
                $file = $_FILES['avatar'];
                $allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
                
                if (!in_array($file['type'], $allowed_types)) {
                    echo json_encode(['error' => 'Invalid image type']);
                    break;
                }
                
                if ($file['size'] > 5 * 1024 * 1024) {
                    echo json_encode(['error' => 'Image too large (max 5MB)']);
                    break;
                }
                
                $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
                $filename = 'avatar_' . $current_user['user_id'] . '_' . time() . '.' . $extension;
                
                if (!file_exists('avatars')) mkdir('avatars', 0755, true);
                
                // Save original
                move_uploaded_file($file['tmp_name'], 'avatars/' . $filename);
                
                // Create compressed version jika GD tersedia
                $compressed_filename = 'avatar_' . $current_user['user_id'] . '_' . time() . '_compressed.' . $extension;
                if (function_exists('gd_info')) {
                    compress_image('avatars/' . $filename, 'avatars/' . $compressed_filename, 10);
                    // Update database dengan compressed version
                    $stmt = $db->prepare("UPDATE users SET avatar = ? WHERE user_id = ?");
                    $stmt->execute([$compressed_filename, $current_user['user_id']]);
                } else {
                    // Kalau GD tidak tersedia, pakai original
                    $stmt = $db->prepare("UPDATE users SET avatar = ? WHERE user_id = ?");
                    $stmt->execute([$filename, $current_user['user_id']]);
                }
                
                echo json_encode(['success' => true, 'avatar' => function_exists('gd_info') ? $compressed_filename : $filename]);
            } else {
                echo json_encode(['error' => 'No file uploaded']);
            }
            break;

        case 'update_settings':
            if (!$current_user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }
            
            $theme = sanitize($input['theme'] ?? 'dark');
            $notifications = intval($input['notifications'] ?? 1);
            $sound = intval($input['sound'] ?? 1);
            $privacy = intval($input['privacy'] ?? 0);
            
            $stmt = $db->prepare("
                INSERT OR REPLACE INTO user_settings (user_id, theme, notifications, sound, privacy) 
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->execute([$current_user['user_id'], $theme, $notifications, $sound, $privacy]);
            
            echo json_encode(['success' => true]);
            break;

        case 'search_users':
            if (!$current_user) {
                echo json_encode([]);
                break;
            }
            
            $query = sanitize($_GET['q'] ?? '');
            if (strlen($query) < 2) {
                echo json_encode([]);
                break;
            }
            
            $search = '%' . strtolower($query) . '%';
            $stmt = $db->prepare("
                SELECT user_id, username, name, avatar, status, last_seen
                FROM users 
                WHERE (username LIKE ? OR name LIKE ? OR search_index LIKE ?) 
                AND user_id != ?
                ORDER BY 
                    CASE WHEN status = 'online' THEN 1 ELSE 2 END,
                    last_seen DESC
                LIMIT 20
            ");
            $stmt->execute([$search, $search, $search, $current_user['user_id']]);
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $current_time = time();
            foreach ($users as &$user) {
                if ($current_time - $user['last_seen'] < 300) {
                    $user['status'] = 'online';
                    $user['last_seen_text'] = 'Online';
                } else {
                    $user['status'] = 'offline';
                    $user['last_seen_text'] = 'Last seen ' . date('H:i', $user['last_seen']);
                }
            }
            
            echo json_encode($users);
            break;

        case 'get_inbox':
            if (!$current_user) {
                echo json_encode([]);
                break;
            }
            
            // Get recent conversations
            $stmt = $db->prepare("
                SELECT 
                    CASE 
                        WHEN m.sender_id = ? THEN m.receiver_id
                        ELSE m.sender_id
                    END as contact_id,
                    MAX(m.time) as last_time,
                    COUNT(CASE WHEN m.is_read = 0 AND m.receiver_id = ? THEN 1 END) as unread_count
                FROM messages m
                WHERE m.sender_id = ? OR m.receiver_id = ?
                GROUP BY contact_id
                ORDER BY last_time DESC
            ");
            $stmt->execute([$current_user['user_id'], $current_user['user_id'], $current_user['user_id'], $current_user['user_id']]);
            $conversations = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $inbox = [];
            foreach ($conversations as $conv) {
                $user = get_user_by_id($conv['contact_id']);
                if ($user) {
                    $inbox[] = [
                        'user_id' => $user['user_id'],
                        'username' => $user['username'],
                        'name' => $user['name'],
                        'avatar' => $user['avatar'],
                        'status' => $user['status'],
                        'last_seen' => $user['last_seen'],
                        'last_message_time' => $conv['last_time'],
                        'unread_count' => $conv['unread_count']
                    ];
                }
            }
            
            echo json_encode($inbox);
            break;

        case 'get_messages':
            if (!$current_user) {
                echo json_encode([]);
                break;
            }
            
            $other_user_id = intval($_GET['user_id'] ?? 0);
            if (!$other_user_id) {
                echo json_encode([]);
                break;
            }
            
            // Mark messages as read
            $stmt = $db->prepare("UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ?");
            $stmt->execute([$other_user_id, $current_user['user_id']]);
            
            // Get messages
            $stmt = $db->prepare("
                SELECT m.*, u.username as sender_name
                FROM messages m
                JOIN users u ON m.sender_id = u.user_id
                WHERE (m.sender_id = ? AND m.receiver_id = ?) 
                   OR (m.sender_id = ? AND m.receiver_id = ?)
                ORDER BY m.time ASC
                LIMIT 100
            ");
            $stmt->execute([$current_user['user_id'], $other_user_id, $other_user_id, $current_user['user_id']]);
            $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            echo json_encode($messages);
            break;

        case 'send_message':
            if (!$current_user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }
            
            $receiver_id = intval($input['receiver_id'] ?? 0);
            $content = sanitize($input['content'] ?? '');
            $type = $input['type'] ?? 'text';
            
            if (!$receiver_id || empty($content)) {
                echo json_encode(['error' => 'Invalid message']);
                break;
            }
            
            // Check if receiver exists
            $receiver = get_user_by_id($receiver_id);
            if (!$receiver) {
                echo json_encode(['error' => 'User not found']);
                break;
            }
            
            // Check privacy settings
            $stmt = $db->prepare("SELECT privacy FROM user_settings WHERE user_id = ?");
            $stmt->execute([$receiver_id]);
            $settings = $stmt->fetch();
            
            if ($settings && $settings['privacy'] == 1) {
                // Check if contact request exists
                $stmt = $db->prepare("SELECT * FROM contact_requests WHERE from_id = ? AND to_id = ? AND status = 'accepted'");
                $stmt->execute([$current_user['user_id'], $receiver_id]);
                if (!$stmt->fetch()) {
                    // Send contact request instead
                    $stmt = $db->prepare("INSERT OR IGNORE INTO contact_requests (from_id, to_id, created_at) VALUES (?, ?, ?)");
                    $stmt->execute([$current_user['user_id'], $receiver_id, time()]);
                    
                    echo json_encode(['pending' => true]);
                    break;
                }
            }
            
            // Send message
            $message_id = generate_id('message');
            $stmt = $db->prepare("
                INSERT INTO messages (message_id, sender_id, receiver_id, content, message_type, time)
                VALUES (?, ?, ?, ?, ?, ?)
            ");
            $stmt->execute([$message_id, $current_user['user_id'], $receiver_id, $content, $type, time()]);
            
            echo json_encode(['success' => true, 'message_id' => $message_id]);
            break;

        case 'upload_file':
            if (!$current_user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }
            
            if (!isset($_FILES['file'])) {
                echo json_encode(['error' => 'No file uploaded']);
                break;
            }
            
            $file = $_FILES['file'];
            $allowed_types = [
                'image/jpeg', 'image/png', 'image/gif', 'image/webp',
                'application/pdf', 'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'text/plain', 'application/zip'
            ];
            
            if (!in_array($file['type'], $allowed_types)) {
                echo json_encode(['error' => 'File type not allowed']);
                break;
            }
            
            if ($file['size'] > 25 * 1024 * 1024) {
                echo json_encode(['error' => 'File too large (max 25MB)']);
                break;
            }
            
            $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
            $filename = 'file_' . $current_user['user_id'] . '_' . time() . '.' . $extension;
            
            if (!file_exists('uploads')) mkdir('uploads', 0755, true);
            
            if (move_uploaded_file($file['tmp_name'], 'uploads/' . $filename)) {
                // Compress if image dan GD tersedia
                if (strpos($file['type'], 'image/') === 0 && function_exists('gd_info')) {
                    $compressed_filename = 'file_' . $current_user['user_id'] . '_' . time() . '_compressed.' . $extension;
                    compress_image('uploads/' . $filename, 'uploads/' . $compressed_filename, 10);
                    $filename = $compressed_filename;
                }
                
                echo json_encode([
                    'success' => true,
                    'filename' => $filename,
                    'original_name' => $file['name'],
                    'size' => $file['size'],
                    'type' => $file['type']
                ]);
            } else {
                echo json_encode(['error' => 'Upload failed']);
            }
            break;

        case 'create_group':
            if (!$current_user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }
            
            $name = sanitize($input['name'] ?? '');
            $description = sanitize($input['description'] ?? '');
            $members = $input['members'] ?? [];
            
            if (empty($name)) {
                echo json_encode(['error' => 'Group name is required']);
                break;
            }
            
            // Create group
            $group_code = generate_id('group');
            $stmt = $db->prepare("
                INSERT INTO groups (group_code, name, description, created_by, created_at)
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->execute([$group_code, $name, $description, $current_user['user_id'], time()]);
            $group_id = $db->lastInsertId();
            
            // Add creator as admin
            $stmt = $db->prepare("INSERT INTO group_members (group_id, user_id, role, joined_at) VALUES (?, ?, 'admin', ?)");
            $stmt->execute([$group_id, $current_user['user_id'], time()]);
            
            // Add members
            foreach ($members as $member_id) {
                if ($member_id != $current_user['user_id']) {
                    $stmt->execute([$group_id, $member_id, 'member', time()]);
                }
            }
            
            echo json_encode(['success' => true, 'group_id' => $group_id, 'group_code' => $group_code]);
            break;

        case 'get_groups':
            if (!$current_user) {
                echo json_encode([]);
                break;
            }
            
            $stmt = $db->prepare("
                SELECT g.*, gm.role
                FROM groups g
                JOIN group_members gm ON g.group_id = gm.group_id
                WHERE gm.user_id = ?
                ORDER BY g.created_at DESC
            ");
            $stmt->execute([$current_user['user_id']]);
            $groups = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            echo json_encode($groups);
            break;

        case 'get_group_messages':
            if (!$current_user) {
                echo json_encode([]);
                break;
            }
            
            $group_id = intval($_GET['group_id'] ?? 0);
            
            // Check if user is member
            $stmt = $db->prepare("SELECT * FROM group_members WHERE group_id = ? AND user_id = ?");
            $stmt->execute([$group_id, $current_user['user_id']]);
            if (!$stmt->fetch()) {
                echo json_encode([]);
                break;
            }
            
            $stmt = $db->prepare("
                SELECT gm.*, u.username as sender_name
                FROM group_messages gm
                JOIN users u ON gm.sender_id = u.user_id
                WHERE gm.group_id = ?
                ORDER BY gm.time ASC
                LIMIT 100
            ");
            $stmt->execute([$group_id]);
            $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            echo json_encode($messages);
            break;

        case 'send_group_message':
            if (!$current_user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }
            
            $group_id = intval($input['group_id'] ?? 0);
            $content = sanitize($input['content'] ?? '');
            
            if (!$group_id || empty($content)) {
                echo json_encode(['error' => 'Invalid message']);
                break;
            }
            
            // Check if user is member
            $stmt = $db->prepare("SELECT * FROM group_members WHERE group_id = ? AND user_id = ?");
            $stmt->execute([$group_id, $current_user['user_id']]);
            if (!$stmt->fetch()) {
                echo json_encode(['error' => 'Not a member']);
                break;
            }
            
            $stmt = $db->prepare("
                INSERT INTO group_messages (group_id, sender_id, content, time)
                VALUES (?, ?, ?, ?)
            ");
            $stmt->execute([$group_id, $current_user['user_id'], $content, time()]);
            
            echo json_encode(['success' => true]);
            break;

        case 'get_notifications':
            if (!$current_user) {
                echo json_encode([]);
                break;
            }
            
            $stmt = $db->prepare("
                SELECT n.*, u.username as from_username, u.name as from_name
                FROM notifications n
                JOIN users u ON n.from_id = u.user_id
                WHERE n.user_id = ?
                ORDER BY n.created_at DESC
                LIMIT 20
            ");
            $stmt->execute([$current_user['user_id']]);
            $notifications = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            echo json_encode($notifications);
            break;

        case 'mark_notification_read':
            if (!$current_user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }
            
            $notification_id = intval($input['notification_id'] ?? 0);
            if ($notification_id) {
                $stmt = $db->prepare("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?");
                $stmt->execute([$notification_id, $current_user['user_id']]);
            }
            echo json_encode(['success' => true]);
            break;

        case 'get_contact_requests':
            if (!$current_user) {
                echo json_encode([]);
                break;
            }
            
            $stmt = $db->prepare("
                SELECT cr.*, u.username as from_username, u.name as from_name, u.avatar
                FROM contact_requests cr
                JOIN users u ON cr.from_id = u.user_id
                WHERE cr.to_id = ? AND cr.status = 'pending'
                ORDER BY cr.created_at DESC
            ");
            $stmt->execute([$current_user['user_id']]);
            $requests = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            echo json_encode($requests);
            break;

        case 'handle_contact_request':
            if (!$current_user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }
            
            $request_id = intval($input['request_id'] ?? 0);
            $action = $input['action'] ?? ''; // 'accept' or 'reject'
            
            if (!$request_id || !in_array($action, ['accept', 'reject'])) {
                echo json_encode(['error' => 'Invalid request']);
                break;
            }
            
            $status = $action . 'ed';
            $stmt = $db->prepare("UPDATE contact_requests SET status = ? WHERE id = ? AND to_id = ?");
            $stmt->execute([$status, $request_id, $current_user['user_id']]);
            
            echo json_encode(['success' => true]);
            break;

        default:
            echo json_encode(['error' => 'Invalid API endpoint']);
            break;
    }
    exit;
}

// Create necessary directories
foreach (['avatars', 'uploads', 'cache'] as $dir) {
    if (!file_exists($dir)) {
        mkdir($dir, 0755, true);
        // Tambahkan file .htaccess untuk security
        file_put_contents($dir . '/.htaccess', "Deny from all\n");
    }
}

// Tambahkan .htaccess di root untuk security
if (!file_exists('.htaccess')) {
    file_put_contents('.htaccess', 
"# Security headers
<IfModule mod_headers.c>
    Header set X-Frame-Options DENY
    Header set X-Content-Type-Options nosniff
    Header set X-XSS-Protection \"1; mode=block\"
</IfModule>

# Disable directory browsing
Options -Indexes

# Protect sensitive files
<FilesMatch \"^\\.(htaccess|htpasswd|ini|log|sh|sql)$\">
    Order Allow,Deny
    Deny from all
</FilesMatch>

# Redirect to index.php for clean URLs
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php [QSA,L]
");
}
?>
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LinkA • Secure Messenger</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /* ===== VARIABLES ===== */
        :root {
            /* Discord-like colors */
            --background-primary: #36393f;
            --background-secondary: #2f3136;
            --background-tertiary: #202225;
            --background-accent: #5865f2;
            
            --text-primary: #ffffff;
            --text-secondary: #b9bbbe;
            --text-muted: #72767d;
            
            --border-color: #42454a;
            
            --online: #3ba55d;
            --idle: #faa81a;
            --dnd: #ed4245;
            --offline: #747f8d;
            
            --radius: 8px;
            --shadow: 0 8px 16px rgba(0, 0, 0, 0.24);
            
            /* Message colors */
            --message-bg: #32353b;
            --message-hover: #3a3d44;
            --own-message-bg: #4752c4;
        }
        
        [data-theme="light"] {
            --background-primary: #ffffff;
            --background-secondary: #f2f3f5;
            --background-tertiary: #e3e5e8;
            --background-accent: #5865f2;
            
            --text-primary: #060607;
            --text-secondary: #4f5660;
            --text-muted: #747f8d;
            
            --border-color: #e3e5e8;
            
            --message-bg: #f2f3f5;
            --message-hover: #e3e5e8;
            --own-message-bg: #4752c4;
        }
        
        /* ===== RESET & BASE ===== */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--background-primary);
            color: var(--text-primary);
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
            width: 240px;
            background: var(--background-secondary);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            position: relative;
        }
        
        .server-list {
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .server-icon {
            width: 48px;
            height: 48px;
            border-radius: 50%;
            background: var(--background-accent);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: border-radius 0.2s;
            margin-bottom: 8px;
        }
        
        .server-icon:hover {
            border-radius: 30%;
        }
        
        .server-icon i {
            font-size: 20px;
        }
        
        .channel-list {
            flex: 1;
            padding: 12px;
            overflow-y: auto;
        }
        
        .channel-category {
            color: var(--text-muted);
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            margin: 16px 0 8px 8px;
            letter-spacing: 0.5px;
        }
        
        .channel-item {
            padding: 8px;
            border-radius: var(--radius);
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: background 0.2s;
        }
        
        .channel-item:hover {
            background: var(--background-tertiary);
        }
        
        .channel-item.active {
            background: var(--background-tertiary);
        }
        
        .channel-icon {
            color: var(--text-muted);
            font-size: 14px;
        }
        
        .user-panel {
            background: var(--background-tertiary);
            padding: 12px;
            display: flex;
            align-items: center;
            gap: 12px;
            border-top: 1px solid var(--border-color);
        }
        
        .user-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            object-fit: cover;
        }
        
        .user-info {
            flex: 1;
        }
        
        .user-name {
            font-size: 14px;
            font-weight: 600;
        }
        
        .user-status {
            font-size: 12px;
            color: var(--text-muted);
        }
        
        .user-controls {
            display: flex;
            gap: 8px;
        }
        
        .control-btn {
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            padding: 4px;
            border-radius: 4px;
            transition: color 0.2s, background 0.2s;
        }
        
        .control-btn:hover {
            color: var(--text-primary);
            background: var(--background-secondary);
        }
        
        /* ===== MAIN CONTENT ===== */
        .main-content {
            flex: 1;
            display: flex;
        }
        
        .chat-sidebar {
            width: 240px;
            background: var(--background-secondary);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
        }
        
        .chat-header {
            padding: 16px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .chat-title {
            font-size: 16px;
            font-weight: 600;
        }
        
        .chat-search {
            padding: 16px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .search-box {
            position: relative;
        }
        
        .search-input {
            width: 100%;
            padding: 8px 12px 8px 32px;
            background: var(--background-tertiary);
            border: none;
            border-radius: var(--radius);
            color: var(--text-primary);
            font-size: 14px;
        }
        
        .search-input:focus {
            outline: none;
        }
        
        .search-icon {
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
        }
        
        .chat-list {
            flex: 1;
            overflow-y: auto;
            padding: 8px;
        }
        
        .chat-item {
            padding: 8px;
            border-radius: var(--radius);
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 12px;
            transition: background 0.2s;
        }
        
        .chat-item:hover {
            background: var(--background-tertiary);
        }
        
        .chat-item.active {
            background: var(--background-tertiary);
        }
        
        .chat-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            object-fit: cover;
            position: relative;
        }
        
        .chat-status {
            position: absolute;
            bottom: -2px;
            right: -2px;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            border: 2px solid var(--background-secondary);
        }
        
        .status-online { background: var(--online); }
        .status-idle { background: var(--idle); }
        .status-dnd { background: var(--dnd); }
        .status-offline { background: var(--offline); }
        
        .chat-info {
            flex: 1;
            min-width: 0;
        }
        
        .chat-name {
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 2px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .chat-preview {
            font-size: 12px;
            color: var(--text-muted);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .chat-meta {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 4px;
        }
        
        .chat-time {
            font-size: 11px;
            color: var(--text-muted);
        }
        
        .chat-unread {
            background: var(--background-accent);
            color: white;
            font-size: 10px;
            padding: 2px 4px;
            border-radius: 10px;
            min-width: 16px;
            text-align: center;
        }
        
        /* ===== CHAT AREA ===== */
        .chat-area {
            flex: 1;
            display: flex;
            flex-direction: column;
            background: var(--background-primary);
        }
        
        .message-header {
            padding: 16px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 12px;
            background: var(--background-primary);
            position: sticky;
            top: 0;
            z-index: 10;
        }
        
        .message-title {
            font-size: 16px;
            font-weight: 600;
        }
        
        .message-info {
            font-size: 12px;
            color: var(--text-muted);
        }
        
        .message-container {
            flex: 1;
            padding: 16px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }
        
        .message-date {
            text-align: center;
            margin: 16px 0;
        }
        
        .date-label {
            background: var(--background-tertiary);
            color: var(--text-muted);
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            display: inline-block;
        }
        
        .message-group {
            display: flex;
            gap: 12px;
            padding: 4px 16px;
            transition: background 0.2s;
        }
        
        .message-group:hover {
            background: var(--message-hover);
            border-radius: var(--radius);
        }
        
        .message-group.own {
            flex-direction: row-reverse;
        }
        
        .message-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            object-fit: cover;
            flex-shrink: 0;
        }
        
        .message-content {
            max-width: 70%;
        }
        
        .message-author {
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 4px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .message-time {
            font-size: 11px;
            color: var(--text-muted);
            font-weight: normal;
        }
        
        .message-bubble {
            background: var(--message-bg);
            padding: 8px 12px;
            border-radius: 0 var(--radius) var(--radius) var(--radius);
            line-height: 1.4;
            word-wrap: break-word;
        }
        
        .own .message-bubble {
            background: var(--own-message-bg);
            border-radius: var(--radius) 0 var(--radius) var(--radius);
        }
        
        .message-input-area {
            padding: 16px;
            border-top: 1px solid var(--border-color);
            background: var(--background-primary);
        }
        
        .message-input-container {
            background: var(--background-tertiary);
            border-radius: var(--radius);
            padding: 8px;
        }
        
        .message-input {
            width: 100%;
            background: none;
            border: none;
            color: var(--text-primary);
            font-size: 14px;
            resize: none;
            min-height: 20px;
            max-height: 200px;
        }
        
        .message-input:focus {
            outline: none;
        }
        
        .message-actions {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 8px;
        }
        
        .action-buttons {
            display: flex;
            gap: 8px;
        }
        
        .action-btn {
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            padding: 4px;
            border-radius: 4px;
            transition: color 0.2s;
        }
        
        .action-btn:hover {
            color: var(--text-primary);
        }
        
        .send-btn {
            background: var(--background-accent);
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: var(--radius);
            cursor: pointer;
            font-weight: 500;
            transition: background 0.2s;
        }
        
        .send-btn:hover {
            background: #4752c4;
        }
        
        /* ===== MODALS ===== */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        
        .modal.active {
            display: flex;
        }
        
        .modal-content {
            background: var(--background-primary);
            border-radius: var(--radius);
            width: 90%;
            max-width: 500px;
            max-height: 90vh;
            overflow: hidden;
            box-shadow: var(--shadow);
            animation: modalIn 0.2s ease;
        }
        
        @keyframes modalIn {
            from { opacity: 0; transform: scale(0.9); }
            to { opacity: 1; transform: scale(1); }
        }
        
        .modal-header {
            padding: 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .modal-title {
            font-size: 20px;
            font-weight: 600;
        }
        
        .modal-close {
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 20px;
            padding: 4px;
        }
        
        .modal-body {
            padding: 20px;
            overflow-y: auto;
            max-height: 60vh;
        }
        
        /* ===== FORMS ===== */
        .form-group {
            margin-bottom: 16px;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            color: var(--text-secondary);
            font-size: 14px;
            font-weight: 500;
        }
        
        .form-input {
            width: 100%;
            padding: 10px 12px;
            background: var(--background-tertiary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            color: var(--text-primary);
            font-size: 14px;
            transition: border-color 0.2s;
        }
        
        .form-input:focus {
            outline: none;
            border-color: var(--background-accent);
        }
        
        .form-textarea {
            min-height: 100px;
            resize: vertical;
        }
        
        .form-select {
            width: 100%;
            padding: 10px 12px;
            background: var(--background-tertiary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            color: var(--text-primary);
            font-size: 14px;
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 8px;
        }
        
        .checkbox {
            width: 16px;
            height: 16px;
            accent-color: var(--background-accent);
        }
        
        /* ===== UTILITIES ===== */
        .hidden { display: none !important; }
        .flex { display: flex; }
        .items-center { align-items: center; }
        .justify-between { justify-content: space-between; }
        .gap-2 { gap: 8px; }
        .gap-4 { gap: 16px; }
        .mt-4 { margin-top: 16px; }
        .mb-4 { margin-bottom: 16px; }
        .w-full { width: 100%; }
        .text-center { text-align: center; }
        .text-muted { color: var(--text-muted); }
        .text-sm { font-size: 12px; }
        
        /* ===== SCROLLBAR ===== */
        ::-webkit-scrollbar {
            width: 6px;
        }
        
        ::-webkit-scrollbar-track {
            background: transparent;
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--background-tertiary);
            border-radius: 3px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--text-muted);
        }
        
        /* ===== RESPONSIVE ===== */
        @media (max-width: 768px) {
            .sidebar {
                width: 72px;
            }
            
            .sidebar .channel-name,
            .sidebar .user-info {
                display: none;
            }
            
            .chat-sidebar {
                width: 100%;
                position: absolute;
                top: 0;
                left: 72px;
                height: 100%;
                z-index: 100;
                display: none;
            }
            
            .chat-sidebar.active {
                display: flex;
            }
        }
    </style>
</head>
<body>
    <!-- AUTH SCREEN -->
    <div id="authScreen" class="modal active">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title">LinkA Messenger</h2>
            </div>
            <div class="modal-body">
                <div id="loginView">
                    <div class="form-group">
                        <label class="form-label">Username</label>
                        <input type="text" class="form-input" id="loginUsername" placeholder="Enter your username">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Password</label>
                        <input type="password" class="form-input" id="loginPassword" placeholder="Enter your password">
                    </div>
                    <button class="send-btn w-full" onclick="login()">Login</button>
                    <p class="text-center mt-4 text-muted">
                        Don't have an account? 
                        <a href="#" onclick="showRegister()" style="color: var(--background-accent); cursor: pointer;">Register</a>
                    </p>
                </div>
                
                <div id="registerView" class="hidden">
                    <div class="form-group">
                        <label class="form-label">Username</label>
                        <input type="text" class="form-input" id="registerUsername" placeholder="Choose a username">
                        <div class="text-sm text-muted mt-1">3-20 characters, letters, numbers and underscore only</div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Display Name</label>
                        <input type="text" class="form-input" id="registerName" placeholder="Your display name">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Password</label>
                        <input type="password" class="form-input" id="registerPassword" placeholder="Choose a password">
                        <div class="text-sm text-muted mt-1">At least 6 characters</div>
                    </div>
                    <button class="send-btn w-full" onclick="register()">Create Account</button>
                    <p class="text-center mt-4 text-muted">
                        Already have an account? 
                        <a href="#" onclick="showLogin()" style="color: var(--background-accent); cursor: pointer;">Login</a>
                    </p>
                </div>
            </div>
        </div>
    </div>

    <!-- MAIN APP -->
    <div id="appContainer" class="app-container hidden">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="server-list">
                <div class="server-icon" onclick="showHome()">
                    <i class="fas fa-home"></i>
                </div>
                <div class="server-icon" onclick="showDirectMessages()">
                    <i class="fas fa-user-friends"></i>
                </div>
                <div class="server-icon" onclick="showGroups()">
                    <i class="fas fa-users"></i>
                </div>
                <div class="server-icon" onclick="showSearch()">
                    <i class="fas fa-search"></i>
                </div>
            </div>
            
            <div class="channel-list">
                <div class="channel-category">DIRECT MESSAGES</div>
                <div id="dmList">
                    <!-- Direct messages will be loaded here -->
                </div>
                
                <div class="channel-category">GROUPS</div>
                <div id="groupList">
                    <!-- Groups will be loaded here -->
                </div>
            </div>
            
            <div class="user-panel">
                <img src="avatars/default.png" class="user-avatar" id="currentUserAvatar">
                <div class="user-info">
                    <div class="user-name" id="currentUserName">Loading...</div>
                    <div class="user-status" id="currentUserStatus">Online</div>
                </div>
                <div class="user-controls">
                    <button class="control-btn" onclick="showUserSettings()">
                        <i class="fas fa-cog"></i>
                    </button>
                    <button class="control-btn" onclick="logout()">
                        <i class="fas fa-sign-out-alt"></i>
                    </button>
                </div>
            </div>
        </div>
        
        <!-- Chat Sidebar -->
        <div class="chat-sidebar">
            <div class="chat-header">
                <div class="chat-title" id="chatSidebarTitle">Messages</div>
                <button class="control-btn" onclick="createNewChat()">
                    <i class="fas fa-edit"></i>
                </button>
            </div>
            
            <div class="chat-search">
                <div class="search-box">
                    <i class="fas fa-search search-icon"></i>
                    <input type="text" class="search-input" placeholder="Search conversations..." id="chatSearch">
                </div>
            </div>
            
            <div class="chat-list" id="chatList">
                <!-- Chat list will be loaded here -->
            </div>
        </div>
        
        <!-- Chat Area -->
        <div class="chat-area">
            <div class="message-header">
                <div id="chatHeaderContent">
                    <div class="message-title">Welcome to LinkA</div>
                    <div class="message-info">Select a conversation to start messaging</div>
                </div>
            </div>
            
            <div class="message-container" id="messageContainer">
                <!-- Messages will be loaded here -->
            </div>
            
            <div class="message-input-area hidden" id="messageInputArea">
                <div class="message-input-container">
                    <textarea class="message-input" id="messageInput" placeholder="Message @username" rows="1"></textarea>
                </div>
                <div class="message-actions">
                    <div class="action-buttons">
                        <button class="action-btn" onclick="attachFile()">
                            <i class="fas fa-paperclip"></i>
                        </button>
                        <button class="action-btn" onclick="attachImage()">
                            <i class="fas fa-image"></i>
                        </button>
                        <input type="file" id="fileInput" class="hidden" accept="*/*">
                        <input type="file" id="imageInput" class="hidden" accept="image/*">
                    </div>
                    <button class="send-btn" onclick="sendMessage()">
                        <i class="fas fa-paper-plane"></i>
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- MODALS -->
    <!-- New Chat Modal -->
    <div class="modal" id="newChatModal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title">New Message</h2>
                <button class="modal-close" onclick="hideModal('newChatModal')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">Search Users</label>
                    <input type="text" class="form-input" id="newChatSearch" placeholder="Type username or name..." oninput="searchNewChat()">
                </div>
                <div id="newChatResults" class="chat-list" style="max-height: 300px;">
                    <!-- Search results will appear here -->
                </div>
            </div>
        </div>
    </div>

    <!-- Create Group Modal -->
    <div class="modal" id="createGroupModal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title">Create Group</h2>
                <button class="modal-close" onclick="hideModal('createGroupModal')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">Group Name</label>
                    <input type="text" class="form-input" id="groupName" placeholder="Enter group name">
                </div>
                <div class="form-group">
                    <label class="form-label">Description</label>
                    <textarea class="form-input form-textarea" id="groupDescription" placeholder="Optional group description"></textarea>
                </div>
                <div class="form-group">
                    <label class="form-label">Add Members</label>
                    <input type="text" class="form-input" id="groupMemberSearch" placeholder="Search users to add..." oninput="searchGroupMembers()">
                </div>
                <div id="selectedMembers" class="mb-4">
                    <!-- Selected members will appear here -->
                </div>
                <div id="groupSearchResults" class="chat-list" style="max-height: 200px;">
                    <!-- Search results will appear here -->
                </div>
                <button class="send-btn w-full mt-4" onclick="createGroup()">Create Group</button>
            </div>
        </div>
    </div>

    <!-- User Settings Modal -->
    <div class="modal" id="userSettingsModal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title">User Settings</h2>
                <button class="modal-close" onclick="hideModal('userSettingsModal')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="text-center mb-4">
                    <img src="avatars/default.png" class="user-avatar" id="settingsAvatar" style="width: 80px; height: 80px; cursor: pointer;" onclick="document.getElementById('avatarUpload').click()">
                    <input type="file" id="avatarUpload" class="hidden" accept="image/*">
                    <div class="text-sm text-muted mt-2">Click to change avatar</div>
                </div>
                
                <div class="form-group">
                    <label class="form-label">User ID</label>
                    <input type="text" class="form-input" id="settingsUserId" readonly>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Username</label>
                    <input type="text" class="form-input" id="settingsUsername" readonly>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Display Name</label>
                    <input type="text" class="form-input" id="settingsName">
                </div>
                
                <div class="form-group">
                    <label class="form-label">Bio</label>
                    <textarea class="form-input form-textarea" id="settingsBio" placeholder="Tell something about yourself"></textarea>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Theme</label>
                    <select class="form-select" id="settingsTheme">
                        <option value="dark">Dark</option>
                        <option value="light">Light</option>
                    </select>
                </div>
                
                <div class="checkbox-group">
                    <input type="checkbox" class="checkbox" id="settingsNotifications" checked>
                    <label for="settingsNotifications">Enable notifications</label>
                </div>
                
                <div class="checkbox-group">
                    <input type="checkbox" class="checkbox" id="settingsSound" checked>
                    <label for="settingsSound">Enable sounds</label>
                </div>
                
                <div class="checkbox-group">
                    <input type="checkbox" class="checkbox" id="settingsPrivacy">
                    <label for="settingsPrivacy">Private account (only contacts can message you)</label>
                </div>
                
                <button class="send-btn w-full mt-4" onclick="saveSettings()">Save Settings</button>
            </div>
        </div>
    </div>

    <!-- Search Modal -->
    <div class="modal" id="searchModal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title">Search Users</h2>
                <button class="modal-close" onclick="hideModal('searchModal')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <input type="text" class="form-input" id="globalSearch" placeholder="Search users by username or name..." oninput="globalSearch()">
                </div>
                <div id="globalSearchResults" class="chat-list" style="max-height: 400px;">
                    <!-- Search results will appear here -->
                </div>
            </div>
        </div>
    </div>

    <!-- Toast Container -->
    <div id="toastContainer" style="position: fixed; bottom: 20px; right: 20px; z-index: 10000;"></div>

    <script>
        // ===== GLOBAL STATE =====
        let currentUser = null;
        let currentChat = null;
        let currentChatType = null; // 'dm' or 'group'
        let selectedMembers = [];
        let csrfToken = '<?php echo $_SESSION['csrf_token']; ?>';
        
        // ===== INITIALIZATION =====
        document.addEventListener('DOMContentLoaded', function() {
            checkAuth();
            
            // Auto-resize textarea
            const messageInput = document.getElementById('messageInput');
            if (messageInput) {
                messageInput.addEventListener('input', function() {
                    this.style.height = 'auto';
                    this.style.height = (this.scrollHeight) + 'px';
                });
            }
            
            // Enter key to send message
            messageInput.addEventListener('keydown', function(e) {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    sendMessage();
                }
            });
        });
        
        // ===== AUTHENTICATION =====
        async function checkAuth() {
            try {
                const response = await fetch('?api=check_auth');
                const data = await response.json();
                
                if (data.authenticated) {
                    loadApp();
                } else {
                    // Show auth screen if not authenticated
                    document.getElementById('authScreen').classList.add('active');
                }
            } catch (error) {
                console.error('Auth check failed:', error);
                document.getElementById('authScreen').classList.add('active');
            }
        }
        
        function showLogin() {
            document.getElementById('loginView').classList.remove('hidden');
            document.getElementById('registerView').classList.add('hidden');
        }
        
        function showRegister() {
            document.getElementById('loginView').classList.add('hidden');
            document.getElementById('registerView').classList.remove('hidden');
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
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({ username, password, csrf_token: csrfToken })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showToast('Login successful', 'success');
                    loadApp();
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
            
            if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
                showToast('Username must be 3-20 characters (letters, numbers, underscore only)', 'error');
                return;
            }
            
            if (password.length < 6) {
                showToast('Password must be at least 6 characters', 'error');
                return;
            }
            
            try {
                const response = await fetch('?api=register', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({ 
                        username, 
                        name, 
                        password, 
                        csrf_token: csrfToken 
                    })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showToast('Account created successfully', 'success');
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
                await fetch('?api=logout', {
                    headers: { 'X-CSRF-Token': csrfToken }
                });
                window.location.reload();
            } catch (error) {
                console.error('Logout error:', error);
            }
        }
        
        // ===== APP FUNCTIONS =====
        function loadApp() {
            document.getElementById('authScreen').classList.remove('active');
            document.getElementById('appContainer').classList.remove('hidden');
            
            loadUserProfile();
            loadInbox();
            loadGroups();
            
            // Auto-refresh
            setInterval(() => {
                if (currentChat) {
                    if (currentChatType === 'dm') {
                        loadMessages();
                    } else {
                        loadGroupMessages();
                    }
                }
                loadInbox();
            }, 3000);
        }
        
        async function loadUserProfile() {
            try {
                const response = await fetch('?api=get_profile');
                const data = await response.json();
                
                if (data.user_id) {
                    currentUser = data;
                    
                    // Update UI
                    document.getElementById('currentUserName').textContent = data.name;
                    document.getElementById('currentUserStatus').textContent = data.status === 'online' ? 'Online' : 'Offline';
                    
                    if (data.avatar && data.avatar !== 'default.png') {
                        const avatarUrl = `avatars/${data.avatar}`;
                        document.getElementById('currentUserAvatar').src = avatarUrl;
                        document.getElementById('settingsAvatar').src = avatarUrl;
                    }
                    
                    // Update settings modal
                    document.getElementById('settingsUserId').value = data.user_id;
                    document.getElementById('settingsUsername').value = data.username;
                    document.getElementById('settingsName').value = data.name;
                    document.getElementById('settingsBio').value = data.bio || '';
                    document.getElementById('settingsTheme').value = data.theme || 'dark';
                    document.getElementById('settingsNotifications').checked = data.notifications == 1;
                    document.getElementById('settingsSound').checked = data.sound == 1;
                    document.getElementById('settingsPrivacy').checked = data.privacy == 1;
                    
                    // Apply theme
                    document.documentElement.setAttribute('data-theme', data.theme || 'dark');
                }
            } catch (error) {
                console.error('Profile load error:', error);
            }
        }
        
        // ===== INBOX & MESSAGES =====
        async function loadInbox() {
            try {
                const response = await fetch('?api=get_inbox');
                const inbox = await response.json();
                
                const container = document.getElementById('chatList');
                let html = '';
                
                inbox.forEach(item => {
                    const avatarSrc = item.avatar && item.avatar !== 'default.png' 
                        ? `avatars/${item.avatar}` 
                        : 'avatars/default.png';
                    
                    const lastMessageTime = item.last_message_time ? new Date(item.last_message_time * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
                    const unreadBadge = item.unread_count > 0 ? `<div class="chat-unread">${item.unread_count}</div>` : '';
                    
                    html += `
                        <div class="chat-item" onclick="openChat(${item.user_id}, 'user')">
                            <div class="chat-avatar">
                                <img src="${avatarSrc}" class="chat-avatar">
                                <div class="chat-status status-${item.status || 'offline'}"></div>
                            </div>
                            <div class="chat-info">
                                <div class="chat-name">${escapeHtml(item.name)}</div>
                                <div class="chat-preview">${item.status === 'online' ? 'Online' : 'Offline'}</div>
                            </div>
                            <div class="chat-meta">
                                <div class="chat-time">${lastMessageTime}</div>
                                ${unreadBadge}
                            </div>
                        </div>
                    `;
                });
                
                container.innerHTML = html || '<div class="text-center text-muted mt-4">No messages yet</div>';
            } catch (error) {
                console.error('Inbox load error:', error);
            }
        }
        
        async function openChat(userId, type = 'user', userName = '') {
            currentChat = userId;
            currentChatType = type === 'user' ? 'dm' : 'group';
            
            // Update UI
            document.getElementById('messageInputArea').classList.remove('hidden');
            
            if (type === 'user') {
                // Load user info
                try {
                    const response = await fetch(`?api=get_profile&user_id=${userId}`);
                    const user = await response.json();
                    
                    document.getElementById('chatHeaderContent').innerHTML = `
                        <div class="message-title">${escapeHtml(user.name)}</div>
                        <div class="message-info">${user.status === 'online' ? 'Online' : user.last_seen_text || 'Offline'}</div>
                    `;
                } catch (error) {
                    console.error('Error loading user:', error);
                }
                
                loadMessages();
            } else {
                // Load group info
                document.getElementById('chatHeaderContent').innerHTML = `
                    <div class="message-title">${escapeHtml(userName)}</div>
                    <div class="message-info">Group</div>
                `;
                
                loadGroupMessages();
            }
        }
        
        async function loadMessages() {
            if (!currentChat || currentChatType !== 'dm') return;
            
            try {
                const response = await fetch(`?api=get_messages&user_id=${currentChat}`);
                const messages = await response.json();
                
                const container = document.getElementById('messageContainer');
                let html = '';
                
                if (messages.length === 0) {
                    html = `
                        <div class="text-center text-muted" style="margin-top: 100px;">
                            <i class="fas fa-comments" style="font-size: 48px; margin-bottom: 16px;"></i>
                            <div>No messages yet. Say hi!</div>
                        </div>
                    `;
                } else {
                    let lastDate = '';
                    
                    messages.forEach(msg => {
                        const msgDate = new Date(msg.time * 1000);
                        const dateStr = msgDate.toLocaleDateString();
                        const timeStr = msgDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                        
                        if (dateStr !== lastDate) {
                            html += `<div class="message-date"><div class="date-label">${dateStr}</div></div>`;
                            lastDate = dateStr;
                        }
                        
                        const isOwn = msg.sender_id === currentUser.user_id;
                        
                        html += `
                            <div class="message-group ${isOwn ? 'own' : ''}">
                                ${!isOwn ? `<img src="avatars/default.png" class="message-avatar">` : ''}
                                <div class="message-content">
                                    ${!isOwn ? `
                                        <div class="message-author">
                                            ${escapeHtml(msg.sender_name)}
                                            <span class="message-time">${timeStr}</span>
                                        </div>
                                    ` : ''}
                                    <div class="message-bubble">${escapeHtml(msg.content)}</div>
                                    ${isOwn ? `
                                        <div class="message-author" style="justify-content: flex-end;">
                                            <span class="message-time">${timeStr}</span>
                                        </div>
                                    ` : ''}
                                </div>
                                ${isOwn ? `<img src="avatars/${currentUser.avatar || 'default.png'}" class="message-avatar">` : ''}
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
            
            if (!message || !currentChat) return;
            
            try {
                let apiUrl, payload;
                
                if (currentChatType === 'dm') {
                    apiUrl = '?api=send_message';
                    payload = {
                        receiver_id: currentChat,
                        content: message,
                        csrf_token: csrfToken
                    };
                } else {
                    apiUrl = '?api=send_group_message';
                    payload = {
                        group_id: currentChat,
                        content: message,
                        csrf_token: csrfToken
                    };
                }
                
                const response = await fetch(apiUrl, {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify(payload)
                });
                
                const data = await response.json();
                
                if (data.success) {
                    input.value = '';
                    input.style.height = 'auto';
                    
                    if (currentChatType === 'dm') {
                        loadMessages();
                    } else {
                        loadGroupMessages();
                    }
                } else if (data.pending) {
                    showToast('Contact request sent. Waiting for acceptance.', 'info');
                }
            } catch (error) {
                showToast('Failed to send message', 'error');
            }
        }
        
        // ===== GROUPS =====
        async function loadGroups() {
            try {
                const response = await fetch('?api=get_groups');
                const groups = await response.json();
                
                const container = document.getElementById('groupList');
                let html = '';
                
                groups.forEach(group => {
                    html += `
                        <div class="channel-item" onclick="openChat(${group.group_id}, 'group', '${escapeHtml(group.name)}')">
                            <i class="fas fa-users channel-icon"></i>
                            <span class="channel-name">${escapeHtml(group.name)}</span>
                        </div>
                    `;
                });
                
                container.innerHTML = html || '<div class="text-muted text-sm ml-2 mt-2">No groups yet</div>';
            } catch (error) {
                console.error('Groups load error:', error);
            }
        }
        
        async function loadGroupMessages() {
            if (!currentChat || currentChatType !== 'group') return;
            
            try {
                const response = await fetch(`?api=get_group_messages&group_id=${currentChat}`);
                const messages = await response.json();
                
                const container = document.getElementById('messageContainer');
                let html = '';
                
                messages.forEach(msg => {
                    const timeStr = new Date(msg.time * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    const isOwn = msg.sender_id === currentUser.user_id;
                    
                    html += `
                        <div class="message-group ${isOwn ? 'own' : ''}">
                            ${!isOwn ? `<img src="avatars/default.png" class="message-avatar">` : ''}
                            <div class="message-content">
                                ${!isOwn ? `
                                    <div class="message-author">
                                        ${escapeHtml(msg.sender_name)}
                                        <span class="message-time">${timeStr}</span>
                                    </div>
                                ` : ''}
                                <div class="message-bubble">${escapeHtml(msg.content)}</div>
                                ${isOwn ? `
                                    <div class="message-author" style="justify-content: flex-end;">
                                        <span class="message-time">${timeStr}</span>
                                    </div>
                                ` : ''}
                            </div>
                            ${isOwn ? `<img src="avatars/${currentUser.avatar || 'default.png'}" class="message-avatar">` : ''}
                        </div>
                    `;
                });
                
                container.innerHTML = html || '<div class="text-center text-muted">No messages in this group yet</div>';
                container.scrollTop = container.scrollHeight;
            } catch (error) {
                console.error('Group messages error:', error);
            }
        }
        
        // ===== SEARCH =====
        async function searchNewChat() {
            const query = document.getElementById('newChatSearch').value.trim();
            if (query.length < 2) return;
            
            try {
                const response = await fetch(`?api=search_users&q=${encodeURIComponent(query)}`);
                const users = await response.json();
                
                const container = document.getElementById('newChatResults');
                let html = '';
                
                users.forEach(user => {
                    const avatarSrc = user.avatar && user.avatar !== 'default.png' 
                        ? `avatars/${user.avatar}` 
                        : 'avatars/default.png';
                    
                    html += `
                        <div class="chat-item" onclick="startNewChat(${user.user_id}, '${escapeHtml(user.name)}')">
                            <div class="chat-avatar">
                                <img src="${avatarSrc}" class="chat-avatar">
                                <div class="chat-status status-${user.status}"></div>
                            </div>
                            <div class="chat-info">
                                <div class="chat-name">${escapeHtml(user.name)}</div>
                                <div class="chat-preview">@${escapeHtml(user.username)}</div>
                            </div>
                        </div>
                    `;
                });
                
                container.innerHTML = html || '<div class="text-center text-muted">No users found</div>';
            } catch (error) {
                console.error('Search error:', error);
            }
        }
        
        function startNewChat(userId, userName) {
            hideModal('newChatModal');
            openChat(userId, 'user', userName);
        }
        
        // ===== FILE UPLOAD =====
        function attachFile() {
            document.getElementById('fileInput').click();
        }
        
        function attachImage() {
            document.getElementById('imageInput').click();
        }
        
        document.getElementById('fileInput').addEventListener('change', async function(e) {
            if (e.target.files[0]) {
                await uploadFile(e.target.files[0]);
            }
        });
        
        document.getElementById('imageInput').addEventListener('change', async function(e) {
            if (e.target.files[0]) {
                await uploadFile(e.target.files[0], true);
            }
        });
        
        async function uploadFile(file, isImage = false) {
            const formData = new FormData();
            formData.append('file', file);
            formData.append('csrf_token', csrfToken);
            
            try {
                const response = await fetch('?api=upload_file', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showToast('File uploaded successfully', 'success');
                    
                    // Send as message
                    const message = isImage ? '[Image]' : '[File]';
                    const input = document.getElementById('messageInput');
                    input.value = message;
                    sendMessage();
                }
            } catch (error) {
                showToast('Upload failed', 'error');
            }
        }
        
        // ===== SETTINGS =====
        function showUserSettings() {
            showModal('userSettingsModal');
        }
        
        async function saveSettings() {
            const name = document.getElementById('settingsName').value.trim();
            const bio = document.getElementById('settingsBio').value.trim();
            const theme = document.getElementById('settingsTheme').value;
            const notifications = document.getElementById('settingsNotifications').checked ? 1 : 0;
            const sound = document.getElementById('settingsSound').checked ? 1 : 0;
            const privacy = document.getElementById('settingsPrivacy').checked ? 1 : 0;
            
            try {
                // Update profile
                await fetch('?api=update_profile', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({ 
                        name, 
                        bio,
                        csrf_token: csrfToken 
                    })
                });
                
                // Update settings
                await fetch('?api=update_settings', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({ 
                        theme,
                        notifications,
                        sound,
                        privacy,
                        csrf_token: csrfToken 
                    })
                });
                
                // Update avatar if changed
                const avatarInput = document.getElementById('avatarUpload');
                if (avatarInput.files[0]) {
                    const avatarFormData = new FormData();
                    avatarFormData.append('avatar', avatarInput.files[0]);
                    avatarFormData.append('csrf_token', csrfToken);
                    
                    await fetch('?api=update_avatar', {
                        method: 'POST',
                        body: avatarFormData
                    });
                }
                
                showToast('Settings saved', 'success');
                loadUserProfile();
                hideModal('userSettingsModal');
            } catch (error) {
                showToast('Failed to save settings', 'error');
            }
        }
        
        // ===== CREATE GROUP =====
        function showCreateGroup() {
            selectedMembers = [];
            updateSelectedMembers();
            showModal('createGroupModal');
        }
        
        async function searchGroupMembers() {
            const query = document.getElementById('groupMemberSearch').value.trim();
            if (query.length < 2) return;
            
            try {
                const response = await fetch(`?api=search_users&q=${encodeURIComponent(query)}`);
                const users = await response.json();
                
                const container = document.getElementById('groupSearchResults');
                let html = '';
                
                users.forEach(user => {
                    if (selectedMembers.includes(user.user_id) || user.user_id === currentUser.user_id) return;
                    
                    html += `
                        <div class="chat-item" onclick="addGroupMember(${user.user_id}, '${escapeHtml(user.name)}')">
                            <div class="chat-avatar">
                                <img src="avatars/${user.avatar || 'default.png'}" class="chat-avatar">
                            </div>
                            <div class="chat-info">
                                <div class="chat-name">${escapeHtml(user.name)}</div>
                                <div class="chat-preview">@${escapeHtml(user.username)}</div>
                            </div>
                            <div class="chat-meta">
                                <i class="fas fa-plus text-muted"></i>
                            </div>
                        </div>
                    `;
                });
                
                container.innerHTML = html || '<div class="text-center text-muted">No users found</div>';
            } catch (error) {
                console.error('Search error:', error);
            }
        }
        
        function addGroupMember(userId, userName) {
            if (!selectedMembers.includes(userId)) {
                selectedMembers.push(userId);
                updateSelectedMembers();
            }
        }
        
        function updateSelectedMembers() {
            const container = document.getElementById('selectedMembers');
            let html = '';
            
            selectedMembers.forEach(userId => {
                html += `<span class="text-sm bg-gray-700 text-white px-2 py-1 rounded mr-2">User ${userId}</span>`;
            });
            
            container.innerHTML = html || '<div class="text-muted text-sm">No members selected</div>';
        }
        
        async function createGroup() {
            const name = document.getElementById('groupName').value.trim();
            const description = document.getElementById('groupDescription').value.trim();
            
            if (!name) {
                showToast('Group name is required', 'error');
                return;
            }
            
            if (selectedMembers.length === 0) {
                showToast('Add at least one member', 'error');
                return;
            }
            
            try {
                const response = await fetch('?api=create_group', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({ 
                        name, 
                        description, 
                        members: selectedMembers,
                        csrf_token: csrfToken 
                    })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showToast('Group created successfully', 'success');
                    hideModal('createGroupModal');
                    loadGroups();
                }
            } catch (error) {
                showToast('Failed to create group', 'error');
            }
        }
        
        // ===== UI HELPERS =====
        function showModal(id) {
            document.getElementById(id).classList.add('active');
        }
        
        function hideModal(id) {
            document.getElementById(id).classList.remove('active');
        }
        
        function createNewChat() {
            showModal('newChatModal');
        }
        
        function showHome() {
            // Reset to home view
            currentChat = null;
            document.getElementById('messageInputArea').classList.add('hidden');
            document.getElementById('chatHeaderContent').innerHTML = `
                <div class="message-title">Welcome to LinkA</div>
                <div class="message-info">Select a conversation to start messaging</div>
            `;
            document.getElementById('messageContainer').innerHTML = `
                <div class="text-center text-muted" style="margin-top: 100px;">
                    <i class="fas fa-comments" style="font-size: 48px; margin-bottom: 16px;"></i>
                    <div>Welcome to LinkA Messenger</div>
                    <div class="text-sm mt-2">Select a conversation or start a new one</div>
                </div>
            `;
        }
        
        function showDirectMessages() {
            loadInbox();
        }
        
        function showGroups() {
            showCreateGroup();
        }
        
        function showSearch() {
            showModal('searchModal');
        }
        
        async function globalSearch() {
            const query = document.getElementById('globalSearch').value.trim();
            if (query.length < 2) return;
            
            try {
                const response = await fetch(`?api=search_users&q=${encodeURIComponent(query)}`);
                const users = await response.json();
                
                const container = document.getElementById('globalSearchResults');
                let html = '';
                
                users.forEach(user => {
                    const avatarSrc = user.avatar && user.avatar !== 'default.png' 
                        ? `avatars/${user.avatar}` 
                        : 'avatars/default.png';
                    
                    html += `
                        <div class="chat-item" onclick="openChat(${user.user_id}, 'user')">
                            <div class="chat-avatar">
                                <img src="${avatarSrc}" class="chat-avatar">
                                <div class="chat-status status-${user.status}"></div>
                            </div>
                            <div class="chat-info">
                                <div class="chat-name">${escapeHtml(user.name)}</div>
                                <div class="chat-preview">@${escapeHtml(user.username)} • ${user.status === 'online' ? 'Online' : 'Offline'}</div>
                            </div>
                        </div>
                    `;
                });
                
                container.innerHTML = html || '<div class="text-center text-muted">No users found</div>';
            } catch (error) {
                console.error('Search error:', error);
            }
        }
        
        function showToast(message, type = 'info') {
            const toast = document.createElement('div');
            toast.style.cssText = `
                background: ${type === 'error' ? '#ed4245' : type === 'success' ? '#3ba55d' : '#5865f2'};
                color: white;
                padding: 12px 16px;
                border-radius: 4px;
                margin-bottom: 10px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                animation: slideIn 0.3s ease;
                max-width: 300px;
            `;
            
            toast.innerHTML = `
                <div style="display: flex; align-items: center; gap: 8px;">
                    <i class="fas fa-${type === 'error' ? 'exclamation-circle' : type === 'success' ? 'check-circle' : 'info-circle'}"></i>
                    <span>${escapeHtml(message)}</span>
                </div>
            `;
            
            document.getElementById('toastContainer').appendChild(toast);
            
            setTimeout(() => {
                toast.style.animation = 'slideOut 0.3s ease';
                setTimeout(() => toast.remove(), 300);
            }, 3000);
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // Add CSS for animations
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
        `;
        document.head.appendChild(style);
    </script>
</body>
</html>
