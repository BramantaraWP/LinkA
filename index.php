<?php
/* ===============================
   LINKA - FINAL VERSION
   =============================== */

session_start();
$db = new PDO("sqlite:data.db");
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

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
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender TEXT,
  receiver TEXT,
  content TEXT,
  message_type TEXT DEFAULT 'text',
  file_name TEXT,
  file_size INTEGER,
  is_encrypted INTEGER DEFAULT 1,
  time INTEGER
);

CREATE TABLE IF NOT EXISTS groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  description TEXT,
  avatar TEXT DEFAULT 'group.png',
  created_by TEXT,
  created_at INTEGER
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
  is_encrypted INTEGER DEFAULT 1,
  time INTEGER
);

CREATE TABLE IF NOT EXISTS contact_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_user TEXT,
  to_user TEXT,
  status TEXT DEFAULT 'pending',
  created_at INTEGER
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
");

/* === HELPER FUNCTIONS === */
function getCurrentUser() {
    return isset($_SESSION['username']) ? $_SESSION['username'] : null;
}

function sanitize($input) {
    return htmlspecialchars(strip_tags($input), ENT_QUOTES, 'UTF-8');
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
            $stmt = $db->prepare("INSERT INTO users (username, password, name, created_at) VALUES (?, ?, ?, ?)");
            $stmt->execute([$username, $hashed_password, $name, time()]);

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

            $_SESSION['username'] = $username;
            echo json_encode(['success' => true, 'message' => 'Login successful']);
            break;

        case 'logout':
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

        case 'get_profile':
            $user = $_GET['username'] ?? getCurrentUser();
            $stmt = $db->prepare("SELECT username, name, bio, avatar, theme, privacy FROM users WHERE username = ?");
            $stmt->execute([$user]);
            echo json_encode($stmt->fetch(PDO::FETCH_ASSOC) ?: []);
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

            echo json_encode(['success' => true]);
            break;

        case 'update_avatar':
            $user = getCurrentUser();
            if (!$user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }

            $avatarData = $input['avatar'] ?? '';
            if (preg_match('/^data:image\/(\w+);base64,/', $avatarData, $matches)) {
                $data = base64_decode(substr($avatarData, strpos($avatarData, ',') + 1));
                $extension = $matches[1];
                $filename = $user . '_' . time() . '.' . $extension;
                
                if (!file_exists('avatars')) mkdir('avatars', 0755);
                file_put_contents('avatars/' . $filename, $data);
                
                $stmt = $db->prepare("UPDATE users SET avatar = ? WHERE username = ?");
                $stmt->execute([$filename, $user]);
                
                echo json_encode(['success' => true, 'avatar' => $filename]);
            } else {
                echo json_encode(['error' => 'Invalid image data']);
            }
            break;

        case 'search_users':
            $query = sanitize($_GET['q'] ?? '');
            $user = getCurrentUser();
            
            if (strlen($query) < 2) {
                echo json_encode([]);
                break;
            }

            $search = "%$query%";
            $stmt = $db->prepare("SELECT username, name, avatar, privacy FROM users WHERE (username LIKE ? OR name LIKE ?) AND username != ? LIMIT 20");
            $stmt->execute([$search, $search, $user]);
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Filter by privacy
            $filtered = [];
            foreach ($users as $u) {
                if ($u['privacy'] == 0) {
                    $filtered[] = $u;
                } else {
                    // Check if contact request exists
                    $stmt2 = $db->prepare("SELECT * FROM contact_requests WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)");
                    $stmt2->execute([$user, $u['username'], $u['username'], $user]);
                    if ($stmt2->fetch()) {
                        $filtered[] = $u;
                    }
                }
            }

            echo json_encode($filtered);
            break;

        case 'get_inbox':
            $user = getCurrentUser();
            if (!$user) {
                echo json_encode([]);
                break;
            }

            // Get individual chats
            $stmt = $db->prepare("SELECT DISTINCT 
                CASE 
                    WHEN sender=? THEN receiver 
                    ELSE sender 
                END as contact,
                MAX(time) as last_time
                FROM messages 
                WHERE sender=? OR receiver=?
                GROUP BY contact
                ORDER BY last_time DESC");
            $stmt->execute([$user, $user, $user]);
            $contacts = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $inbox = [];
            foreach ($contacts as $contact) {
                $stmt2 = $db->prepare("SELECT username, name, avatar FROM users WHERE username = ?");
                $stmt2->execute([$contact['contact']]);
                $userData = $stmt2->fetch(PDO::FETCH_ASSOC);
                if ($userData) {
                    $inbox[] = array_merge($userData, [
                        'type' => 'user',
                        'last_time' => $contact['last_time']
                    ]);
                }
            }

            // Get groups
            $stmt3 = $db->prepare("SELECT g.* FROM groups g 
                JOIN group_members gm ON g.id = gm.group_id 
                WHERE gm.username = ? 
                ORDER BY g.created_at DESC");
            $stmt3->execute([$user]);
            $groups = $stmt3->fetchAll(PDO::FETCH_ASSOC);

            foreach ($groups as $group) {
                $inbox[] = [
                    'type' => 'group',
                    'id' => $group['id'],
                    'name' => $group['name'],
                    'avatar' => $group['avatar'],
                    'last_time' => $group['created_at']
                ];
            }

            echo json_encode($inbox);
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

            if (empty($message) && $type === 'text') {
                echo json_encode(['error' => 'Message cannot be empty']);
                break;
            }

            // Check privacy
            $stmt = $db->prepare("SELECT privacy FROM users WHERE username = ?");
            $stmt->execute([$to]);
            $target = $stmt->fetch();

            if ($target && $target['privacy'] == 1) {
                // Check if contact request exists
                $stmt2 = $db->prepare("SELECT * FROM contact_requests WHERE 
                    ((from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)) 
                    AND status = 'accepted'");
                $stmt2->execute([$user, $to, $to, $user]);
                
                if (!$stmt2->fetch()) {
                    // Send contact request
                    $stmt3 = $db->prepare("INSERT OR IGNORE INTO contact_requests (from_user, to_user, created_at) VALUES (?, ?, ?)");
                    $stmt3->execute([$user, $to, time()]);
                    
                    // Send notification
                    $stmt4 = $db->prepare("INSERT INTO notifications (username, type, from_user, content, created_at) VALUES (?, ?, ?, ?, ?)");
                    $stmt4->execute([$to, 'contact_request', $user, 'New contact request from ' . $user, time()]);
                    
                    echo json_encode(['pending' => true]);
                    break;
                }
            }

            // Encrypt and send message
            $encrypted_content = encryptMessage($message);
            
            $stmt5 = $db->prepare("INSERT INTO messages (sender, receiver, content, message_type, file_name, file_size, time) 
                VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt5->execute([$user, $to, $encrypted_content, $type, $file_name, $file_size, time()]);

            // Send notification
            $stmt6 = $db->prepare("INSERT INTO notifications (username, type, from_user, content, created_at) VALUES (?, ?, ?, ?, ?)");
            $stmt6->execute([$to, 'message', $user, 'New message from ' . $user, time()]);

            echo json_encode(['success' => true]);
            break;

        case 'get_messages':
            $user = getCurrentUser();
            $with = sanitize($_GET['with'] ?? '');
            
            if (!$user || !$with) {
                echo json_encode([]);
                break;
            }

            $stmt = $db->prepare("SELECT sender, content, message_type, file_name, file_size, time FROM messages 
                WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?) 
                ORDER BY time ASC");
            $stmt->execute([$user, $with, $with, $user]);
            $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Decrypt messages
            foreach ($messages as &$msg) {
                $msg['content'] = decryptMessage($msg['content']);
            }

            echo json_encode($messages);
            break;

        case 'upload_file':
            $user = getCurrentUser();
            if (!$user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }

            if (!isset($_FILES['file'])) {
                echo json_encode(['error' => 'No file uploaded']);
                break;
            }

            $file = $_FILES['file'];
            $max_size = 15 * 1024 * 1024; // 15MB
            
            if ($file['size'] > $max_size) {
                echo json_encode(['error' => 'File size exceeds 15MB limit']);
                break;
            }

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

            $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
            $filename = 'file_' . $user . '_' . time() . '.' . $extension;
            
            if (!file_exists('uploads')) mkdir('uploads', 0755);
            
            if (move_uploaded_file($file['tmp_name'], 'uploads/' . $filename)) {
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
            $user = getCurrentUser();
            if (!$user) {
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
            $stmt = $db->prepare("INSERT INTO groups (name, description, created_by, created_at) VALUES (?, ?, ?, ?)");
            $stmt->execute([$name, $description, $user, time()]);
            
            $group_id = $db->lastInsertId();

            // Add creator as admin
            $stmt2 = $db->prepare("INSERT INTO group_members (group_id, username, role, joined_at) VALUES (?, ?, ?, ?)");
            $stmt2->execute([$group_id, $user, 'admin', time()]);

            // Add members
            foreach ($members as $member) {
                if ($member !== $user) {
                    $stmt2->execute([$group_id, $member, 'member', time()]);
                }
            }

            echo json_encode(['success' => true, 'group_id' => $group_id]);
            break;

        case 'get_group_messages':
            $user = getCurrentUser();
            $group_id = intval($_GET['group_id'] ?? 0);

            if (!$user || !$group_id) {
                echo json_encode([]);
                break;
            }

            // Check if user is member
            $stmt = $db->prepare("SELECT * FROM group_members WHERE group_id = ? AND username = ?");
            $stmt->execute([$group_id, $user]);
            
            if (!$stmt->fetch()) {
                echo json_encode([]);
                break;
            }

            $stmt2 = $db->prepare("SELECT sender, content, message_type, file_name, file_size, time FROM group_messages 
                WHERE group_id = ? ORDER BY time ASC");
            $stmt2->execute([$group_id]);
            $messages = $stmt2->fetchAll(PDO::FETCH_ASSOC);

            foreach ($messages as &$msg) {
                $msg['content'] = decryptMessage($msg['content']);
            }

            echo json_encode($messages);
            break;

        case 'send_group_message':
            $user = getCurrentUser();
            if (!$user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }

            $group_id = intval($input['group_id'] ?? 0);
            $message = sanitize($input['message'] ?? '');
            $type = $input['type'] ?? 'text';

            if (empty($message) && $type === 'text') {
                echo json_encode(['error' => 'Message cannot be empty']);
                break;
            }

            // Check if user is member
            $stmt = $db->prepare("SELECT * FROM group_members WHERE group_id = ? AND username = ?");
            $stmt->execute([$group_id, $user]);
            
            if (!$stmt->fetch()) {
                echo json_encode(['error' => 'Not a member']);
                break;
            }

            $encrypted_content = encryptMessage($message);
            
            $stmt2 = $db->prepare("INSERT INTO group_messages (group_id, sender, content, message_type, time) VALUES (?, ?, ?, ?, ?)");
            $stmt2->execute([$group_id, $user, $encrypted_content, $type, time()]);

            echo json_encode(['success' => true]);
            break;

        case 'get_contact_requests':
            $user = getCurrentUser();
            if (!$user) {
                echo json_encode([]);
                break;
            }

            $stmt = $db->prepare("SELECT cr.*, u.name, u.avatar FROM contact_requests cr 
                JOIN users u ON cr.from_user = u.username 
                WHERE cr.to_user = ? AND cr.status = 'pending' 
                ORDER BY cr.created_at DESC");
            $stmt->execute([$user]);
            echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
            break;

        case 'handle_contact_request':
            $user = getCurrentUser();
            if (!$user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }

            $request_id = intval($input['request_id'] ?? 0);
            $action = $input['action'] ?? ''; // 'accept' or 'reject'

            if (!$request_id || !in_array($action, ['accept', 'reject'])) {
                echo json_encode(['error' => 'Invalid request']);
                break;
            }

            $stmt = $db->prepare("UPDATE contact_requests SET status = ? WHERE id = ? AND to_user = ?");
            $stmt->execute([$action . 'ed', $request_id, $user]);

            echo json_encode(['success' => true]);
            break;

        case 'get_notifications':
            $user = getCurrentUser();
            if (!$user) {
                echo json_encode([]);
                break;
            }

            $stmt = $db->prepare("SELECT * FROM notifications WHERE username = ? ORDER BY created_at DESC LIMIT 20");
            $stmt->execute([$user]);
            echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
            break;

        case 'mark_notification_read':
            $user = getCurrentUser();
            if (!$user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }

            $notification_id = intval($input['notification_id'] ?? 0);
            if ($notification_id) {
                $stmt = $db->prepare("UPDATE notifications SET is_read = 1 WHERE id = ? AND username = ?");
                $stmt->execute([$notification_id, $user]);
            }
            echo json_encode(['success' => true]);
            break;

        case 'update_settings':
            $user = getCurrentUser();
            if (!$user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }

            $theme = sanitize($input['theme'] ?? 'black');
            $notifications = intval($input['notifications'] ?? 1);

            $stmt = $db->prepare("UPDATE users SET theme = ?, notifications = ? WHERE username = ?");
            $stmt->execute([$theme, $notifications, $user]);

            echo json_encode(['success' => true]);
            break;

        default:
            echo json_encode(['error' => 'Invalid API endpoint']);
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
<title>LinkA - Secure Messenger</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
/* ===== VERCEL BLACK & WHITE THEME ===== */
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
    --shadow: 0 1px 3px 0 rgba(0,0,0,0.1), 0 1px 2px 0 rgba(0,0,0,0.06);
    --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -2px rgba(0,0,0,0.05);
    --radius: 0.5rem;
    --radius-lg: 0.75rem;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: var(--white);
    color: var(--black);
    margin: 0;
    padding: 0;
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
    position: fixed;
    height: 100vh;
    z-index: 50;
    transition: transform 0.3s ease;
}

.user-panel {
    padding: 1rem;
    border-bottom: 1px solid var(--gray-200);
    display: flex;
    align-items: center;
    gap: 0.75rem;
    background: var(--white);
}

.avatar {
    width: 2.5rem;
    height: 2.5rem;
    border-radius: 50%;
    object-fit: cover;
    border: 2px solid var(--black);
    background: var(--gray-100);
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

.nav-item i {
    width: 1rem;
    text-align: center;
}

.inbox-list {
    flex: 1;
    overflow-y: auto;
    padding: 0.5rem 0;
}

.contact-item {
    display: flex;
    align-items: center;
    padding: 0.75rem 1rem;
    gap: 0.75rem;
    cursor: pointer;
    transition: background 0.2s;
    border-bottom: 1px solid var(--gray-100);
}

.contact-item:hover {
    background: var(--gray-50);
}

.contact-item.active {
    background: var(--gray-100);
}

.contact-avatar {
    width: 2.25rem;
    height: 2.25rem;
    border-radius: 50%;
    object-fit: cover;
    background: var(--gray-200);
}

.contact-info h4 {
    margin: 0;
    font-size: 0.875rem;
    font-weight: 500;
}

.contact-info span {
    font-size: 0.75rem;
    color: var(--gray-500);
    display: block;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 180px;
}

.badge {
    background: var(--black);
    color: var(--white);
    font-size: 0.75rem;
    padding: 0.125rem 0.375rem;
    border-radius: 9999px;
    margin-left: auto;
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
}

.chat-actions {
    display: flex;
    gap: 0.5rem;
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
    animation: fadeIn 0.3s ease;
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

.message-file {
    padding: 0.75rem;
    background: var(--gray-50);
    border-radius: var(--radius);
    margin-top: 0.5rem;
    border: 1px solid var(--gray-200);
}

.file-info {
    display: flex;
    align-items: center;
    gap: 0.75rem;
}

.file-icon {
    font-size: 1.5rem;
    color: var(--gray-600);
}

.file-details {
    flex: 1;
}

.file-name {
    font-weight: 500;
    margin-bottom: 0.125rem;
}

.file-size {
    font-size: 0.75rem;
    color: var(--gray-500);
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

.btn-secondary {
    background: var(--gray-100);
    color: var(--black);
}

.btn-secondary:hover {
    background: var(--gray-200);
}

.btn-danger {
    background: var(--danger);
}

.btn-danger:hover {
    background: #b91c1c;
}

.btn-success {
    background: var(--success);
}

.btn-icon {
    width: 2.5rem;
    height: 2.5rem;
    padding: 0;
    border-radius: 50%;
}

/* ===== MODALS ===== */
.modal {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0,0,0,0.5);
    z-index: 1000;
    align-items: center;
    justify-content: center;
    padding: 1rem;
}

.modal.active {
    display: flex;
}

.modal-content {
    background: var(--white);
    border-radius: var(--radius-lg);
    width: 100%;
    max-width: 500px;
    max-height: 90vh;
    overflow-y: auto;
    box-shadow: var(--shadow-lg);
    animation: modalSlideIn 0.3s ease;
}

@keyframes modalSlideIn {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
}

.modal-header {
    padding: 1.25rem 1.5rem;
    border-bottom: 1px solid var(--gray-200);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.modal-header h3 {
    margin: 0;
    font-size: 1.25rem;
    font-weight: 600;
}

.modal-close {
    background: none;
    border: none;
    color: var(--gray-500);
    cursor: pointer;
    padding: 0.25rem;
    border-radius: 50%;
    transition: background 0.2s;
}

.modal-close:hover {
    background: var(--gray-100);
}

.modal-body {
    padding: 1.5rem;
}

/* ===== FORMS ===== */
.form-group {
    margin-bottom: 1rem;
}

.form-label {
    display: block;
    margin-bottom: 0.5rem;
    color: var(--gray-700);
    font-size: 0.875rem;
    font-weight: 500;
}

.form-input {
    width: 100%;
    padding: 0.625rem 0.875rem;
    background: var(--white);
    border: 1px solid var(--gray-300);
    border-radius: var(--radius);
    color: var(--black);
    font-size: 0.875rem;
    outline: none;
    transition: border-color 0.2s;
}

.form-input:focus {
    border-color: var(--black);
}

.form-textarea {
    min-height: 6rem;
    resize: vertical;
}

.form-checkbox {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
    font-size: 0.875rem;
}

.form-checkbox input {
    width: 1rem;
    height: 1rem;
    accent-color: var(--black);
}

/* ===== SEARCH RESULTS ===== */
.search-results {
    max-height: 300px;
    overflow-y: auto;
    margin-top: 1rem;
}

.search-item {
    display: flex;
    align-items: center;
    padding: 0.75rem;
    border: 1px solid var(--gray-200);
    border-radius: var(--radius);
    margin-bottom: 0.5rem;
    cursor: pointer;
    transition: background 0.2s;
}

.search-item:hover {
    background: var(--gray-50);
}

/* ===== NOTIFICATIONS ===== */
.notification-badge {
    background: var(--danger);
    color: var(--white);
    font-size: 0.75rem;
    width: 1.25rem;
    height: 1.25rem;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    position: absolute;
    top: -0.25rem;
    right: -0.25rem;
}

.notification-item {
    padding: 0.75rem;
    border-bottom: 1px solid var(--gray-200);
    display: flex;
    align-items: center;
    gap: 0.75rem;
}

.notification-item.unread {
    background: var(--gray-50);
}

/* ===== AUTH SCREENS ===== */
.auth-screen {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    background: var(--white);
    padding: 1rem;
}

.auth-container {
    width: 100%;
    max-width: 400px;
    background: var(--white);
    border: 1px solid var(--gray-200);
    border-radius: var(--radius-lg);
    padding: 2rem;
    box-shadow: var(--shadow-lg);
}

.auth-header {
    text-align: center;
    margin-bottom: 2rem;
}

.auth-header h1 {
    margin: 0 0 0.5rem 0;
    font-size: 1.875rem;
    font-weight: 700;
}

.auth-header p {
    color: var(--gray-500);
    margin: 0;
}

/* ===== UTILITY ===== */
.hidden { display: none !important; }
.text-center { text-align: center; }
.mt-4 { margin-top: 1rem; }
.mb-4 { margin-bottom: 1rem; }
.w-full { width: 100%; }

/* ===== SCROLLBAR ===== */
::-webkit-scrollbar {
    width: 8px;
}

::-webkit-scrollbar-track {
    background: var(--gray-100);
}

::-webkit-scrollbar-thumb {
    background: var(--gray-400);
    border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
    background: var(--gray-500);
}

/* ===== RESPONSIVE ===== */
@media (max-width: 768px) {
    .sidebar {
        transform: translateX(-100%);
        width: 100%;
        max-width: 300px;
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
    }
    
    .message-bubble {
        max-width: 85%;
    }
    
    .modal-content {
        margin: 1rem;
    }
}

@media (min-width: 769px) {
    .mobile-menu-btn {
        display: none;
    }
}
</style>
</head>
<body>

<!-- AUTH SCREEN -->
<div id="authScreen" class="auth-screen">
    <div class="auth-container">
        <div class="auth-header">
            <h1>LinkA</h1>
            <p>Secure messaging with end-to-end encryption</p>
        </div>
        
        <div id="loginForm">
            <div class="form-group">
                <label class="form-label">Username</label>
                <input type="text" class="form-input" id="loginUsername" placeholder="Enter username">
            </div>
            <div class="form-group">
                <label class="form-label">Password</label>
                <input type="password" class="form-input" id="loginPassword" placeholder="Enter password">
            </div>
            <button class="btn w-full" onclick="login()">Login</button>
            <p class="text-center mt-4" style="color: var(--gray-500);">
                Don't have an account? <a href="#" onclick="showRegisterForm()" style="color: var(--black); text-decoration: underline;">Register</a>
            </p>
        </div>
        
        <div id="registerForm" class="hidden">
            <div class="form-group">
                <label class="form-label">Username</label>
                <input type="text" class="form-input" id="registerUsername" placeholder="Choose username">
            </div>
            <div class="form-group">
                <label class="form-label">Name</label>
                <input type="text" class="form-input" id="registerName" placeholder="Your full name">
            </div>
            <div class="form-group">
                <label class="form-label">Password</label>
                <input type="password" class="form-input" id="registerPassword" placeholder="Choose password">
            </div>
            <div class="form-group">
                <label class="form-label">Confirm Password</label>
                <input type="password" class="form-input" id="registerConfirmPassword" placeholder="Confirm password">
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
            <div class="user-info">
                <h3 id="userName">Loading...</h3>
                <span id="userStatus">Online</span>
            </div>
            <div class="notification-badge hidden" id="notificationBadge">0</div>
        </div>
        
        <div class="sidebar-nav">
            <div class="nav-item active" onclick="showSection('inbox')">
                <i class="fas fa-inbox"></i>
                <span>Inbox</span>
            </div>
            <div class="nav-item" onclick="showModal('searchModal')">
                <i class="fas fa-search"></i>
                <span>Search</span>
            </div>
            <div class="nav-item" onclick="showModal('contactsModal')">
                <i class="fas fa-user-plus"></i>
                <span>Contacts</span>
            </div>
            <div class="nav-item" onclick="showModal('groupsModal')">
                <i class="fas fa-users"></i>
                <span>Groups</span>
            </div>
            <div class="nav-item" onclick="showModal('profileModal')">
                <i class="fas fa-user-edit"></i>
                <span>Profile</span>
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
            <!-- Inbox items will be loaded here -->
        </div>
    </div>
    
    <!-- Main Content -->
    <div class="main-content">
        <div class="chat-header">
            <div class="chat-header-info">
                <img src="avatars/default.png" class="avatar" id="chatAvatar">
                <div>
                    <h3 id="chatWith">Select a chat</h3>
                    <span id="chatStatus">Start a conversation</span>
                </div>
            </div>
            <div class="chat-actions" id="chatActions" style="display: none;">
                <button class="btn btn-icon btn-secondary" onclick="toggleEncryption()">
                    <i class="fas fa-lock" id="encryptionIcon"></i>
                </button>
                <button class="btn btn-icon btn-danger" onclick="clearChat()">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        </div>
        
        <div class="chat-container" id="chatContainer">
            <div class="text-center" style="padding: 3rem; color: var(--gray-500);">
                <i class="fas fa-comments" style="font-size: 3rem; margin-bottom: 1rem;"></i>
                <h3>No chat selected</h3>
                <p>Select a conversation or start a new one</p>
            </div>
        </div>
        
        <div class="chat-input-area hidden" id="chatInputArea">
            <button class="btn btn-icon btn-secondary" onclick="showFileUpload()">
                <i class="fas fa-paperclip"></i>
            </button>
            <input type="text" class="chat-input" id="messageInput" placeholder="Type a message..." onkeypress="if(event.key === 'Enter') sendMessage()">
            <button class="btn btn-icon" onclick="sendMessage()">
                <i class="fas fa-paper-plane"></i>
            </button>
            <input type="file" id="fileInput" class="hidden" accept="image/*,application/pdf,application/msword,text/plain,application/zip">
        </div>
    </div>
</div>

<!-- MODALS -->
<!-- Search Modal -->
<div class="modal" id="searchModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Search Users</h3>
            <button class="modal-close" onclick="hideModal('searchModal')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="modal-body">
            <div class="form-group">
                <input type="text" class="form-input" id="searchInput" placeholder="Search by username or name..." onkeyup="searchUsers()">
            </div>
            <div class="search-results" id="searchResults">
                <!-- Results will appear here -->
            </div>
        </div>
    </div>
</div>

<!-- Profile Modal -->
<div class="modal" id="profileModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Edit Profile</h3>
            <button class="modal-close" onclick="hideModal('profileModal')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="modal-body">
            <div class="text-center mb-4">
                <img src="avatars/default.png" class="avatar" id="editAvatar" style="width: 5rem; height: 5rem; cursor: pointer;" onclick="document.getElementById('avatarInput').click()">
                <input type="file" id="avatarInput" class="hidden" accept="image/*">
                <p class="text-sm" style="color: var(--gray-500); margin-top: 0.5rem;">Click to change avatar</p>
            </div>
            <div class="form-group">
                <label class="form-label">Username</label>
                <input type="text" class="form-input" id="editUsername" readonly>
            </div>
            <div class="form-group">
                <label class="form-label">Display Name</label>
                <input type="text" class="form-input" id="editName">
            </div>
            <div class="form-group">
                <label class="form-label">Bio</label>
                <textarea class="form-input form-textarea" id="editBio"></textarea>
            </div>
            <div class="form-group">
                <label class="form-checkbox">
                    <input type="checkbox" id="editPrivacy">
                    <span>Private account (only contacts can message me)</span>
                </label>
            </div>
            <button class="btn w-full" onclick="updateProfile()">Save Changes</button>
        </div>
    </div>
</div>

<!-- Contacts Modal -->
<div class="modal" id="contactsModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Contact Requests</h3>
            <button class="modal-close" onclick="hideModal('contactsModal')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="modal-body">
            <div id="contactRequests">
                <!-- Contact requests will appear here -->
            </div>
        </div>
    </div>
</div>

<!-- Groups Modal -->
<div class="modal" id="groupsModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Groups</h3>
            <button class="modal-close" onclick="hideModal('groupsModal')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="modal-body">
            <button class="btn w-full mb-4" onclick="showModal('createGroupModal')">
                <i class="fas fa-plus"></i> Create New Group
            </button>
            <div id="groupsList">
                <!-- Groups will appear here -->
            </div>
        </div>
    </div>
</div>

<!-- Create Group Modal -->
<div class="modal" id="createGroupModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Create Group</h3>
            <button class="modal-close" onclick="hideModal('createGroupModal')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="modal-body">
            <div class="form-group">
                <label class="form-label">Group Name</label>
                <input type="text" class="form-input" id="groupName" placeholder="Enter group name">
            </div>
            <div class="form-group">
                <label class="form-label">Description</label>
                <textarea class="form-input form-textarea" id="groupDescription" placeholder="Group description (optional)"></textarea>
            </div>
            <div class="form-group">
                <label class="form-label">Add Members</label>
                <input type="text" class="form-input" id="groupSearch" placeholder="Search users..." onkeyup="searchGroupMembers()">
                <div id="selectedMembers" class="mt-2" style="min-height: 2rem;">
                    <!-- Selected members will appear here -->
                </div>
                <div id="groupSearchResults" class="search-results">
                    <!-- Search results will appear here -->
                </div>
            </div>
            <button class="btn w-full" onclick="createGroup()">Create Group</button>
        </div>
    </div>
</div>

<!-- Settings Modal -->
<div class="modal" id="settingsModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Settings</h3>
            <button class="modal-close" onclick="hideModal('settingsModal')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="modal-body">
            <div class="form-group">
                <label class="form-label">Theme</label>
                <select class="form-input" id="themeSelect">
                    <option value="black">Black</option>
                    <option value="white">White</option>
                    <option value="gray">Gray</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-checkbox">
                    <input type="checkbox" id="notificationsToggle" checked>
                    <span>Enable notifications</span>
                </label>
            </div>
            <button class="btn btn-secondary w-full mb-2" onclick="requestNotificationPermission()">
                <i class="fas fa-bell"></i> Enable Browser Notifications
            </button>
            <button class="btn w-full" onclick="saveSettings()">Save Settings</button>
        </div>
    </div>
</div>

<!-- Toast Container -->
<div id="toastContainer" style="position: fixed; bottom: 1rem; right: 1rem; z-index: 9999;"></div>

<script>
// ===== GLOBAL STATE =====
let currentUser = null;
let currentChat = null;
let currentChatType = null; // 'user' or 'group'
let notificationsEnabled = false;
let notificationPermission = Notification.permission;
let selectedFiles = [];
let groupMembers = [];

// ===== INITIALIZATION =====
document.addEventListener('DOMContentLoaded', function() {
    checkAuth();
    
    // Request notification permission
    if ('Notification' in window && Notification.permission === 'default') {
        setTimeout(() => {
            showToast('Enable notifications for message alerts', 'info');
        }, 3000);
    }
});

// ===== AUTHENTICATION =====
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

function showLoginForm() {
    document.getElementById('loginForm').classList.remove('hidden');
    document.getElementById('registerForm').classList.add('hidden');
}

function showRegisterForm() {
    document.getElementById('loginForm').classList.add('hidden');
    document.getElementById('registerForm').classList.remove('hidden');
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
    const confirmPassword = document.getElementById('registerConfirmPassword').value.trim();
    
    if (!username || !name || !password || !confirmPassword) {
        showToast('Please fill all fields', 'error');
        return;
    }
    
    if (password !== confirmPassword) {
        showToast('Passwords do not match', 'error');
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
            body: JSON.stringify({ username, name, password, confirm_password: confirmPassword })
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

async function logout() {
    try {
        await fetch('?api=logout');
        currentUser = null;
        document.getElementById('appContainer').classList.add('hidden');
        document.getElementById('authScreen').classList.remove('auth-screen');
        document.getElementById('authScreen').style.display = 'flex';
        showToast('Logged out successfully', 'success');
    } catch (error) {
        console.error('Logout error:', error);
    }
}

// ===== APP FUNCTIONS =====
function loadApp() {
    document.getElementById('authScreen').style.display = 'none';
    document.getElementById('appContainer').classList.remove('hidden');
    
    loadUserProfile();
    loadInbox();
    loadNotifications();
    loadContactRequests();
    
    // Auto-refresh
    setInterval(() => {
        if (currentChat) {
            if (currentChatType === 'user') {
                loadMessages();
            } else {
                loadGroupMessages();
            }
        }
        loadInbox();
        loadNotifications();
        loadContactRequests();
    }, 3000);
}

async function loadUserProfile() {
    try {
        const response = await fetch(`?api=get_profile`);
        const data = await response.json();
        
        if (data.username) {
            document.getElementById('userName').textContent = data.name || data.username;
            document.getElementById('editUsername').value = data.username;
            document.getElementById('editName').value = data.name || '';
            document.getElementById('editBio').value = data.bio || '';
            document.getElementById('editPrivacy').checked = data.privacy == 1;
            
            // Load avatar from localStorage or server
            let avatar = localStorage.getItem(`avatar_${data.username}`);
            if (avatar) {
                document.getElementById('userAvatar').src = avatar;
                document.getElementById('editAvatar').src = avatar;
            } else if (data.avatar && data.avatar !== 'default.png') {
                const avatarUrl = `avatars/${data.avatar}`;
                document.getElementById('userAvatar').src = avatarUrl;
                document.getElementById('editAvatar').src = avatarUrl;
                localStorage.setItem(`avatar_${data.username}`, avatarUrl);
            }
        }
    } catch (error) {
        console.error('Profile load error:', error);
    }
}

async function updateProfile() {
    const name = document.getElementById('editName').value.trim();
    const bio = document.getElementById('editBio').value.trim();
    const privacy = document.getElementById('editPrivacy').checked ? 1 : 0;
    
    try {
        const response = await fetch('?api=update_profile', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, bio, privacy })
        });
        
        const data = await response.json();
        
        if (data.success) {
            hideModal('profileModal');
            loadUserProfile();
            showToast('Profile updated', 'success');
        }
    } catch (error) {
        showToast('Update failed', 'error');
    }
}

// Handle avatar upload
document.getElementById('avatarInput').addEventListener('change', async function(e) {
    if (e.target.files[0]) {
        const reader = new FileReader();
        reader.onload = async function(event) {
            const base64Image = event.target.result;
            
            try {
                const response = await fetch('?api=update_avatar', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ avatar: base64Image })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('userAvatar').src = base64Image;
                    document.getElementById('editAvatar').src = base64Image;
                    localStorage.setItem(`avatar_${currentUser}`, base64Image);
                    showToast('Avatar updated', 'success');
                }
            } catch (error) {
                showToast('Avatar upload failed', 'error');
            }
        };
        reader.readAsDataURL(e.target.files[0]);
    }
});

// ===== INBOX & CHAT =====
async function loadInbox() {
    try {
        const response = await fetch('?api=get_inbox');
        const inbox = await response.json();
        
        const container = document.getElementById('inboxList');
        container.innerHTML = '';
        
        if (inbox.length === 0) {
            container.innerHTML = '<div class="text-center" style="padding: 2rem; color: var(--gray-500);">No conversations yet</div>';
            return;
        }
        
        inbox.forEach(item => {
            const div = document.createElement('div');
            div.className = 'contact-item';
            div.onclick = () => {
                if (item.type === 'user') {
                    openChat(item.username, 'user');
                } else {
                    openChat(item.id, 'group', item.name);
                }
            };
            
            let avatarSrc = 'avatars/default.png';
            if (item.avatar && item.avatar !== 'default.png') {
                avatarSrc = `avatars/${item.avatar}`;
            }
            
            if (item.type === 'user') {
                div.innerHTML = `
                    <img src="${avatarSrc}" class="contact-avatar">
                    <div class="contact-info">
                        <h4>${item.name || item.username}</h4>
                        <span>${item.bio || 'No bio'}</span>
                    </div>
                `;
            } else {
                div.innerHTML = `
                    <div class="contact-avatar" style="background: var(--gray-300); display: flex; align-items: center; justify-content: center;">
                        <i class="fas fa-users" style="color: var(--gray-600);"></i>
                    </div>
                    <div class="contact-info">
                        <h4>${item.name}</h4>
                        <span>Group • ${item.member_count || 1} members</span>
                    </div>
                `;
            }
            
            container.appendChild(div);
        });
    } catch (error) {
        console.error('Inbox load error:', error);
    }
}

function openChat(target, type, groupName = '') {
    currentChat = target;
    currentChatType = type;
    
    document.getElementById('chatInputArea').classList.remove('hidden');
    document.getElementById('chatActions').style.display = 'flex';
    
    if (type === 'user') {
        document.getElementById('chatWith').textContent = target;
        document.getElementById('chatStatus').textContent = 'Online';
        
        // Load user avatar
        const cachedAvatar = localStorage.getItem(`avatar_${target}`);
        if (cachedAvatar) {
            document.getElementById('chatAvatar').src = cachedAvatar;
        }
        
        loadMessages();
    } else {
        document.getElementById('chatWith').textContent = groupName || 'Group';
        document.getElementById('chatStatus').textContent = 'Group chat';
        document.getElementById('chatAvatar').src = 'avatars/default.png';
        
        loadGroupMessages();
    }
    
    // Close sidebar on mobile
    if (window.innerWidth <= 768) {
        document.getElementById('sidebar').classList.remove('active');
    }
}

async function loadMessages() {
    if (!currentChat || currentChatType !== 'user') return;
    
    try {
        const response = await fetch(`?api=get_messages?with=${currentChat}`);
        const messages = await response.json();
        
        const container = document.getElementById('chatContainer');
        container.innerHTML = '';
        
        if (messages.length === 0) {
            container.innerHTML = `
                <div class="text-center" style="padding: 3rem; color: var(--gray-500);">
                    <p>No messages yet. Start the conversation!</p>
                </div>
            `;
            return;
        }
        
        messages.forEach(msg => {
            const bubble = document.createElement('div');
            bubble.className = `message-bubble ${msg.sender === currentUser ? 'message-sent' : 'message-received'}`;
            
            const time = new Date(msg.time * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            
            let content = msg.content;
            if (msg.message_type === 'file') {
                content = `
                    <div>${msg.content}</div>
                    <div class="message-file">
                        <div class="file-info">
                            <i class="fas fa-file file-icon"></i>
                            <div class="file-details">
                                <div class="file-name">${msg.file_name}</div>
                                <div class="file-size">${formatFileSize(msg.file_size)}</div>
                            </div>
                            <a href="uploads/${msg.file_name}" class="btn btn-sm btn-secondary" download>
                                <i class="fas fa-download"></i>
                            </a>
                        </div>
                    </div>
                `;
            }
            
            bubble.innerHTML = `
                <div>${content}</div>
                <div class="message-time">${time}</div>
            `;
            
            container.appendChild(bubble);
        });
        
        container.scrollTop = container.scrollHeight;
    } catch (error) {
        console.error('Messages load error:', error);
    }
}

async function sendMessage() {
    const input = document.getElementById('messageInput');
    const message = input.value.trim();
    
    if (!message && selectedFiles.length === 0) return;
    
    let apiUrl, payload;
    
    if (currentChatType === 'user') {
        apiUrl = '?api=send_message';
        payload = {
            to: currentChat,
            message: message || '[File attached]',
            type: selectedFiles.length > 0 ? 'file' : 'text'
        };
        
        if (selectedFiles.length > 0) {
            payload.file_name = selectedFiles[0].name;
            payload.file_size = selectedFiles[0].size;
        }
    } else {
        apiUrl = '?api=send_group_message';
        payload = {
            group_id: currentChat,
            message: message || '[File attached]',
            type: selectedFiles.length > 0 ? 'file' : 'text'
        };
    }
    
    try {
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();
        
        if (data.success) {
            input.value = '';
            selectedFiles = [];
            
            if (currentChatType === 'user') {
                loadMessages();
            } else {
                loadGroupMessages();
            }
            
            // Show browser notification
            if ('Notification' in window && Notification.permission === 'granted') {
                new Notification('LinkA', {
                    body: `Message sent to ${currentChat}`,
                    icon: '/favicon.ico'
                });
            }
        } else if (data.pending) {
            showToast('Contact request sent. Waiting for acceptance.', 'info');
        }
    } catch (error) {
        showToast('Failed to send message', 'error');
    }
}

// ===== FILE UPLOAD =====
function showFileUpload() {
    document.getElementById('fileInput').click();
}

document.getElementById('fileInput').addEventListener('change', async function(e) {
    if (e.target.files[0]) {
        const file = e.target.files[0];
        
        if (file.size > 15 * 1024 * 1024) {
            showToast('File size must be less than 15MB', 'error');
            return;
        }
        
        const formData = new FormData();
        formData.append('file', file);
        
        try {
            const response = await fetch('?api=upload_file', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (data.success) {
                selectedFiles = [{
                    name: data.filename,
                    size: data.size
                }];
                
                // Auto-send file
                sendMessage();
            }
        } catch (error) {
            showToast('File upload failed', 'error');
        }
    }
});

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ===== SEARCH =====
async function searchUsers() {
    const query = document.getElementById('searchInput').value.trim();
    
    if (query.length < 2) {
        document.getElementById('searchResults').innerHTML = '';
        return;
    }
    
    try {
        const response = await fetch(`?api=search_users?q=${encodeURIComponent(query)}`);
        const users = await response.json();
        
        const container = document.getElementById('searchResults');
        container.innerHTML = '';
        
        if (users.length === 0) {
            container.innerHTML = '<div class="text-center" style="padding: 1rem; color: var(--gray-500);">No users found</div>';
            return;
        }
        
        users.forEach(user => {
            const div = document.createElement('div');
            div.className = 'search-item';
            div.onclick = () => {
                hideModal('searchModal');
                openChat(user.username, 'user');
            };
            
            let avatarSrc = 'avatars/default.png';
            if (user.avatar && user.avatar !== 'default.png') {
                avatarSrc = `avatars/${user.avatar}`;
            }
            
            div.innerHTML = `
                <img src="${avatarSrc}" class="contact-avatar">
                <div style="flex: 1;">
                    <div style="font-weight: 500;">${user.name || user.username}</div>
                    <div style="font-size: 0.875rem; color: var(--gray-500);">@${user.username}</div>
                </div>
                ${user.privacy == 1 ? '<span style="color: var(--gray-500); font-size: 0.75rem;">Private</span>' : ''}
            `;
            
            container.appendChild(div);
        });
    } catch (error) {
        console.error('Search error:', error);
    }
}

// ===== GROUPS =====
async function loadGroups() {
    try {
        // This would need a proper API endpoint
        // For now, we'll load from inbox
        const response = await fetch('?api=get_inbox');
        const inbox = await response.json();
        
        const groups = inbox.filter(item => item.type === 'group');
        const container = document.getElementById('groupsList');
        container.innerHTML = '';
        
        if (groups.length === 0) {
            container.innerHTML = '<div class="text-center" style="padding: 1rem; color: var(--gray-500);">No groups yet</div>';
            return;
        }
        
        groups.forEach(group => {
            const div = document.createElement('div');
            div.className = 'search-item';
            div.onclick = () => {
                hideModal('groupsModal');
                openChat(group.id, 'group', group.name);
            };
            
            div.innerHTML = `
                <div class="contact-avatar" style="background: var(--gray-300); display: flex; align-items: center; justify-content: center;">
                    <i class="fas fa-users" style="color: var(--gray-600);"></i>
                </div>
                <div style="flex: 1;">
                    <div style="font-weight: 500;">${group.name}</div>
                    <div style="font-size: 0.875rem; color: var(--gray-500);">${group.description || 'Group chat'}</div>
                </div>
            `;
            
            container.appendChild(div);
        });
    } catch (error) {
        console.error('Groups load error:', error);
    }
}

async function searchGroupMembers() {
    const query = document.getElementById('groupSearch').value.trim();
    
    if (query.length < 2) {
        document.getElementById('groupSearchResults').innerHTML = '';
        return;
    }
    
    try {
        const response = await fetch(`?api=search_users?q=${encodeURIComponent(query)}`);
        const users = await response.json();
        
        const container = document.getElementById('groupSearchResults');
        container.innerHTML = '';
        
        users.forEach(user => {
            if (groupMembers.includes(user.username)) return;
            
            const div = document.createElement('div');
            div.className = 'search-item';
            div.onclick = () => {
                groupMembers.push(user.username);
                updateSelectedMembers();
                document.getElementById('groupSearch').value = '';
                container.innerHTML = '';
            };
            
            div.innerHTML = `
                <img src="avatars/default.png" class="contact-avatar">
                <div style="flex: 1;">
                    <div style="font-weight: 500;">${user.name || user.username}</div>
                    <div style="font-size: 0.875rem; color: var(--gray-500);">@${user.username}</div>
                </div>
                <button class="btn btn-sm">Add</button>
            `;
            
            container.appendChild(div);
        });
    } catch (error) {
        console.error('Group search error:', error);
    }
}

function updateSelectedMembers() {
    const container = document.getElementById('selectedMembers');
    container.innerHTML = '';
    
    groupMembers.forEach(member => {
        const span = document.createElement('span');
        span.className = 'badge';
        span.style.marginRight = '0.5rem';
        span.style.marginBottom = '0.5rem';
        span.style.display = 'inline-block';
        span.innerHTML = `
            ${member}
            <button onclick="removeGroupMember('${member}')" style="background: none; border: none; color: var(--white); margin-left: 0.25rem; cursor: pointer;">
                <i class="fas fa-times"></i>
            </button>
        `;
        container.appendChild(span);
    });
}

function removeGroupMember(member) {
    groupMembers = groupMembers.filter(m => m !== member);
    updateSelectedMembers();
}

async function createGroup() {
    const name = document.getElementById('groupName').value.trim();
    
    if (!name) {
        showToast('Group name is required', 'error');
        return;
    }
    
    if (groupMembers.length === 0) {
        showToast('Add at least one member', 'error');
        return;
    }
    
    try {
        const response = await fetch('?api=create_group', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: name,
                description: document.getElementById('groupDescription').value.trim(),
                members: groupMembers
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            hideModal('createGroupModal');
            groupMembers = [];
            document.getElementById('groupName').value = '';
            document.getElementById('groupDescription').value = '';
            loadGroups();
            showToast('Group created successfully', 'success');
        }
    } catch (error) {
        showToast('Failed to create group', 'error');
    }
}

async function loadGroupMessages() {
    if (!currentChat || currentChatType !== 'group') return;
    
    try {
        const response = await fetch(`?api=get_group_messages?group_id=${currentChat}`);
        const messages = await response.json();
        
        const container = document.getElementById('chatContainer');
        container.innerHTML = '';
        
        messages.forEach(msg => {
            const bubble = document.createElement('div');
            bubble.className = `message-bubble ${msg.sender === currentUser ? 'message-sent' : 'message-received'}`;
            
            const time = new Date(msg.time * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            
            bubble.innerHTML = `
                <div><strong>${msg.sender}:</strong> ${msg.content}</div>
                <div class="message-time">${time}</div>
            `;
            
            container.appendChild(bubble);
        });
        
        container.scrollTop = container.scrollHeight;
    } catch (error) {
        console.error('Group messages error:', error);
    }
}

// ===== CONTACT REQUESTS =====
async function loadContactRequests() {
    try {
        const response = await fetch('?api=get_contact_requests');
        const requests = await response.json();
        
        const container = document.getElementById('contactRequests');
        container.innerHTML = '';
        
        if (requests.length === 0) {
            container.innerHTML = '<div class="text-center" style="padding: 1rem; color: var(--gray-500);">No pending requests</div>';
            return;
        }
        
        requests.forEach(request => {
            const div = document.createElement('div');
            div.className = 'search-item';
            div.innerHTML = `
                <img src="avatars/default.png" class="contact-avatar">
                <div style="flex: 1;">
                    <div style="font-weight: 500;">${request.name || request.from_user}</div>
                    <div style="font-size: 0.875rem; color: var(--gray-500);">Wants to chat with you</div>
                </div>
                <div style="display: flex; gap: 0.5rem;">
                    <button class="btn btn-sm btn-success" onclick="handleContactRequest(${request.id}, 'accept')">Accept</button>
                    <button class="btn btn-sm btn-danger" onclick="handleContactRequest(${request.id}, 'reject')">Reject</button>
                </div>
            `;
            
            container.appendChild(div);
        });
    } catch (error) {
        console.error('Contact requests error:', error);
    }
}

async function handleContactRequest(requestId, action) {
    try {
        const response = await fetch('?api=handle_contact_request', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ request_id: requestId, action: action })
        });
        
        const data = await response.json();
        
        if (data.success) {
            loadContactRequests();
            showToast(`Contact request ${action}ed`, 'success');
        }
    } catch (error) {
        showToast('Failed to process request', 'error');
    }
}

// ===== NOTIFICATIONS =====
async function loadNotifications() {
    try {
        const response = await fetch('?api=get_notifications');
        const notifications = await response.json();
        
        const unreadCount = notifications.filter(n => !n.is_read).length;
        const badge = document.getElementById('notificationBadge');
        
        if (unreadCount > 0) {
            badge.textContent = unreadCount;
            badge.classList.remove('hidden');
        } else {
            badge.classList.add('hidden');
        }
        
        // Show browser notifications for new unread
        if ('Notification' in window && Notification.permission === 'granted') {
            notifications.forEach(notification => {
                if (!notification.is_read) {
                    new Notification('LinkA', {
                        body: notification.content,
                        icon: '/favicon.ico'
                    });
                    
                    // Mark as read
                    fetch('?api=mark_notification_read', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ notification_id: notification.id })
                    });
                }
            });
        }
    } catch (error) {
        console.error('Notifications error:', error);
    }
}

function requestNotificationPermission() {
    if (!('Notification' in window)) {
        showToast('Notifications not supported', 'error');
        return;
    }
    
    if (Notification.permission === 'granted') {
        showToast('Notifications already enabled', 'success');
        return;
    }
    
    Notification.requestPermission().then(permission => {
        notificationPermission = permission;
        if (permission === 'granted') {
            showToast('Notifications enabled', 'success');
        }
    });
}

// ===== SETTINGS =====
async function saveSettings() {
    const theme = document.getElementById('themeSelect').value;
    const notifications = document.getElementById('notificationsToggle').checked ? 1 : 0;
    
    try {
        const response = await fetch('?api=update_settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ theme, notifications })
        });
        
        const data = await response.json();
        
        if (data.success) {
            hideModal('settingsModal');
            showToast('Settings saved', 'success');
            applyTheme(theme);
        }
    } catch (error) {
        showToast('Failed to save settings', 'error');
    }
}

function applyTheme(theme) {
    const root = document.documentElement;
    
    switch (theme) {
        case 'white':
            root.style.setProperty('--black', '#ffffff');
            root.style.setProperty('--white', '#000000');
            break;
        case 'gray':
            root.style.setProperty('--black', '#404040');
            root.style.setProperty('--white', '#f5f5f5');
            break;
        default: // black
            root.style.setProperty('--black', '#000000');
            root.style.setProperty('--white', '#ffffff');
    }
}

// ===== MODAL FUNCTIONS =====
function showModal(id) {
    if (id === 'groupsModal') loadGroups();
    if (id === 'contactsModal') loadContactRequests();
    
    document.getElementById(id).classList.add('active');
}

function hideModal(id) {
    document.getElementById(id).classList.remove('active');
}

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('active');
}

function showSection(section) {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    event.target.closest('.nav-item').classList.add('active');
    
    // Load appropriate content
    if (section === 'inbox') {
        loadInbox();
    }
}

// ===== UTILITY FUNCTIONS =====
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.style.cssText = `
        background: ${type === 'error' ? '#dc2626' : type === 'success' ? '#16a34a' : '#000000'};
        color: white;
        padding: 0.75rem 1rem;
        border-radius: var(--radius);
        margin-bottom: 0.5rem;
        box-shadow: var(--shadow);
        animation: slideIn 0.3s ease;
    `;
    
    toast.innerHTML = `
        <div style="display: flex; align-items: center; gap: 0.5rem;">
            <i class="fas fa-${type === 'error' ? 'exclamation-circle' : type === 'success' ? 'check-circle' : 'info-circle'}"></i>
            <span>${message}</span>
        </div>
    `;
    
    document.getElementById('toastContainer').appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Add animation styles
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
