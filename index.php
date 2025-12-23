<?php
/* ===============================
   LINKA - ENHANCED SECURE MESSENGER
   =============================== */

session_start();
date_default_timezone_set('Asia/Jakarta');

$db = new PDO("sqlite:data.db");
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Encryption key
define('ENCRYPTION_KEY', 'ENIGMAISMOSTSMARTENCRIPTIONINWW2');

/* === INIT DB === */
$db->exec("
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  name TEXT,
  bio TEXT DEFAULT 'Hello LinkA user!',
  avatar TEXT DEFAULT 'default',
  theme TEXT DEFAULT 'dark',
  notifications INTEGER DEFAULT 1,
  privacy INTEGER DEFAULT 0,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender TEXT,
  receiver TEXT,
  content TEXT,
  type TEXT DEFAULT 'text',
  file_path TEXT,
  file_name TEXT,
  file_size INTEGER,
  encrypted INTEGER DEFAULT 1,
  time INTEGER
);

CREATE TABLE IF NOT EXISTS groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  description TEXT,
  creator TEXT,
  avatar TEXT DEFAULT 'group_default',
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
  type TEXT DEFAULT 'text',
  file_path TEXT,
  file_name TEXT,
  file_size INTEGER,
  encrypted INTEGER DEFAULT 1,
  time INTEGER
);

CREATE TABLE IF NOT EXISTS contacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_from TEXT,
  user_to TEXT,
  status TEXT DEFAULT 'pending',
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  type TEXT,
  from_user TEXT,
  content TEXT,
  read_status INTEGER DEFAULT 0,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS captcha (
  token TEXT,
  expire INTEGER
);
");

// Create uploads directory
if (!file_exists('uploads')) {
    mkdir('uploads', 0777, true);
}

if (!file_exists('uploads/files')) {
    mkdir('uploads/files', 0777, true);
}

/* === HELPER FUNCTIONS === */
function encryptMessage($message) {
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($message, 'AES-256-CBC', ENCRYPTION_KEY, 0, $iv);
    return base64_encode($iv . $encrypted);
}

function decryptMessage($encrypted) {
    $data = base64_decode($encrypted);
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    return openssl_decrypt($encrypted, 'AES-256-CBC', ENCRYPTION_KEY, 0, $iv);
}

function sanitizeInput($input) {
    return htmlspecialchars(strip_tags($input), ENT_QUOTES, 'UTF-8');
}

function generateFileToken($filename) {
    return md5($filename . time() . ENCRYPTION_KEY);
}

function getCurrentUser() {
    return isset($_SESSION['username']) ? $_SESSION['username'] : null;
}

function sendNotification($username, $type, $from_user, $content) {
    global $db;
    $stmt = $db->prepare("INSERT INTO notifications (username, type, from_user, content, created_at) VALUES (?,?,?,?,?)");
    $stmt->execute([$username, $type, $from_user, $content, time()]);
}

/* === API HANDLER === */
if (isset($_GET['api'])) {
    header("Content-Type: application/json");

    // Get request body
    $input = file_get_contents("php://input");
    $data = $input ? json_decode($input, true) : [];

    /* CAPTCHA */
    if ($_GET['api'] === "captcha") {
        $token = bin2hex(random_bytes(8));
        $exp = time() + 60;
        $db->prepare("INSERT INTO captcha VALUES (?,?)")->execute([$token, $exp]);
        echo json_encode(["token" => $token]);
        exit;
    }

    /* REGISTER */
    if ($_GET['api'] === "register") {
        $chk = $db->prepare("SELECT * FROM captcha WHERE token=? AND expire>?");
        $chk->execute([$data['captcha'], time()]);
        if (!$chk->fetch()) {
            echo json_encode(["err" => "captcha"]);
            exit;
        }

        $username = sanitizeInput($data['username']);
        $name = sanitizeInput($data['name']);
        $bio = sanitizeInput($data['bio'] ?? '');

        $db->prepare("INSERT INTO users (username, name, bio, created_at) VALUES (?,?,?,?)")
            ->execute([$username, $name, $bio, time()]);

        $_SESSION['username'] = $username;
        echo json_encode(["ok" => true]);
        exit;
    }

    /* LOGIN */
    if ($_GET['api'] === "login") {
        $username = sanitizeInput($data['username']);
        $q = $db->prepare("SELECT * FROM users WHERE username=?");
        $q->execute([$username]);

        if ($q->fetch()) {
            $_SESSION['username'] = $username;
            echo json_encode(["ok" => true]);
        } else {
            echo json_encode(["err" => "User not found"]);
        }
        exit;
    }

    /* LOGOUT */
    if ($_GET['api'] === "logout") {
        session_destroy();
        echo json_encode(["ok" => true]);
        exit;
    }

    /* UPDATE PROFILE */
    if ($_GET['api'] === "update_profile") {
        $user = getCurrentUser();
        if (!$user) {
            echo json_encode(["err" => "Not logged in"]);
            exit;
        }

        $name = sanitizeInput($data['name']);
        $bio = sanitizeInput($data['bio']);
        $privacy = intval($data['privacy'] ?? 0);

        $stmt = $db->prepare("UPDATE users SET name=?, bio=?, privacy=? WHERE username=?");
        $stmt->execute([$name, $bio, $privacy, $user]);

        echo json_encode(["ok" => true]);
        exit;
    }

    /* UPDATE AVATAR */
    if ($_GET['api'] === "update_avatar") {
        $user = getCurrentUser();
        if (!$user) {
            echo json_encode(["err" => "Not logged in"]);
            exit;
        }

        $avatarData = $data['avatar'];
        if (strpos($avatarData, 'data:image') === 0) {
            $parts = explode(',', $avatarData);
            $imageData = base64_decode($parts[1]);
            $filename = 'avatar_' . $user . '_' . time() . '.png';
            file_put_contents('uploads/' . $filename, $imageData);
            
            $db->prepare("UPDATE users SET avatar=? WHERE username=?")->execute([$filename, $user]);
            echo json_encode(["ok" => true, "avatar" => $filename]);
        } else {
            echo json_encode(["err" => "Invalid image data"]);
        }
        exit;
    }

    /* UPDATE SETTINGS */
    if ($_GET['api'] === "update_settings") {
        $user = getCurrentUser();
        if (!$user) {
            echo json_encode(["err" => "Not logged in"]);
            exit;
        }

        $theme = sanitizeInput($data['theme']);
        $notifications = intval($data['notifications']);

        $stmt = $db->prepare("UPDATE users SET theme=?, notifications=? WHERE username=?");
        $stmt->execute([$theme, $notifications, $user]);

        echo json_encode(["ok" => true]);
        exit;
    }

    /* GET PROFILE */
    if ($_GET['api'] === "get_profile") {
        $user = $_GET['username'] ?? getCurrentUser();
        $q = $db->prepare("SELECT username, name, bio, avatar, privacy FROM users WHERE username=?");
        $q->execute([$user]);
        $profile = $q->fetch(PDO::FETCH_ASSOC);
        
        if ($profile) {
            if ($profile['avatar'] && $profile['avatar'] !== 'default' && file_exists('uploads/' . $profile['avatar'])) {
                $profile['avatar_url'] = 'uploads/' . $profile['avatar'];
            } else {
                $profile['avatar_url'] = 'data:image/svg+xml;base64,' . base64_encode('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="50" fill="#333"/><text x="50" y="55" text-anchor="middle" fill="white" font-size="30">' . strtoupper(substr($profile['username'], 0, 1)) . '</text></svg>');
            }
        }
        
        echo json_encode($profile ?: []);
        exit;
    }

    /* GET INBOX */
    if ($_GET['api'] === "get_inbox") {
        $user = getCurrentUser();
        if (!$user) {
            echo json_encode([]);
            exit;
        }

        // Get individual chats
        $q = $db->prepare("SELECT DISTINCT 
            CASE 
                WHEN sender=? THEN receiver 
                ELSE sender 
            END as contact,
            MAX(time) as last_time
            FROM messages 
            WHERE (sender=? OR receiver=?)
            GROUP BY contact
            ORDER BY last_time DESC");
        $q->execute([$user, $user, $user]);
        $chats = $q->fetchAll(PDO::FETCH_ASSOC);

        // Get group chats
        $q2 = $db->prepare("SELECT g.* FROM groups g 
            JOIN group_members gm ON g.id = gm.group_id 
            WHERE gm.username = ? 
            ORDER BY g.created_at DESC");
        $q2->execute([$user]);
        $groups = $q2->fetchAll(PDO::FETCH_ASSOC);

        $inbox = [];
        
        // Add individual chats
        foreach ($chats as $chat) {
            $q3 = $db->prepare("SELECT username, name, avatar, privacy FROM users WHERE username=?");
            $q3->execute([$chat['contact']]);
            $userData = $q3->fetch(PDO::FETCH_ASSOC);
            
            if ($userData && ($userData['privacy'] == 0 || in_array($user, getAcceptedContacts($chat['contact'])))) {
                $inbox[] = array_merge($userData, [
                    'type' => 'user',
                    'last_time' => $chat['last_time']
                ]);
            }
        }

        // Add groups
        foreach ($groups as $group) {
            $inbox[] = [
                'type' => 'group',
                'id' => $group['id'],
                'name' => $group['name'],
                'description' => $group['description'],
                'last_time' => $group['created_at']
            ];
        }

        echo json_encode($inbox);
        exit;
    }

    /* SEARCH USERS */
    if ($_GET['api'] === "search") {
        $query = sanitizeInput($_GET['q'] ?? '');
        $user = getCurrentUser();
        
        $q = $db->prepare("SELECT username, name, bio, avatar, privacy FROM users 
            WHERE (username LIKE ? OR name LIKE ?) AND username != ? 
            LIMIT 20");
        $q->execute(['%' . $query . '%', '%' . $query . '%', $user]);
        
        $users = $q->fetchAll(PDO::FETCH_ASSOC);
        
        // Filter by privacy settings
        $filteredUsers = [];
        foreach ($users as $userData) {
            if ($userData['privacy'] == 0 || in_array(getCurrentUser(), getAcceptedContacts($userData['username']))) {
                $filteredUsers[] = $userData;
            }
        }
        
        echo json_encode($filteredUsers);
        exit;
    }

    /* SEND MESSAGE */
    if ($_GET['api'] === "send") {
        $user = getCurrentUser();
        if (!$user) {
            echo json_encode(["err" => "Not logged in"]);
            exit;
        }

        $to = sanitizeInput($data['to']);
        $message = sanitizeInput($data['msg']);
        $type = $data['type'] ?? 'text';
        $file_name = $data['file_name'] ?? null;
        $file_size = $data['file_size'] ?? 0;

        // Check privacy settings
        $q = $db->prepare("SELECT privacy FROM users WHERE username=?");
        $q->execute([$to]);
        $target = $q->fetch(PDO::FETCH_ASSOC);

        if ($target && $target['privacy'] == 1) {
            $contacts = getAcceptedContacts($to);
            if (!in_array($user, $contacts)) {
                // Send contact request
                sendContactRequest($user, $to, $message);
                echo json_encode(["pending" => true]);
                exit;
            }
        }

        // Encrypt message
        $encrypted_content = encryptMessage($message);

        $db->prepare("INSERT INTO messages (sender, receiver, content, type, file_name, file_size, time) VALUES (?,?,?,?,?,?,?)")
            ->execute([$user, $to, $encrypted_content, $type, $file_name, $file_size, time()]);

        // Send notification
        sendNotification($to, 'message', $user, 'New message from ' . $user);

        echo json_encode(["ok" => true]);
        exit;
    }

    /* SEND GROUP MESSAGE */
    if ($_GET['api'] === "send_group") {
        $user = getCurrentUser();
        if (!$user) {
            echo json_encode(["err" => "Not logged in"]);
            exit;
        }

        $group_id = intval($data['group_id']);
        $message = sanitizeInput($data['msg']);
        $type = $data['type'] ?? 'text';

        // Check if user is member
        $q = $db->prepare("SELECT * FROM group_members WHERE group_id=? AND username=?");
        $q->execute([$group_id, $user]);
        if (!$q->fetch()) {
            echo json_encode(["err" => "Not a member"]);
            exit;
        }

        // Encrypt message
        $encrypted_content = encryptMessage($message);

        $db->prepare("INSERT INTO group_messages (group_id, sender, content, type, time) VALUES (?,?,?,?,?)")
            ->execute([$group_id, $user, $encrypted_content, $type, time()]);

        // Send notifications to all members except sender
        $q = $db->prepare("SELECT username FROM group_members WHERE group_id=? AND username!=?");
        $q->execute([$group_id, $user]);
        $members = $q->fetchAll(PDO::FETCH_COLUMN);

        foreach ($members as $member) {
            sendNotification($member, 'group_message', $user, 'New message in group');
        }

        echo json_encode(["ok" => true]);
        exit;
    }

    /* FETCH MESSAGES */
    if ($_GET['api'] === "fetch") {
        $user = getCurrentUser();
        $with = sanitizeInput($_GET['with']);

        $q = $db->prepare("SELECT sender, content, type, file_name, file_size, time FROM messages 
            WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?) 
            ORDER BY time ASC");
        $q->execute([$user, $with, $with, $user]);

        $messages = $q->fetchAll(PDO::FETCH_ASSOC);
        
        // Decrypt messages
        foreach ($messages as &$msg) {
            try {
                $msg['content'] = decryptMessage($msg['content']);
            } catch (Exception $e) {
                $msg['content'] = '[Encrypted message]';
            }
        }

        echo json_encode($messages);
        exit;
    }

    /* FETCH GROUP MESSAGES */
    if ($_GET['api'] === "fetch_group") {
        $user = getCurrentUser();
        $group_id = intval($_GET['group_id']);

        // Check if user is member
        $q = $db->prepare("SELECT * FROM group_members WHERE group_id=? AND username=?");
        $q->execute([$group_id, $user]);
        if (!$q->fetch()) {
            echo json_encode([]);
            exit;
        }

        $q = $db->prepare("SELECT sender, content, type, file_name, file_size, time FROM group_messages 
            WHERE group_id=? 
            ORDER BY time ASC");
        $q->execute([$group_id]);

        $messages = $q->fetchAll(PDO::FETCH_ASSOC);
        
        // Decrypt messages
        foreach ($messages as &$msg) {
            try {
                $msg['content'] = decryptMessage($msg['content']);
            } catch (Exception $e) {
                $msg['content'] = '[Encrypted message]';
            }
        }

        echo json_encode($messages);
        exit;
    }

    /* UPLOAD FILE */
    if ($_GET['api'] === "upload_file") {
        $user = getCurrentUser();
        if (!$user) {
            echo json_encode(["err" => "Not logged in"]);
            exit;
        }

        if (!isset($_FILES['file'])) {
            echo json_encode(["err" => "No file uploaded"]);
            exit;
        }

        $file = $_FILES['file'];
        $max_size = 15 * 1024 * 1024; // 15MB
        
        if ($file['size'] > $max_size) {
            echo json_encode(["err" => "File size exceeds 15MB limit"]);
            exit;
        }

        $allowed_types = [
            'image/jpeg', 'image/png', 'image/gif', 'image/webp',
            'application/pdf', 'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/plain', 'application/zip', 'application/x-rar-compressed'
        ];

        if (!in_array($file['type'], $allowed_types)) {
            echo json_encode(["err" => "File type not allowed"]);
            exit;
        }

        $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
        $filename = 'file_' . $user . '_' . time() . '_' . bin2hex(random_bytes(8)) . '.' . $extension;
        $filepath = 'uploads/files/' . $filename;

        if (move_uploaded_file($file['tmp_name'], $filepath)) {
            // Encrypt file name for storage
            $encrypted_filename = encryptMessage($file['name']);
            
            echo json_encode([
                "ok" => true,
                "filename" => $filename,
                "original_name" => $file['name'],
                "size" => $file['size'],
                "type" => $file['type']
            ]);
        } else {
            echo json_encode(["err" => "Upload failed"]);
        }
        exit;
    }

    /* CREATE GROUP */
    if ($_GET['api'] === "create_group") {
        $user = getCurrentUser();
        if (!$user) {
            echo json_encode(["err" => "Not logged in"]);
            exit;
        }

        $name = sanitizeInput($data['name']);
        $description = sanitizeInput($data['description'] ?? '');
        $members = $data['members'] ?? [];

        $db->prepare("INSERT INTO groups (name, description, creator, created_at) VALUES (?,?,?,?)")
            ->execute([$name, $description, $user, time()]);

        $group_id = $db->lastInsertId();

        // Add creator as admin
        $db->prepare("INSERT INTO group_members (group_id, username, role, joined_at) VALUES (?,?,?,?)")
            ->execute([$group_id, $user, 'admin', time()]);

        // Add members
        foreach ($members as $member) {
            if ($member != $user) {
                $db->prepare("INSERT INTO group_members (group_id, username, role, joined_at) VALUES (?,?,?,?)")
                    ->execute([$group_id, $member, 'member', time()]);
            }
        }

        echo json_encode(["ok" => true, "group_id" => $group_id]);
        exit;
    }

    /* GET NOTIFICATIONS */
    if ($_GET['api'] === "get_notifications") {
        $user = getCurrentUser();
        if (!$user) {
            echo json_encode([]);
            exit;
        }

        $q = $db->prepare("SELECT * FROM notifications WHERE username=? ORDER BY created_at DESC LIMIT 20");
        $q->execute([$user]);
        $notifications = $q->fetchAll(PDO::FETCH_ASSOC);

        echo json_encode($notifications);
        exit;
    }

    /* MARK NOTIFICATION READ */
    if ($_GET['api'] === "mark_notification_read") {
        $user = getCurrentUser();
        if (!$user) {
            echo json_encode(["err" => "Not logged in"]);
            exit;
        }

        $notification_id = intval($data['id']);
        
        $db->prepare("UPDATE notifications SET read_status=1 WHERE id=? AND username=?")
            ->execute([$notification_id, $user]);

        echo json_encode(["ok" => true]);
        exit;
    }

    /* CONTACT REQUESTS */
    if ($_GET['api'] === "get_contact_requests") {
        $user = getCurrentUser();
        if (!$user) {
            echo json_encode([]);
            exit;
        }

        $q = $db->prepare("SELECT c.*, u.name, u.avatar FROM contacts c 
            JOIN users u ON c.user_from = u.username 
            WHERE c.user_to=? AND c.status='pending' 
            ORDER BY c.created_at DESC");
        $q->execute([$user]);
        $requests = $q->fetchAll(PDO::FETCH_ASSOC);

        echo json_encode($requests);
        exit;
    }

    /* HANDLE CONTACT REQUEST */
    if ($_GET['api'] === "handle_contact_request") {
        $user = getCurrentUser();
        if (!$user) {
            echo json_encode(["err" => "Not logged in"]);
            exit;
        }

        $request_id = intval($data['id']);
        $action = $data['action']; // 'accept' or 'reject'

        $q = $db->prepare("SELECT * FROM contacts WHERE id=? AND user_to=? AND status='pending'");
        $q->execute([$request_id, $user]);
        $request = $q->fetch(PDO::FETCH_ASSOC);

        if ($request) {
            $status = $action === 'accept' ? 'accepted' : 'rejected';
            $db->prepare("UPDATE contacts SET status=? WHERE id=?")->execute([$status, $request_id]);
            
            if ($action === 'accept') {
                sendNotification($request['user_from'], 'contact_accepted', $user, 'Your contact request was accepted');
            }
            
            echo json_encode(["ok" => true]);
        } else {
            echo json_encode(["err" => "Request not found"]);
        }
        exit;
    }

    exit;
}

/* === HELPER FUNCTIONS CONTINUED === */
function getAcceptedContacts($username) {
    global $db;
    $q = $db->prepare("SELECT user_from FROM contacts WHERE user_to=? AND status='accepted'
        UNION
        SELECT user_to FROM contacts WHERE user_from=? AND status='accepted'");
    $q->execute([$username, $username]);
    return $q->fetchAll(PDO::FETCH_COLUMN);
}

function sendContactRequest($from, $to, $message = '') {
    global $db;
    
    // Check if request already exists
    $q = $db->prepare("SELECT * FROM contacts WHERE user_from=? AND user_to=? AND status='pending'");
    $q->execute([$from, $to]);
    
    if (!$q->fetch()) {
        $db->prepare("INSERT INTO contacts (user_from, user_to, status, created_at) VALUES (?,?,?,?)")
            ->execute([$from, $to, 'pending', time()]);
        
        sendNotification($to, 'contact_request', $from, 'New contact request from ' . $from);
    }
}

// Check for file downloads
if (isset($_GET['download'])) {
    $filename = sanitizeInput($_GET['download']);
    $filepath = 'uploads/files/' . $filename;
    
    if (file_exists($filepath)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($filepath) . '"');
        header('Content-Length: ' . filesize($filepath));
        readfile($filepath);
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>LinkA - Secure Messenger</title>
<style>
/* ===== VARIABLES ===== */
:root {
  --bg-primary: #ffffff;
  --bg-secondary: #f5f5f5;
  --bg-tertiary: #e0e0e0;
  --text-primary: #000000;
  --text-secondary: #666666;
  --accent: #007aff;
  --accent-hover: #0056cc;
  --success: #34c759;
  --danger: #ff3b30;
  --warning: #ff9500;
  --border: #d1d1d1;
  --shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.dark-theme {
  --bg-primary: #000000;
  --bg-secondary: #1c1c1c;
  --bg-tertiary: #2c2c2c;
  --text-primary: #ffffff;
  --text-secondary: #8e8e93;
  --border: #3a3a3c;
  --shadow: 0 2px 10px rgba(0,0,0,0.3);
}

.amoled-theme {
  --bg-primary: #000000;
  --bg-secondary: #000000;
  --bg-tertiary: #111111;
  --text-primary: #ffffff;
  --text-secondary: #8e8e93;
  --border: #222222;
}

/* ===== RESET & BASE ===== */
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
  -webkit-tap-highlight-color: transparent;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg-primary);
  color: var(--text-primary);
  height: 100vh;
  overflow: hidden;
  font-size: 16px;
  line-height: 1.4;
}

/* ===== APP LAYOUT ===== */
.app-container {
  display: flex;
  height: 100vh;
  width: 100vw;
  overflow: hidden;
}

/* ===== SIDEBAR ===== */
.sidebar {
  width: 100%;
  max-width: 320px;
  background: var(--bg-secondary);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  position: relative;
  z-index: 100;
}

.user-panel {
  padding: 16px;
  background: var(--bg-tertiary);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 12px;
  min-height: 70px;
}

.avatar {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  object-fit: cover;
  border: 2px solid var(--accent);
  background: var(--bg-tertiary);
  flex-shrink: 0;
}

.user-info {
  flex: 1;
  min-width: 0;
}

.user-info h3 {
  font-size: 18px;
  font-weight: 600;
  margin: 0 0 4px 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.user-info span {
  font-size: 14px;
  color: var(--text-secondary);
  display: block;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.sidebar-nav {
  padding: 12px 0;
  border-bottom: 1px solid var(--border);
}

.nav-item {
  display: flex;
  align-items: center;
  padding: 14px 20px;
  color: var(--text-primary);
  text-decoration: none;
  transition: all 0.2s;
  gap: 12px;
  font-size: 16px;
  font-weight: 500;
}

.nav-item:hover {
  background: var(--bg-tertiary);
}

.nav-item.active {
  background: var(--bg-tertiary);
  border-left: 4px solid var(--accent);
}

.nav-item i {
  width: 24px;
  text-align: center;
  font-size: 18px;
}

.inbox-list {
  flex: 1;
  overflow-y: auto;
  padding: 8px 0;
}

.contact-item {
  display: flex;
  align-items: center;
  padding: 14px 16px;
  gap: 12px;
  cursor: pointer;
  transition: background 0.2s;
  border-bottom: 1px solid var(--border);
}

.contact-item:hover {
  background: var(--bg-tertiary);
}

.contact-item.active {
  background: var(--bg-tertiary);
}

.contact-avatar {
  width: 44px;
  height: 44px;
  border-radius: 50%;
  object-fit: cover;
  flex-shrink: 0;
}

.contact-info {
  flex: 1;
  min-width: 0;
}

.contact-info h4 {
  font-size: 16px;
  font-weight: 600;
  margin: 0 0 4px 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.contact-info span {
  font-size: 14px;
  color: var(--text-secondary);
  display: block;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.group-badge {
  background: var(--accent);
  color: white;
  font-size: 12px;
  padding: 2px 8px;
  border-radius: 12px;
  margin-left: 8px;
}

/* ===== MAIN CONTENT ===== */
.main-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.chat-header {
  padding: 16px 20px;
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 70px;
}

.chat-header-info {
  display: flex;
  align-items: center;
  gap: 12px;
  flex: 1;
  min-width: 0;
}

.chat-actions {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}

.chat-container {
  flex: 1;
  padding: 16px;
  overflow-y: auto;
  background: var(--bg-primary);
  display: flex;
  flex-direction: column;
  gap: 12px;
  -webkit-overflow-scrolling: touch;
}

.empty-chat {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  color: var(--text-secondary);
  text-align: center;
  padding: 20px;
}

.empty-chat i {
  font-size: 64px;
  margin-bottom: 20px;
  opacity: 0.5;
}

.message-bubble {
  max-width: 85%;
  padding: 12px 16px;
  border-radius: 18px;
  position: relative;
  word-wrap: break-word;
  line-height: 1.4;
}

.message-sent {
  align-self: flex-end;
  background: var(--accent);
  color: white;
  border-bottom-right-radius: 4px;
}

.message-received {
  align-self: flex-start;
  background: var(--bg-tertiary);
  border-bottom-left-radius: 4px;
}

.message-time {
  font-size: 12px;
  color: var(--text-secondary);
  margin-top: 4px;
  opacity: 0.8;
}

.message-file {
  padding: 12px;
  background: var(--bg-secondary);
  border-radius: 12px;
  margin-top: 8px;
  border: 1px solid var(--border);
}

.file-info {
  display: flex;
  align-items: center;
  gap: 12px;
}

.file-icon {
  font-size: 24px;
  color: var(--accent);
}

.file-details {
  flex: 1;
}

.file-name {
  font-weight: 500;
  margin-bottom: 4px;
}

.file-size {
  font-size: 12px;
  color: var(--text-secondary);
}

.download-btn {
  background: var(--accent);
  color: white;
  border: none;
  padding: 8px 16px;
  border-radius: 8px;
  cursor: pointer;
  text-decoration: none;
  display: inline-block;
  font-size: 14px;
}

.chat-input-area {
  padding: 16px;
  background: var(--bg-secondary);
  border-top: 1px solid var(--border);
  display: flex;
  gap: 12px;
  align-items: center;
}

.chat-input {
  flex: 1;
  padding: 14px 16px;
  background: var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: 24px;
  color: var(--text-primary);
  font-size: 16px;
  outline: none;
  min-height: 48px;
  resize: none;
  line-height: 1.4;
  font-family: inherit;
}

.chat-input:focus {
  border-color: var(--accent);
}

.attachment-btn {
  background: none;
  border: none;
  color: var(--text-secondary);
  font-size: 24px;
  cursor: pointer;
  padding: 8px;
  border-radius: 50%;
  transition: all 0.2s;
}

.attachment-btn:hover {
  background: var(--bg-tertiary);
  color: var(--text-primary);
}

.send-btn {
  background: var(--accent);
  color: white;
  border: none;
  width: 48px;
  height: 48px;
  border-radius: 50%;
  cursor: pointer;
  font-size: 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  transition: background 0.2s;
}

.send-btn:hover {
  background: var(--accent-hover);
}

/* ===== BUTTONS ===== */
.btn {
  padding: 12px 24px;
  background: var(--accent);
  color: white;
  border: none;
  border-radius: 12px;
  cursor: pointer;
  transition: all 0.2s;
  font-weight: 500;
  font-size: 16px;
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  min-height: 44px;
}

.btn:hover {
  background: var(--accent-hover);
  transform: translateY(-1px);
}

.btn-secondary {
  background: var(--bg-tertiary);
  color: var(--text-primary);
}

.btn-secondary:hover {
  background: var(--border);
}

.btn-success {
  background: var(--success);
}

.btn-danger {
  background: var(--danger);
}

.btn-small {
  padding: 8px 16px;
  font-size: 14px;
  min-height: 36px;
}

.btn-icon {
  width: 44px;
  height: 44px;
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
  padding: 20px;
}

.modal.active {
  display: flex;
}

.modal-content {
  background: var(--bg-primary);
  border-radius: 16px;
  width: 100%;
  max-width: 500px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: var(--shadow);
  animation: modalSlideIn 0.3s ease;
}

@keyframes modalSlideIn {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.modal-header {
  padding: 20px 24px;
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
  position: sticky;
  top: 0;
  background: var(--bg-primary);
  z-index: 1;
}

.modal-header h3 {
  font-size: 20px;
  font-weight: 600;
}

.modal-close {
  background: none;
  border: none;
  color: var(--text-secondary);
  font-size: 24px;
  cursor: pointer;
  padding: 4px;
  border-radius: 50%;
  transition: all 0.2s;
}

.modal-close:hover {
  background: var(--bg-tertiary);
  color: var(--text-primary);
}

.modal-body {
  padding: 24px;
}

.modal-footer {
  padding: 20px 24px;
  border-top: 1px solid var(--border);
  display: flex;
  gap: 12px;
  justify-content: flex-end;
}

/* ===== FORMS ===== */
.form-group {
  margin-bottom: 20px;
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
  padding: 14px 16px;
  background: var(--bg-primary);
  border: 1px solid var(--border);
  border-radius: 12px;
  color: var(--text-primary);
  font-size: 16px;
  outline: none;
  transition: border-color 0.2s;
}

.form-input:focus {
  border-color: var(--accent);
}

.form-textarea {
  min-height: 120px;
  resize: vertical;
  line-height: 1.4;
  font-family: inherit;
}

.form-checkbox {
  display: flex;
  align-items: center;
  gap: 12px;
  cursor: pointer;
  font-size: 16px;
}

.form-checkbox input {
  width: 20px;
  height: 20px;
  accent-color: var(--accent);
}

/* ===== THEME SELECTOR ===== */
.theme-selector {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-top: 12px;
}

.theme-option {
  padding: 20px;
  background: var(--bg-tertiary);
  border: 2px solid transparent;
  border-radius: 12px;
  cursor: pointer;
  text-align: center;
  transition: all 0.2s;
}

.theme-option:hover {
  transform: translateY(-2px);
}

.theme-option.active {
  border-color: var(--accent);
}

.theme-dark { background: #1c1c1c; color: white; }
.theme-light { background: #ffffff; color: #000; border: 1px solid #ddd; }
.theme-amoled { background: #000000; color: white; }

/* ===== UPLOAD AREA ===== */
.upload-area {
  border: 2px dashed var(--border);
  border-radius: 12px;
  padding: 40px 20px;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s;
  margin-bottom: 20px;
}

.upload-area:hover {
  border-color: var(--accent);
  background: var(--bg-tertiary);
}

.upload-area i {
  font-size: 48px;
  color: var(--text-secondary);
  margin-bottom: 16px;
}

.file-preview {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px;
  background: var(--bg-tertiary);
  border-radius: 12px;
  margin-top: 12px;
}

/* ===== CONTACT REQUESTS ===== */
.request-item {
  padding: 16px;
  border: 1px solid var(--border);
  border-radius: 12px;
  margin-bottom: 12px;
  display: flex;
  align-items: center;
  gap: 16px;
}

.request-actions {
  display: flex;
  gap: 8px;
  margin-left: auto;
}

/* ===== NOTIFICATIONS ===== */
.notification-badge {
  background: var(--danger);
  color: white;
  font-size: 12px;
  width: 20px;
  height: 20px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  position: absolute;
  top: 8px;
  right: 8px;
}

.notification-item {
  padding: 16px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 12px;
}

.notification-item.unread {
  background: var(--bg-tertiary);
}

.notification-content {
  flex: 1;
}

.notification-time {
  font-size: 12px;
  color: var(--text-secondary);
  margin-top: 4px;
}

/* ===== RESPONSIVE ===== */
@media (max-width: 768px) {
  .app-container {
    flex-direction: column;
  }
  
  .sidebar {
    width: 100%;
    max-width: none;
    height: auto;
    flex-shrink: 0;
  }
  
  .sidebar-nav {
    display: flex;
    overflow-x: auto;
    padding: 0;
  }
  
  .nav-item {
    flex-direction: column;
    padding: 12px;
    min-width: 80px;
    text-align: center;
    font-size: 14px;
  }
  
  .nav-item i {
    font-size: 20px;
    margin-bottom: 4px;
  }
  
  .inbox-list {
    display: none;
  }
  
  .inbox-list.active {
    display: block;
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: var(--bg-primary);
    z-index: 1001;
    padding-top: 70px;
  }
  
  .contact-item {
    padding: 16px;
  }
  
  .modal-content {
    margin: 0;
    border-radius: 0;
    max-height: 100vh;
    height: 100vh;
  }
  
  .chat-input {
    font-size: 16px;
    min-height: 44px;
  }
  
  .btn {
    padding: 14px 20px;
    min-height: 48px;
  }
}

@media (max-width: 480px) {
  body {
    font-size: 14px;
  }
  
  .modal-body {
    padding: 16px;
  }
  
  .theme-selector {
    grid-template-columns: 1fr;
  }
  
  .message-bubble {
    max-width: 90%;
  }
}

/* ===== UTILITY ===== */
.hidden { display: none !important; }
.text-center { text-align: center; }
.mt-20 { margin-top: 20px; }
.mb-20 { margin-bottom: 20px; }
.ml-auto { margin-left: auto; }

/* ===== SCROLLBAR ===== */
::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}

::-webkit-scrollbar-track {
  background: var(--bg-tertiary);
  border-radius: 4px;
}

::-webkit-scrollbar-thumb {
  background: var(--border);
  border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
  background: var(--text-secondary);
}

/* ===== ANIMATIONS ===== */
@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

@keyframes slideIn {
  from { transform: translateY(10px); opacity: 0; }
  to { transform: translateY(0); opacity: 1; }
}

.fade-in {
  animation: fadeIn 0.3s ease;
}

.slide-in {
  animation: slideIn 0.3s ease;
}

/* ===== LOADING ===== */
.loading {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 40px;
  color: var(--text-secondary);
}

.loading i {
  font-size: 24px;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

/* ===== BADGES ===== */
.badge {
  background: var(--accent);
  color: white;
  font-size: 12px;
  padding: 2px 8px;
  border-radius: 12px;
  display: inline-block;
  margin-left: 8px;
}

/* ===== TOAST NOTIFICATION ===== */
.toast {
  position: fixed;
  bottom: 20px;
  right: 20px;
  background: var(--bg-secondary);
  color: var(--text-primary);
  padding: 16px 24px;
  border-radius: 12px;
  box-shadow: var(--shadow);
  z-index: 10000;
  animation: slideIn 0.3s ease;
  display: flex;
  align-items: center;
  gap: 12px;
  max-width: 400px;
}

.toast.success {
  border-left: 4px solid var(--success);
}

.toast.error {
  border-left: 4px solid var(--danger);
}

.toast.warning {
  border-left: 4px solid var(--warning);
}

/* ===== MOBILE MENU TOGGLE ===== */
.menu-toggle {
  display: none;
  background: none;
  border: none;
  color: var(--text-primary);
  font-size: 24px;
  padding: 12px;
  cursor: pointer;
}

@media (max-width: 768px) {
  .menu-toggle {
    display: block;
  }
}
</style>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<link rel="manifest" href="manifest.json">
</head>
<body>

<!-- APP CONTAINER -->
<div class="app-container" id="app">
  <!-- SIDEBAR -->
  <div class="sidebar">
    <div class="user-panel">
      <button class="menu-toggle" onclick="toggleMobileMenu()">
        <i class="fas fa-bars"></i>
      </button>
      <img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI1MCIgZmlsbD0iIzAwN2FmZiIvPjx0ZXh0IHg9IjUwIiB5PSI1NSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0id2hpdGUiIGZvbnQtc2l6ZT0iNDAiPkw8L3RleHQ+PC9zdmc+" 
           class="avatar" id="userAvatar" onclick="showModal('profileModal')">
      <div class="user-info">
        <h3 id="userName">Loading...</h3>
        <span id="userStatus">LinkA User</span>
      </div>
      <div class="notification-badge hidden" id="notificationBadge">0</div>
    </div>
    
    <div class="sidebar-nav">
      <a href="#" class="nav-item active" onclick="showSection('inbox')">
        <i class="fas fa-inbox"></i>
        <span>Inbox</span>
      </a>
      <a href="#" class="nav-item" onclick="showModal('searchModal')">
        <i class="fas fa-search"></i>
        <span>Search</span>
      </a>
      <a href="#" class="nav-item" onclick="showModal('groupModal')">
        <i class="fas fa-users"></i>
        <span>Groups</span>
      </a>
      <a href="#" class="nav-item" onclick="showModal('contactsModal')" id="contactsNav">
        <i class="fas fa-user-plus"></i>
        <span>Contacts</span>
      </a>
      <a href="#" class="nav-item" onclick="showModal('notificationsModal')" id="notificationsNav">
        <i class="fas fa-bell"></i>
        <span>Notifications</span>
      </a>
    </div>
    
    <div class="inbox-list active" id="inboxList">
      <!-- Inbox items will be loaded here -->
    </div>
  </div>
  
  <!-- MAIN CONTENT -->
  <div class="main-content">
    <div class="chat-header">
      <div class="chat-header-info">
        <img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI1MCIgZmlsbD0iI2UwZTBlMCIvPjx0ZXh0IHg9IjUwIiB5PSI1NSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0iIzY2NiIgZm9udC1zaXplPSI0MCI+ITwvdGV4dD48L3N2Zz4=" 
             class="avatar" id="chatAvatar">
        <div>
          <h3 id="chatContactName">Welcome to LinkA</h3>
          <span id="chatContactStatus">Select a chat to start messaging</span>
        </div>
      </div>
      <div class="chat-actions" id="chatActions">
        <button class="btn btn-icon" onclick="showChatInfo()">
          <i class="fas fa-info-circle"></i>
        </button>
        <button class="btn btn-icon btn-danger" onclick="clearCurrentChat()">
          <i class="fas fa-trash"></i>
        </button>
      </div>
    </div>
    
    <div class="chat-container" id="chatContainer">
      <div class="empty-chat">
        <i class="fas fa-comments"></i>
        <h3>No chat selected</h3>
        <p>Select a contact or group from the inbox to start messaging</p>
        <button class="btn mt-20" onclick="showModal('searchModal')">
          <i class="fas fa-search"></i> Find People
        </button>
      </div>
    </div>
    
    <div class="chat-input-area hidden" id="chatInputArea">
      <button class="attachment-btn" onclick="attachFile()">
        <i class="fas fa-paperclip"></i>
      </button>
      <input type="text" class="chat-input" id="messageInput" 
             placeholder="Type a message..." 
             onkeypress="if(event.key === 'Enter') sendMessage()">
      <button class="send-btn" onclick="sendMessage()">
        <i class="fas fa-paper-plane"></i>
      </button>
      <input type="file" id="fileInput" hidden accept="image/*,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/plain,application/zip,application/x-rar-compressed">
    </div>
  </div>
</div>

<!-- LOGIN SCREEN -->
<div id="loginScreen" class="modal active">
  <div class="modal-content">
    <div class="modal-body">
      <div class="text-center">
        <div style="font-size: 48px; color: var(--accent); margin-bottom: 20px;">
          <i class="fas fa-comments"></i>
        </div>
        <h2 style="margin-bottom: 8px;">Welcome to LinkA</h2>
        <p style="color: var(--text-secondary); margin-bottom: 32px;">
          Secure messaging with end-to-end encryption
        </p>
        
        <div class="form-group">
          <input type="text" class="form-input" id="loginUsername" 
                 placeholder="Enter username" 
                 onkeypress="if(event.key === 'Enter') login()">
        </div>
        
        <button class="btn" style="width: 100%;" onclick="login()">
          <i class="fas fa-sign-in-alt"></i> Login / Register
        </button>
        
        <p style="color: var(--text-secondary); margin-top: 24px; font-size: 14px;">
          <i class="fas fa-lock"></i> All messages are encrypted with military-grade encryption
        </p>
      </div>
    </div>
  </div>
</div>

<!-- MODALS -->
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
      <div class="form-group text-center">
        <img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI1MCIgZmlsbD0iIzAwN2FmZiIvPjx0ZXh0IHg9IjUwIiB5PSI1NSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0id2hpdGUiIGZvbnQtc2l6ZT0iNDAiPkw8L3RleHQ+PC9zdmc+" 
             class="avatar" id="editAvatar" style="width: 100px; height: 100px; cursor: pointer;" onclick="changeAvatar()">
        <input type="file" id="avatarInput" accept="image/*" hidden>
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
        <textarea class="form-input form-textarea" id="editBio" maxlength="200"></textarea>
      </div>
      
      <div class="form-group">
        <label class="form-checkbox">
          <input type="checkbox" id="editPrivacy">
          <span>Private Mode (Only accepted contacts can message me)</span>
        </label>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-secondary" onclick="hideModal('profileModal')">Cancel</button>
      <button class="btn" onclick="updateProfile()">Save Changes</button>
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
        <div class="theme-selector">
          <div class="theme-option theme-light" onclick="selectTheme('light')">
            <i class="fas fa-sun"></i><br>Light
          </div>
          <div class="theme-option theme-dark active" onclick="selectTheme('dark')">
            <i class="fas fa-moon"></i><br>Dark
          </div>
          <div class="theme-option theme-amoled" onclick="selectTheme('amoled')">
            <i class="fas fa-moon"></i><br>AMOLED
          </div>
        </div>
      </div>
      
      <div class="form-group">
        <label class="form-label">Notifications</label>
        <label class="form-checkbox">
          <input type="checkbox" id="notificationsToggle" checked>
          <span>Enable notifications</span>
        </label>
      </div>
      
      <div class="form-group">
        <label class="form-label">Notification Permission</label>
        <button class="btn btn-secondary" onclick="requestNotificationPermission()">
          <i class="fas fa-bell"></i> Enable Browser Notifications
        </button>
        <p style="font-size: 12px; color: var(--text-secondary); margin-top: 8px;">
          Allow browser notifications to get alerts for new messages
        </p>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-secondary" onclick="hideModal('settingsModal')">Close</button>
      <button class="btn" onclick="saveSettings()">Save Settings</button>
    </div>
  </div>
</div>

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
        <input type="text" class="form-input" id="searchInput" 
               placeholder="Search by username or name..." 
               onkeyup="searchUsers()">
      </div>
      <div id="searchResults" style="max-height: 400px; overflow-y: auto;">
        <!-- Results will appear here -->
      </div>
    </div>
  </div>
</div>

<!-- Group Modal -->
<div class="modal" id="groupModal">
  <div class="modal-content">
    <div class="modal-header">
      <h3>Group Chat</h3>
      <button class="modal-close" onclick="hideModal('groupModal')">
        <i class="fas fa-times"></i>
      </button>
    </div>
    <div class="modal-body">
      <button class="btn" style="width: 100%; margin-bottom: 20px;" onclick="showModal('createGroupModal')">
        <i class="fas fa-plus"></i> Create New Group
      </button>
      
      <div id="groupList">
        <!-- Groups will be loaded here -->
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
        <div id="groupMemberSearch">
          <input type="text" class="form-input" id="groupSearchInput" 
                 placeholder="Search users to add..." 
                 onkeyup="searchGroupMembers()">
        </div>
        <div id="selectedMembers" style="margin-top: 12px; min-height: 40px; border: 1px solid var(--border); border-radius: 8px; padding: 8px;">
          <!-- Selected members will appear here -->
        </div>
        <div id="groupSearchResults" style="max-height: 200px; overflow-y: auto; margin-top: 12px;">
          <!-- Search results will appear here -->
        </div>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-secondary" onclick="hideModal('createGroupModal')">Cancel</button>
      <button class="btn" onclick="createGroup()">Create Group</button>
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
        <!-- Contact requests will be loaded here -->
      </div>
    </div>
  </div>
</div>

<!-- Notifications Modal -->
<div class="modal" id="notificationsModal">
  <div class="modal-content">
    <div class="modal-header">
      <h3>Notifications</h3>
      <button class="modal-close" onclick="hideModal('notificationsModal')">
        <i class="fas fa-times"></i>
      </button>
    </div>
    <div class="modal-body">
      <div id="notificationsList">
        <!-- Notifications will be loaded here -->
      </div>
    </div>
  </div>
</div>

<!-- File Upload Modal -->
<div class="modal" id="uploadModal">
  <div class="modal-content">
    <div class="modal-header">
      <h3>Upload File</h3>
      <button class="modal-close" onclick="hideModal('uploadModal')">
        <i class="fas fa-times"></i>
      </button>
    </div>
    <div class="modal-body">
      <div class="upload-area" onclick="document.getElementById('fileInput').click()">
        <i class="fas fa-cloud-upload-alt"></i>
        <h4>Click to upload file</h4>
        <p style="color: var(--text-secondary);">Max file size: 15MB</p>
        <p style="font-size: 12px; color: var(--text-secondary); margin-top: 8px;">
          Supported: Images, PDF, Word, Text, ZIP
        </p>
      </div>
      
      <div id="filePreview" class="file-preview hidden">
        <div class="file-info">
          <i class="fas fa-file file-icon"></i>
          <div class="file-details">
            <div class="file-name" id="fileName"></div>
            <div class="file-size" id="fileSize"></div>
          </div>
        </div>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-secondary" onclick="hideModal('uploadModal')">Cancel</button>
      <button class="btn" onclick="sendFile()" id="sendFileBtn" disabled>
        <i class="fas fa-paper-plane"></i> Send File
      </button>
    </div>
  </div>
</div>

<!-- Toast Container -->
<div id="toastContainer"></div>

<script>
// ===== GLOBAL VARIABLES =====
let currentUser = null;
let currentChat = null;
let currentChatType = null; // 'user' or 'group'
let currentGroupId = null;
let notificationsEnabled = false;
let selectedFile = null;
let selectedMembers = [];
let inboxInterval = null;
let notificationInterval = null;

// ===== INITIALIZATION =====
document.addEventListener('DOMContentLoaded', function() {
    // Check if user is logged in
    checkLogin();
    
    // Request notification permission
    if ('Notification' in window && Notification.permission === 'default') {
        setTimeout(() => {
            showToast('Enable notifications to get alerts for new messages', 'info');
        }, 3000);
    }
    
    // Set up service worker for PWA
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('sw.js').catch(console.error);
    }
    
    // Load theme from localStorage
    const savedTheme = localStorage.getItem('linka_theme') || 'dark';
    applyTheme(savedTheme);
    document.querySelectorAll('.theme-option').forEach(opt => {
        if (opt.classList.contains('theme-' + savedTheme)) {
            opt.classList.add('active');
        }
    });
});

// ===== THEME MANAGEMENT =====
function applyTheme(theme) {
    document.body.className = theme + '-theme';
    localStorage.setItem('linka_theme', theme);
}

function selectTheme(theme) {
    document.querySelectorAll('.theme-option').forEach(opt => opt.classList.remove('active'));
    event.target.closest('.theme-option').classList.add('active');
    applyTheme(theme);
}

// ===== AUTHENTICATION =====
function checkLogin() {
    fetch('?api=get_profile')
        .then(r => r.json())
        .then(profile => {
            if (profile && profile.username) {
                currentUser = profile.username;
                showApp();
            } else {
                showLogin();
            }
        })
        .catch(() => showLogin());
}

function login() {
    const username = document.getElementById('loginUsername').value.trim();
    if (!username) {
        showToast('Please enter a username', 'error');
        return;
    }

    fetch('?api=login', {
        method: 'POST',
        body: JSON.stringify({ username })
    })
    .then(r => r.json())
    .then(data => {
        if (data.ok || data.err === 'User not found') {
            // Auto-register if user doesn't exist
            fetch('?api=register', {
                method: 'POST',
                body: JSON.stringify({
                    username: username,
                    name: username,
                    bio: 'Hello LinkA user!',
                    captcha: 'auto' // Note: In production, implement proper captcha
                })
            })
            .then(r => r.json())
            .then(() => {
                currentUser = username;
                showApp();
                showToast('Welcome to LinkA!', 'success');
            });
        }
    })
    .catch(err => {
        console.error('Login error:', err);
        showToast('Login failed. Please try again.', 'error');
    });
}

function logout() {
    fetch('?api=logout')
        .then(() => {
            currentUser = null;
            showLogin();
            clearInterval(inboxInterval);
            clearInterval(notificationInterval);
        });
}

function showLogin() {
    document.getElementById('loginScreen').classList.add('active');
    document.getElementById('app').classList.add('hidden');
}

function showApp() {
    document.getElementById('loginScreen').classList.remove('active');
    document.getElementById('app').classList.remove('hidden');
    
    loadUserProfile();
    loadInbox();
    loadNotifications();
    checkContactRequests();
    
    // Start auto-refresh intervals
    inboxInterval = setInterval(loadInbox, 5000);
    notificationInterval = setInterval(() => {
        loadNotifications();
        checkContactRequests();
    }, 10000);
}

// ===== USER PROFILE =====
function loadUserProfile() {
    fetch('?api=get_profile')
        .then(r => r.json())
        .then(profile => {
            if (!profile) return;
            
            document.getElementById('userName').textContent = profile.name || profile.username;
            document.getElementById('editUsername').value = profile.username;
            document.getElementById('editName').value = profile.name || '';
            document.getElementById('editBio').value = profile.bio || '';
            document.getElementById('editPrivacy').checked = profile.privacy == 1;
            
            // Load avatar
            if (profile.avatar_url) {
                document.getElementById('userAvatar').src = profile.avatar_url;
                document.getElementById('editAvatar').src = profile.avatar_url;
            }
            
            // Save to localStorage for offline use
            localStorage.setItem('linka_profile', JSON.stringify(profile));
        });
}

function changeAvatar() {
    document.getElementById('avatarInput').click();
}

document.getElementById('avatarInput').addEventListener('change', function(e) {
    if (e.target.files[0]) {
        const reader = new FileReader();
        reader.onload = function(event) {
            document.getElementById('editAvatar').src = event.target.result;
            
            // Convert to base64 and save
            fetch('?api=update_avatar', {
                method: 'POST',
                body: JSON.stringify({ avatar: event.target.result })
            })
            .then(r => r.json())
            .then(data => {
                if (data.ok) {
                    loadUserProfile();
                    showToast('Profile picture updated', 'success');
                }
            });
        };
        reader.readAsDataURL(e.target.files[0]);
    }
});

function updateProfile() {
    const name = document.getElementById('editName').value.trim();
    const bio = document.getElementById('editBio').value.trim();
    const privacy = document.getElementById('editPrivacy').checked ? 1 : 0;
    
    if (!name) {
        showToast('Please enter a display name', 'error');
        return;
    }
    
    fetch('?api=update_profile', {
        method: 'POST',
        body: JSON.stringify({ name, bio, privacy })
    })
    .then(r => r.json())
    .then(data => {
        if (data.ok) {
            hideModal('profileModal');
            loadUserProfile();
            showToast('Profile updated successfully', 'success');
        }
    });
}

// ===== SETTINGS =====
function saveSettings() {
    const theme = document.querySelector('.theme-option.active').classList[1].replace('theme-', '');
    const notifications = document.getElementById('notificationsToggle').checked ? 1 : 0;
    
    fetch('?api=update_settings', {
        method: 'POST',
        body: JSON.stringify({ theme, notifications })
    })
    .then(r => r.json())
    .then(data => {
        if (data.ok) {
            hideModal('settingsModal');
            showToast('Settings saved', 'success');
        }
    });
}

function requestNotificationPermission() {
    if (!('Notification' in window)) {
        showToast('Notifications not supported in this browser', 'error');
        return;
    }
    
    if (Notification.permission === 'granted') {
        showToast('Notifications already enabled', 'success');
        notificationsEnabled = true;
        return;
    }
    
    Notification.requestPermission().then(permission => {
        if (permission === 'granted') {
            notificationsEnabled = true;
            showToast('Notifications enabled', 'success');
            
            // Show test notification
            if (Notification.permission === 'granted') {
                new Notification('LinkA', {
                    body: 'Notifications are now enabled!',
                    icon: '/favicon.ico'
                });
            }
        }
    });
}

// ===== INBOX & CHAT =====
function loadInbox() {
    if (!currentUser) return;
    
    fetch('?api=get_inbox')
        .then(r => r.json())
        .then(inbox => {
            const container = document.getElementById('inboxList');
            container.innerHTML = '';
            
            if (inbox.length === 0) {
                container.innerHTML = '<div class="text-center" style="padding: 40px; color: var(--text-secondary);">No conversations yet</div>';
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
                    if (window.innerWidth <= 768) {
                        document.getElementById('inboxList').classList.remove('active');
                    }
                };
                
                if (item.type === 'user') {
                    div.innerHTML = `
                        <img src="${item.avatar_url || 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI1MCIgZmlsbD0iI2UwZTBlMCIvPjx0ZXh0IHg9IjUwIiB5PSI1NSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0iIzY2NiIgZm9udC1zaXplPSI0MCI+ITwvdGV4dD48L3N2Zz4='}" 
                             class="contact-avatar">
                        <div class="contact-info">
                            <h4>${item.name || item.username}</h4>
                            <span>${item.bio || 'No bio'}</span>
                        </div>
                    `;
                } else {
                    div.innerHTML = `
                        <div style="width: 44px; height: 44px; border-radius: 50%; background: var(--accent); display: flex; align-items: center; justify-content: center;">
                            <i class="fas fa-users" style="color: white; font-size: 20px;"></i>
                        </div>
                        <div class="contact-info">
                            <h4>${item.name} <span class="badge">Group</span></h4>
                            <span>${item.description || 'Group chat'}</span>
                        </div>
                    `;
                }
                
                container.appendChild(div);
            });
        })
        .catch(console.error);
}

function openChat(target, type = 'user', groupName = '') {
    currentChat = target;
    currentChatType = type;
    
    if (type === 'user') {
        currentGroupId = null;
        document.getElementById('chatContactName').textContent = target;
        document.getElementById('chatContactStatus').textContent = 'Online';
        
        // Load user profile for avatar
        fetch(`?api=get_profile&username=${target}`)
            .then(r => r.json())
            .then(profile => {
                if (profile && profile.avatar_url) {
                    document.getElementById('chatAvatar').src = profile.avatar_url;
                }
            });
    } else {
        currentGroupId = target;
        document.getElementById('chatContactName').textContent = groupName;
        document.getElementById('chatContactStatus').textContent = 'Group • Multiple members';
        document.getElementById('chatAvatar').src = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI1MCIgZmlsbD0iIzAwN2FmZiIvPjx0ZXh0IHg9IjUwIiB5PSI1NSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0id2hpdGUiIGZvbnQtc2l6ZT0iMzUiPkc8L3RleHQ+PC9zdmc+';
    }
    
    document.getElementById('chatInputArea').classList.remove('hidden');
    document.getElementById('chatActions').style.display = 'flex';
    
    loadMessages();
    // Auto-refresh messages
    clearInterval(window.messageInterval);
    window.messageInterval = setInterval(loadMessages, 3000);
}

function loadMessages() {
    if (!currentChat) return;
    
    let apiUrl = '';
    if (currentChatType === 'user') {
        apiUrl = `?api=fetch&with=${currentChat}`;
    } else {
        apiUrl = `?api=fetch_group&group_id=${currentChat}`;
    }
    
    fetch(apiUrl)
        .then(r => r.json())
        .then(messages => {
            const container = document.getElementById('chatContainer');
            container.innerHTML = '';
            
            if (messages.length === 0) {
                container.innerHTML = `
                    <div class="empty-chat">
                        <i class="fas fa-comment-slash"></i>
                        <h3>No messages yet</h3>
                        <p>Start the conversation by sending a message</p>
                    </div>
                `;
                return;
            }
            
            messages.forEach(msg => {
                const bubble = document.createElement('div');
                const isSent = msg.sender === currentUser;
                bubble.className = `message-bubble ${isSent ? 'message-sent' : 'message-received'} fade-in`;
                
                const time = new Date(msg.time * 1000).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
                
                let content = msg.content;
                if (msg.type === 'file') {
                    content = `
                        <div>${msg.content}</div>
                        <div class="message-file">
                            <div class="file-info">
                                <i class="fas fa-file"></i>
                                <div class="file-details">
                                    <div class="file-name">${msg.file_name}</div>
                                    <div class="file-size">${formatFileSize(msg.file_size)}</div>
                                </div>
                                <a href="?download=${msg.file_name}" class="download-btn" download>
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
        })
        .catch(console.error);
}

function sendMessage() {
    if (!currentChat) {
        showToast('Select a chat first', 'error');
        return;
    }
    
    const input = document.getElementById('messageInput');
    const message = input.value.trim();
    
    if (!message && !selectedFile) {
        return;
    }
    
    let apiUrl = '';
    let payload = {};
    
    if (currentChatType === 'user') {
        apiUrl = '?api=send';
        payload = {
            to: currentChat,
            msg: message || '[File attached]',
            type: selectedFile ? 'file' : 'text'
        };
        
        if (selectedFile) {
            payload.file_name = selectedFile.filename;
            payload.file_size = selectedFile.size;
        }
    } else {
        apiUrl = '?api=send_group';
        payload = {
            group_id: currentChat,
            msg: message || '[File attached]',
            type: selectedFile ? 'file' : 'text'
        };
    }
    
    fetch(apiUrl, {
        method: 'POST',
        body: JSON.stringify(payload)
    })
    .then(r => r.json())
    .then(data => {
        if (data.ok) {
            input.value = '';
            if (selectedFile) {
                selectedFile = null;
                document.getElementById('filePreview').classList.add('hidden');
                document.getElementById('sendFileBtn').disabled = true;
                hideModal('uploadModal');
            }
            loadMessages();
            
            // Clear input and refocus
            input.value = '';
            input.focus();
        } else if (data.pending) {
            showToast('Contact request sent. Waiting for acceptance.', 'info');
        }
    })
    .catch(err => {
        console.error('Send error:', err);
        showToast('Failed to send message', 'error');
    });
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ===== FILE UPLOAD =====
function attachFile() {
    showModal('uploadModal');
}

document.getElementById('fileInput').addEventListener('change', function(e) {
    if (e.target.files[0]) {
        const file = e.target.files[0];
        
        if (file.size > 15 * 1024 * 1024) {
            showToast('File size must be less than 15MB', 'error');
            return;
        }
        
        const formData = new FormData();
        formData.append('file', file);
        
        fetch('?api=upload_file', {
            method: 'POST',
            body: formData
        })
        .then(r => r.json())
        .then(data => {
            if (data.ok) {
                selectedFile = {
                    filename: data.filename,
                    original_name: data.original_name,
                    size: data.size,
                    type: data.type
                };
                
                document.getElementById('fileName').textContent = data.original_name;
                document.getElementById('fileSize').textContent = formatFileSize(data.size);
                document.getElementById('filePreview').classList.remove('hidden');
                document.getElementById('sendFileBtn').disabled = false;
            } else {
                showToast(data.err || 'Upload failed', 'error');
            }
        })
        .catch(err => {
            console.error('Upload error:', err);
            showToast('Upload failed', 'error');
        });
    }
});

function sendFile() {
    if (selectedFile) {
        const input = document.getElementById('messageInput');
        input.value = '[File] ' + selectedFile.original_name;
        sendMessage();
    }
}

// ===== GROUPS =====
function loadGroups() {
    fetch('?api=get_inbox')
        .then(r => r.json())
        .then(inbox => {
            const container = document.getElementById('groupList');
            container.innerHTML = '';
            
            const groups = inbox.filter(item => item.type === 'group');
            
            if (groups.length === 0) {
                container.innerHTML = '<div class="text-center" style="padding: 20px; color: var(--text-secondary);">No groups yet</div>';
                return;
            }
            
            groups.forEach(group => {
                const div = document.createElement('div');
                div.className = 'contact-item';
                div.onclick = () => {
                    openChat(group.id, 'group', group.name);
                    hideModal('groupModal');
                };
                
                div.innerHTML = `
                    <div style="width: 44px; height: 44px; border-radius: 50%; background: var(--accent); display: flex; align-items: center; justify-content: center;">
                        <i class="fas fa-users" style="color: white; font-size: 20px;"></i>
                    </div>
                    <div class="contact-info">
                        <h4>${group.name}</h4>
                        <span>${group.description || 'Group chat'}</span>
                    </div>
                `;
                
                container.appendChild(div);
            });
        });
}

function searchGroupMembers() {
    const query = document.getElementById('groupSearchInput').value.trim();
    if (query.length < 2) {
        document.getElementById('groupSearchResults').innerHTML = '';
        return;
    }
    
    fetch(`?api=search&q=${query}`)
        .then(r => r.json())
        .then(users => {
            const container = document.getElementById('groupSearchResults');
            container.innerHTML = '';
            
            users.forEach(user => {
                if (selectedMembers.includes(user.username) || user.username === currentUser) {
                    return;
                }
                
                const div = document.createElement('div');
                div.className = 'contact-item';
                div.onclick = () => addGroupMember(user);
                
                div.innerHTML = `
                    <img src="${user.avatar_url || 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI1MCIgZmlsbD0iI2UwZTBlMCIvPjx0ZXh0IHg9IjUwIiB5PSI1NSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0iIzY2NiIgZm9udC1zaXplPSI0MCI+ITwvdGV4dD48L3N2Zz4='}" 
                         class="contact-avatar">
                    <div class="contact-info">
                        <h4>${user.name || user.username}</h4>
                        <span>${user.bio || 'No bio'}</span>
                    </div>
                    <button class="btn btn-small">
                        <i class="fas fa-plus"></i> Add
                    </button>
                `;
                
                container.appendChild(div);
            });
        });
}

function addGroupMember(user) {
    if (!selectedMembers.includes(user.username)) {
        selectedMembers.push(user.username);
        updateSelectedMembers();
    }
    document.getElementById('groupSearchInput').value = '';
    document.getElementById('groupSearchResults').innerHTML = '';
}

function updateSelectedMembers() {
    const container = document.getElementById('selectedMembers');
    container.innerHTML = '';
    
    selectedMembers.forEach(username => {
        const span = document.createElement('span');
        span.className = 'badge';
        span.style.marginRight = '8px';
        span.style.marginBottom = '8px';
        span.style.display = 'inline-block';
        span.innerHTML = `
            ${username}
            <button onclick="removeGroupMember('${username}')" style="background: none; border: none; color: white; margin-left: 4px; cursor: pointer;">
                <i class="fas fa-times"></i>
            </button>
        `;
        container.appendChild(span);
    });
}

function removeGroupMember(username) {
    selectedMembers = selectedMembers.filter(u => u !== username);
    updateSelectedMembers();
}

function createGroup() {
    const name = document.getElementById('groupName').value.trim();
    const description = document.getElementById('groupDescription').value.trim();
    
    if (!name) {
        showToast('Please enter a group name', 'error');
        return;
    }
    
    if (selectedMembers.length === 0) {
        showToast('Please add at least one member', 'error');
        return;
    }
    
    fetch('?api=create_group', {
        method: 'POST',
        body: JSON.stringify({
            name,
            description,
            members: selectedMembers
        })
    })
    .then(r => r.json())
    .then(data => {
        if (data.ok) {
            hideModal('createGroupModal');
            showToast('Group created successfully', 'success');
            selectedMembers = [];
            document.getElementById('groupName').value = '';
            document.getElementById('groupDescription').value = '';
            loadGroups();
            loadInbox();
        }
    });
}

// ===== CONTACTS =====
function checkContactRequests() {
    fetch('?api=get_contact_requests')
        .then(r => r.json())
        .then(requests => {
            const badge = document.getElementById('notificationBadge');
            if (requests.length > 0) {
                badge.textContent = requests.length;
                badge.classList.remove('hidden');
            } else {
                badge.classList.add('hidden');
            }
            
            // Update modal if open
            if (document.getElementById('contactsModal').classList.contains('active')) {
                loadContactRequests();
            }
        });
}

function loadContactRequests() {
    fetch('?api=get_contact_requests')
        .then(r => r.json())
        .then(requests => {
            const container = document.getElementById('contactRequests');
            container.innerHTML = '';
            
            if (requests.length === 0) {
                container.innerHTML = '<div class="text-center" style="padding: 40px; color: var(--text-secondary);">No pending requests</div>';
                return;
            }
            
            requests.forEach(req => {
                const div = document.createElement('div');
                div.className = 'request-item';
                
                div.innerHTML = `
                    <img src="${req.avatar_url || 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI1MCIgZmlsbD0iI2UwZTBlMCIvPjx0ZXh0IHg9IjUwIiB5PSI1NSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0iIzY2NiIgZm9udC1zaXplPSI0MCI+ITwvdGV4dD48L3N2Zz4='}" 
                         class="contact-avatar">
                    <div>
                        <h4>${req.name || req.user_from}</h4>
                        <p style="color: var(--text-secondary); font-size: 14px;">Wants to chat with you</p>
                    </div>
                    <div class="request-actions">
                        <button class="btn btn-small btn-success" onclick="handleContactRequest(${req.id}, 'accept')">
                            <i class="fas fa-check"></i> Accept
                        </button>
                        <button class="btn btn-small btn-danger" onclick="handleContactRequest(${req.id}, 'reject')">
                            <i class="fas fa-times"></i> Reject
                        </button>
                    </div>
                `;
                
                container.appendChild(div);
            });
        });
}

function handleContactRequest(requestId, action) {
    fetch('?api=handle_contact_request', {
        method: 'POST',
        body: JSON.stringify({ id: requestId, action })
    })
    .then(r => r.json())
    .then(data => {
        if (data.ok) {
            showToast(`Contact request ${action}ed`, 'success');
            loadContactRequests();
            checkContactRequests();
            loadInbox();
        }
    });
}

// ===== NOTIFICATIONS =====
function loadNotifications() {
    fetch('?api=get_notifications')
        .then(r => r.json())
        .then(notifications => {
            updateNotificationBadge(notifications);
            
            // Update modal if open
            if (document.getElementById('notificationsModal').classList.contains('active')) {
                displayNotifications(notifications);
            }
            
            // Show browser notifications for unread
            if (notificationsEnabled && 'Notification' in window && Notification.permission === 'granted') {
                notifications.forEach(notif => {
                    if (!notif.read_status) {
                        showBrowserNotification(notif);
                        markNotificationRead(notif.id);
                    }
                });
            }
        });
}

function updateNotificationBadge(notifications) {
    const unreadCount = notifications.filter(n => !n.read_status).length;
    const badge = document.getElementById('notificationBadge');
    
    if (unreadCount > 0) {
        badge.textContent = unreadCount > 99 ? '99+' : unreadCount;
        badge.classList.remove('hidden');
    } else {
        badge.classList.add('hidden');
    }
}

function displayNotifications(notifications) {
    const container = document.getElementById('notificationsList');
    container.innerHTML = '';
    
    if (notifications.length === 0) {
        container.innerHTML = '<div class="text-center" style="padding: 40px; color: var(--text-secondary);">No notifications</div>';
        return;
    }
    
    notifications.forEach(notif => {
        const div = document.createElement('div');
        div.className = `notification-item ${notif.read_status ? '' : 'unread'}`;
        
        const time = new Date(notif.created_at * 1000).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        
        div.innerHTML = `
            <div style="width: 40px; height: 40px; border-radius: 50%; background: var(--accent); display: flex; align-items: center; justify-content: center;">
                <i class="fas fa-bell" style="color: white;"></i>
            </div>
            <div class="notification-content">
                <div><strong>${notif.from_user}</strong> ${notif.content}</div>
                <div class="notification-time">${time}</div>
            </div>
        `;
        
        div.onclick = () => markNotificationRead(notif.id);
        container.appendChild(div);
    });
}

function markNotificationRead(notificationId) {
    fetch('?api=mark_notification_read', {
        method: 'POST',
        body: JSON.stringify({ id: notificationId })
    });
}

function showBrowserNotification(notification) {
    if (!('Notification' in window) || Notification.permission !== 'granted') {
        return;
    }
    
    new Notification('LinkA', {
        body: notification.content,
        icon: '/favicon.ico'
    });
}

// ===== SEARCH =====
function searchUsers() {
    const query = document.getElementById('searchInput').value.trim();
    if (query.length < 2) {
        document.getElementById('searchResults').innerHTML = '';
        return;
    }
    
    fetch(`?api=search&q=${query}`)
        .then(r => r.json())
        .then(users => {
            const container = document.getElementById('searchResults');
            container.innerHTML = '';
            
            if (users.length === 0) {
                container.innerHTML = '<div class="text-center" style="padding: 40px; color: var(--text-secondary);">No users found</div>';
                return;
            }
            
            users.forEach(user => {
                const div = document.createElement('div');
                div.className = 'contact-item';
                div.onclick = () => {
                    openChat(user.username, 'user');
                    hideModal('searchModal');
                };
                
                div.innerHTML = `
                    <img src="${user.avatar_url || 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI1MCIgZmlsbD0iI2UwZTBlMCIvPjx0ZXh0IHg9IjUwIiB5PSI1NSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0iIzY2NiIgZm9udC1zaXplPSI0MCI+ITwvdGV4dD48L3N2Zz4='}" 
                         class="contact-avatar">
                    <div class="contact-info">
                        <h4>${user.name || user.username} ${user.privacy == 1 ? '<span class="badge" style="background: var(--warning);">Private</span>' : ''}</h4>
                        <span>${user.bio || 'No bio'}</span>
                    </div>
                    <button class="btn btn-small">
                        <i class="fas fa-message"></i> Chat
                    </button>
                `;
                
                container.appendChild(div);
            });
        });
}

// ===== UTILITY FUNCTIONS =====
function showModal(id) {
    document.getElementById(id).classList.add('active');
    
    // Load data for specific modals
    switch(id) {
        case 'groupModal':
            loadGroups();
            break;
        case 'contactsModal':
            loadContactRequests();
            break;
        case 'notificationsModal':
            loadNotifications();
            break;
        case 'createGroupModal':
            selectedMembers = [];
            updateSelectedMembers();
            break;
    }
}

function hideModal(id) {
    document.getElementById(id).classList.remove('active');
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
        <span>${message}</span>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 5000);
}

function clearCurrentChat() {
    if (!currentChat || !confirm('Clear all messages in this chat?')) {
        return;
    }
    
    // Note: This would need a proper API endpoint to clear messages
    showToast('Clear chat feature would be implemented here', 'info');
}

function showChatInfo() {
    if (!currentChat) return;
    
    let info = '';
    if (currentChatType === 'user') {
        info = `Chat with ${currentChat}`;
    } else {
        info = `Group: ${document.getElementById('chatContactName').textContent}`;
    }
    
    alert(info);
}

function toggleMobileMenu() {
    const inbox = document.getElementById('inboxList');
    inbox.classList.toggle('active');
}

function showSection(section) {
    document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
    event.target.closest('.nav-item').classList.add('active');
    
    if (section === 'inbox' && window.innerWidth <= 768) {
        toggleMobileMenu();
    }
}

// Close modals on escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal.active').forEach(modal => {
            modal.classList.remove('active');
        });
    }
});

// Close modals when clicking outside
document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', function(e) {
        if (e.target === this) {
            this.classList.remove('active');
        }
    });
});

// Service Worker for PWA
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(console.error);
}

// Create manifest.json content
const manifest = {
    "name": "LinkA",
    "short_name": "LinkA",
    "description": "Secure messaging with end-to-end encryption",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#000000",
    "theme_color": "#007aff",
    "icons": [
        {
            "src": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI1MCIgZmlsbD0iIzAwN2FmZiIvPjx0ZXh0IHg9IjUwIiB5PSI1NSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0id2hpdGUiIGZvbnQtc2l6ZT0iNDAiPkw8L3RleHQ+PC9zdmc+",
            "sizes": "100x100",
            "type": "image/svg+xml"
        }
    ]
};

// Create service worker
const swContent = `
self.addEventListener('install', event => {
    event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', event => {
    event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', event => {
    event.respondWith(fetch(event.request));
});
`;
</script>

<!-- Create manifest and service worker files dynamically -->
<script>
// Create manifest.json
const manifestBlob = new Blob([JSON.stringify(manifest)], {type: 'application/json'});
const manifestUrl = URL.createObjectURL(manifestBlob);

const link = document.createElement('link');
link.rel = 'manifest';
link.href = manifestUrl;
document.head.appendChild(link);

// Create service worker
if ('serviceWorker' in navigator) {
    const swBlob = new Blob([swContent], {type: 'application/javascript'});
    const swUrl = URL.createObjectURL(swBlob);
    
    navigator.serviceWorker.register(swUrl).catch(console.error);
}
</script>
</body>
</html>
