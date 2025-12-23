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
  telegram_backup INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender TEXT,
  receiver TEXT,
  content TEXT,
  message_type TEXT DEFAULT 'text',
  file_name TEXT,
  file_size INTEGER,
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
");

// Update existing tables to add new columns if they don't exist
try {
    $db->exec("ALTER TABLE users ADD COLUMN last_seen INTEGER DEFAULT 0");
    $db->exec("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'offline'");
    $db->exec("ALTER TABLE users ADD COLUMN telegram_backup INTEGER DEFAULT 1");
    
    $db->exec("ALTER TABLE messages ADD COLUMN telegram_msg_id TEXT");
    $db->exec("ALTER TABLE groups ADD COLUMN telegram_msg_id TEXT");
    $db->exec("ALTER TABLE group_messages ADD COLUMN telegram_msg_id TEXT");
    $db->exec("ALTER TABLE contact_requests ADD COLUMN telegram_msg_id TEXT");
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

function sendToTelegram($data, $type = 'text') {
    $token = TELEGRAM_TOKEN;
    $chat_id = TELEGRAM_CHAT_ID;
    
    if ($type === 'text') {
        $url = "https://api.telegram.org/bot{$token}/sendMessage";
        $params = [
            'chat_id' => $chat_id,
            'text' => $data,
            'parse_mode' => 'HTML'
        ];
    } elseif ($type === 'document') {
        $url = "https://api.telegram.org/bot{$token}/sendDocument";
        $params = [
            'chat_id' => $chat_id,
            'document' => new CURLFile($data['path']),
            'caption' => $data['caption'] ?? ''
        ];
    } elseif ($type === 'photo') {
        $url = "https://api.telegram.org/bot{$token}/sendPhoto";
        $params = [
            'chat_id' => $chat_id,
            'photo' => new CURLFile($data['path']),
            'caption' => $data['caption'] ?? ''
        ];
    }
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 3); // 3 second timeout
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true);
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
    
    // Calculate new dimensions (10% of original)
    $width = imagesx($image);
    $height = imagesy($image);
    $newWidth = ceil($width * ($quality / 100));
    $newHeight = ceil($height * ($quality / 100));
    
    // Create new image with compressed dimensions
    $compressedImage = imagecreatetruecolor($newWidth, $newHeight);
    
    // Preserve transparency for PNG and GIF
    if ($info['mime'] == 'image/png' || $info['mime'] == 'image/gif') {
        imagecolortransparent($compressedImage, imagecolorallocatealpha($compressedImage, 0, 0, 0, 127));
        imagealphablending($compressedImage, false);
        imagesavealpha($compressedImage, true);
    }
    
    // Copy and resize image
    imagecopyresampled($compressedImage, $image, 0, 0, 0, 0, $newWidth, $newHeight, $width, $height);
    
    // Save compressed image
    if ($info['mime'] == 'image/jpeg') {
        imagejpeg($compressedImage, $targetPath, 85); // 85% JPEG quality
    } elseif ($info['mime'] == 'image/png') {
        imagepng($compressedImage, $targetPath, 8); // 8 = medium compression
    } elseif ($info['mime'] == 'image/gif') {
        imagegif($compressedImage, $targetPath);
    } elseif ($info['mime'] == 'image/webp') {
        imagewebp($compressedImage, $targetPath, 85);
    }
    
    imagedestroy($image);
    imagedestroy($compressedImage);
    
    return true;
}

function backupToTelegram($data, $backupType) {
    global $db;
    
    // Check if user has enabled backup
    $stmt = $db->prepare("SELECT telegram_backup FROM users WHERE username = ?");
    $stmt->execute([$data['username'] ?? getCurrentUser()]);
    $user = $stmt->fetch();
    
    if (!$user || $user['telegram_backup'] == 0) {
        return false;
    }
    
    $timestamp = date('Y-m-d H:i:s');
    
    switch ($backupType) {
        case 'user_registered':
            $text = "👤 <b>New User Registered</b>\n";
            $text .= "Time: {$timestamp}\n";
            $text .= "Username: @{$data['username']}\n";
            $text .= "Name: {$data['name']}\n";
            $text .= "Bio: {$data['bio']}\n";
            break;
            
        case 'message_sent':
            $text = "💬 <b>New Message</b>\n";
            $text .= "Time: {$timestamp}\n";
            $text .= "From: @{$data['from']}\n";
            $text .= "To: @{$data['to']}\n";
            $text .= "Message: {$data['message']}\n";
            if (isset($data['file'])) {
                $text .= "File: {$data['file']}\n";
            }
            break;
            
        case 'group_created':
            $text = "👥 <b>New Group Created</b>\n";
            $text .= "Time: {$timestamp}\n";
            $text .= "Name: {$data['name']}\n";
            $text .= "Description: {$data['description']}\n";
            $text .= "Creator: @{$data['creator']}\n";
            $text .= "Members: " . implode(', ', $data['members']) . "\n";
            break;
            
        case 'group_message':
            $text = "👥 <b>Group Message</b>\n";
            $text .= "Time: {$timestamp}\n";
            $text .= "Group: {$data['group']}\n";
            $text .= "From: @{$data['from']}\n";
            $text .= "Message: {$data['message']}\n";
            break;
            
        case 'contact_request':
            $text = "🤝 <b>Contact Request</b>\n";
            $text .= "Time: {$timestamp}\n";
            $text .= "From: @{$data['from']}\n";
            $text .= "To: @{$data['to']}\n";
            $text .= "Status: {$data['status']}\n";
            break;
    }
    
    $result = sendToTelegram($text, 'text');
    
    if (isset($result['result']['message_id'])) {
        return $result['result']['message_id'];
    }
    
    return false;
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
            
            // Backup to Telegram
            $backupData = [
                'username' => $username,
                'name' => $name,
                'bio' => 'Hello!'
            ];
            $msg_id = backupToTelegram($backupData, 'user_registered');
            
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

            // Update user status
            updateUserStatus($username, 'online');
            
            $_SESSION['username'] = $username;
            echo json_encode(['success' => true, 'message' => 'Login successful']);
            break;

        case 'logout':
            $user = getCurrentUser();
            if ($user) {
                updateUserStatus($user, 'offline');
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
                
                // Update last seen
                updateUserStatus($user, 'online');
                
                echo json_encode(['authenticated' => true, 'user' => $userData]);
            } else {
                echo json_encode(['authenticated' => false]);
            }
            break;

        case 'get_profile':
            $user = $_GET['username'] ?? getCurrentUser();
            $stmt = $db->prepare("SELECT username, name, bio, avatar, theme, privacy, last_seen, status, telegram_backup FROM users WHERE username = ?");
            $stmt->execute([$user]);
            $profile = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Calculate online status
            if ($profile) {
                $current_time = time();
                $last_seen = $profile['last_seen'];
                
                if ($current_time - $last_seen < 300) { // 5 minutes
                    $profile['status'] = 'online';
                } else {
                    $profile['status'] = 'offline';
                }
                
                // Format last seen
                if ($profile['status'] == 'online') {
                    $profile['last_seen_text'] = 'Online';
                } else {
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
                
                // Save original
                file_put_contents('avatars/' . $filename, $data);
                
                // Create compressed version
                $compressedFilename = $user . '_' . time() . '_compressed.' . $extension;
                compressAndSaveImage('avatars/' . $filename, 'avatars/' . $compressedFilename, 10);
                
                // Use compressed version
                $stmt = $db->prepare("UPDATE users SET avatar = ? WHERE username = ?");
                $stmt->execute([$compressedFilename, $user]);
                
                echo json_encode(['success' => true, 'avatar' => $compressedFilename]);
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
            $stmt = $db->prepare("SELECT username, name, avatar, privacy, last_seen FROM users WHERE (username LIKE ? OR name LIKE ?) AND username != ? LIMIT 20");
            $stmt->execute([$search, $search, $user]);
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Add status and filter by privacy
            $filtered = [];
            $current_time = time();
            
            foreach ($users as $u) {
                // Calculate status
                $last_seen = $u['last_seen'];
                if ($current_time - $last_seen < 300) { // 5 minutes
                    $u['status'] = 'online';
                } else {
                    $u['status'] = 'offline';
                }
                
                // Format last seen for display
                if ($u['status'] == 'online') {
                    $u['last_seen_text'] = 'Online now';
                } else {
                    $u['last_seen_text'] = 'Last seen ' . date('H:i', $last_seen);
                }
                
                if ($u['privacy'] == 0) {
                    $filtered[] = $u;
                } else {
                    // Check if contact request exists
                    $stmt2 = $db->prepare("SELECT * FROM contact_requests WHERE (from_user = ? AND to_user = ? AND status = 'accepted') OR (from_user = ? AND to_user = ? AND status = 'accepted')");
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
            $online_threshold = $current_time - 300; // 5 minutes
            
            $stmt = $db->prepare("SELECT username, name, avatar, last_seen FROM users WHERE username != ? AND last_seen > ? ORDER BY last_seen DESC LIMIT 50");
            $stmt->execute([$user, $online_threshold]);
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            foreach ($users as &$u) {
                $u['status'] = 'online';
                $u['last_seen_text'] = 'Online now';
            }
            
            echo json_encode($users);
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
                $stmt2 = $db->prepare("SELECT username, name, avatar, last_seen FROM users WHERE username = ?");
                $stmt2->execute([$contact['contact']]);
                $userData = $stmt2->fetch(PDO::FETCH_ASSOC);
                if ($userData) {
                    // Calculate status
                    $current_time = time();
                    $last_seen = $userData['last_seen'];
                    if ($current_time - $last_seen < 300) {
                        $userData['status'] = 'online';
                    } else {
                        $userData['status'] = 'offline';
                    }
                    
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

            // Send message without encryption
            $stmt5 = $db->prepare("INSERT INTO messages (sender, receiver, content, message_type, file_name, file_size, time) 
                VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt5->execute([$user, $to, $message, $type, $file_name, $file_size, time()]);
            
            $message_id = $db->lastInsertId();

            // Send notification
            $stmt6 = $db->prepare("INSERT INTO notifications (username, type, from_user, content, created_at) VALUES (?, ?, ?, ?, ?)");
            $stmt6->execute([$to, 'message', $user, 'New message from ' . $user, time()]);

            // Backup to Telegram
            $backupData = [
                'from' => $user,
                'to' => $to,
                'message' => $message,
                'file' => $file_name
            ];
            $msg_id = backupToTelegram($backupData, 'message_sent');
            
            // Save Telegram message ID
            if ($msg_id) {
                $stmt7 = $db->prepare("UPDATE messages SET telegram_msg_id = ? WHERE id = ?");
                $stmt7->execute([$msg_id, $message_id]);
            }

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
                // Compress image if it's an image
                if (strpos($file['type'], 'image/') === 0) {
                    $compressedFilename = 'file_' . $user . '_' . time() . '_compressed.' . $extension;
                    compressAndSaveImage('uploads/' . $filename, 'uploads/' . $compressedFilename, 10);
                    $filename = $compressedFilename;
                    $file['size'] = filesize('uploads/' . $filename);
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

            // Backup to Telegram
            $backupData = [
                'name' => $name,
                'description' => $description,
                'creator' => $user,
                'members' => array_merge([$user], $members)
            ];
            $msg_id = backupToTelegram($backupData, 'group_created');
            
            // Save Telegram message ID
            if ($msg_id) {
                $stmt3 = $db->prepare("UPDATE groups SET telegram_msg_id = ? WHERE id = ?");
                $stmt3->execute([$msg_id, $group_id]);
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

            // Get group name
            $stmt2 = $db->prepare("SELECT name FROM groups WHERE id = ?");
            $stmt2->execute([$group_id]);
            $group = $stmt2->fetch();
            
            $stmt3 = $db->prepare("INSERT INTO group_messages (group_id, sender, content, message_type, time) VALUES (?, ?, ?, ?, ?)");
            $stmt3->execute([$group_id, $user, $message, $type, time()]);
            
            $message_id = $db->lastInsertId();

            // Backup to Telegram
            $backupData = [
                'group' => $group['name'],
                'from' => $user,
                'message' => $message
            ];
            $msg_id = backupToTelegram($backupData, 'group_message');
            
            // Save Telegram message ID
            if ($msg_id) {
                $stmt4 = $db->prepare("UPDATE group_messages SET telegram_msg_id = ? WHERE id = ?");
                $stmt4->execute([$msg_id, $message_id]);
            }

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

            $status = $action . 'ed';
            $stmt = $db->prepare("UPDATE contact_requests SET status = ? WHERE id = ? AND to_user = ?");
            $stmt->execute([$status, $request_id, $user]);

            // Backup to Telegram
            $stmt2 = $db->prepare("SELECT from_user, to_user FROM contact_requests WHERE id = ?");
            $stmt2->execute([$request_id]);
            $request = $stmt2->fetch();
            
            if ($request) {
                $backupData = [
                    'from' => $request['from_user'],
                    'to' => $request['to_user'],
                    'status' => $status
                ];
                backupToTelegram($backupData, 'contact_request');
            }

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
            $telegram_backup = intval($input['telegram_backup'] ?? 1);

            $stmt = $db->prepare("UPDATE users SET theme = ?, notifications = ?, telegram_backup = ? WHERE username = ?");
            $stmt->execute([$theme, $notifications, $telegram_backup, $user]);

            echo json_encode(['success' => true]);
            break;

        case 'update_last_seen':
            $user = getCurrentUser();
            if ($user) {
                updateUserStatus($user, 'online');
            }
            echo json_encode(['success' => true]);
            break;

        case 'backup_data':
            $user = getCurrentUser();
            if (!$user) {
                echo json_encode(['error' => 'Not authenticated']);
                break;
            }

            // Get user data
            $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
            $stmt->execute([$user]);
            $userData = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Get messages
            $stmt2 = $db->prepare("SELECT * FROM messages WHERE sender = ? OR receiver = ? LIMIT 100");
            $stmt2->execute([$user, $user]);
            $messages = $stmt2->fetchAll(PDO::FETCH_ASSOC);
            
            // Get groups
            $stmt3 = $db->prepare("SELECT g.* FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.username = ?");
            $stmt3->execute([$user]);
            $groups = $stmt3->fetchAll(PDO::FETCH_ASSOC);
            
            $backupData = [
                'user' => $userData,
                'messages' => $messages,
                'groups' => $groups,
                'timestamp' => time(),
                'total_messages' => count($messages),
                'total_groups' => count($groups)
            ];
            
            $jsonData = json_encode($backupData, JSON_PRETTY_PRINT);
            
            // Send to Telegram
            $filename = 'backup_' . $user . '_' . date('Y-m-d') . '.json';
            file_put_contents('temp/' . $filename, $jsonData);
            
            $result = sendToTelegram([
                'path' => 'temp/' . $filename,
                'caption' => "📊 Backup data for @{$user} - " . date('Y-m-d H:i:s')
            ], 'document');
            
            unlink('temp/' . $filename);
            
            echo json_encode(['success' => true, 'result' => $result]);
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
if (!file_exists('temp')) mkdir('temp', 0755);
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
    --online: #10b981;
    --offline: #9ca3af;
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
    position: relative;
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
    position: relative;
}

.contact-avatar .status-indicator {
    position: absolute;
    bottom: -0.125rem;
    right: -0.125rem;
    width: 0.75rem;
    height: 0.75rem;
    border-radius: 50%;
    border: 2px solid var(--white);
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

/* ===== SEARCH RESULTS ===== */
.search-results {
    max-height: 400px;
    overflow-y: auto;
    margin-top: 1rem;
    border: 1px solid var(--gray-200);
    border-radius: var(--radius);
}

.search-item {
    display: flex;
    align-items: center;
    padding: 0.75rem;
    border-bottom: 1px solid var(--gray-200);
    cursor: pointer;
    transition: background 0.2s;
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
}

.search-item-name {
    font-weight: 500;
    margin-bottom: 0.125rem;
}

.search-item-username {
    font-size: 0.75rem;
    color: var(--gray-500);
}

.search-item-status {
    font-size: 0.75rem;
    padding: 0.125rem 0.375rem;
    border-radius: 0.25rem;
    margin-top: 0.125rem;
}

.status-online-text {
    color: var(--online);
    font-weight: 500;
}

.status-offline-text {
    color: var(--offline);
}

/* ===== ONLINE USERS ===== */
.online-users-container {
    padding: 1rem;
    border-top: 1px solid var(--gray-200);
}

.online-users-title {
    font-size: 0.875rem;
    font-weight: 600;
    margin-bottom: 0.75rem;
    color: var(--gray-700);
}

.online-users-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
}

.online-user-item {
    display: flex;
    align-items: center;
    padding: 0.5rem;
    border-radius: var(--radius);
    cursor: pointer;
    transition: background 0.2s;
}

.online-user-item:hover {
    background: var(--gray-50);
}

.online-user-avatar {
    width: 2rem;
    height: 2rem;
    border-radius: 50%;
    object-fit: cover;
    background: var(--gray-200);
    position: relative;
}

.online-user-info {
    margin-left: 0.5rem;
    flex: 1;
}

.online-user-name {
    font-size: 0.875rem;
    font-weight: 500;
}

/* ===== CHAT ===== */
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
        position: absolute;
        top: 1rem;
        left: 1rem;
        z-index: 100;
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
            <p>Secure messaging with Telegram backup</p>
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
            <div class="form-checkbox">
                <input type="checkbox" id="rememberMe">
                <span>Remember me</span>
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
            <div class="form-checkbox">
                <input type="checkbox" id="enableBackup" checked>
                <span>Enable Telegram backup</span>
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
            <div class="notification-badge hidden" id="notificationBadge">0</div>
        </div>
        
        <div class="sidebar-nav">
            <div class="nav-item active" onclick="showSection('inbox')">
                <i class="fas fa-inbox"></i>
                <span>Inbox</span>
            </div>
            <div class="nav-item" onclick="showModal('searchModal')">
                <i class="fas fa-search"></i>
                <span>Search Users</span>
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
            <div class="nav-item" onclick="backupData()">
                <i class="fas fa-cloud-upload-alt"></i>
                <span>Backup to Telegram</span>
            </div>
            <div class="nav-item" onclick="logout()">
                <i class="fas fa-sign-out-alt"></i>
                <span>Logout</span>
            </div>
        </div>
        
        <div class="inbox-list" id="inboxList">
            <!-- Inbox items will be loaded here -->
        </div>
        
        <div class="online-users-container">
            <div class="online-users-title">Online Now</div>
            <div class="online-users-list" id="onlineUsersList">
                <!-- Online users will appear here -->
            </div>
        </div>
    </div>
    
    <!-- Main Content -->
    <div class="main-content">
        <div class="chat-header">
            <div class="chat-header-info">
                <img src="avatars/default.png" class="avatar" id="chatAvatar">
                <div class="status-indicator" id="chatStatusIndicator"></div>
                <div>
                    <h3 id="chatWith">Select a chat</h3>
                    <span id="chatStatus">Start a conversation</span>
                </div>
            </div>
            <div class="chat-actions" id="chatActions" style="display: none;">
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
                <div class="text-center" style="padding: 2rem; color: var(--gray-500);">
                    <i class="fas fa-search" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                    <p>Start typing to search for users</p>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Online Users Modal -->
<div class="modal" id="onlineUsersModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>Online Users</h3>
            <button class="modal-close" onclick="hideModal('onlineUsersModal')">
                <i class="fas fa-times"></i>
            </button>
        </div>
        <div class="modal-body">
            <div class="search-results" id="onlineUsersResults">
                <!-- Online users will appear here -->
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
                <div class="status-indicator status-online" style="position: absolute; bottom: 4.5rem; left: calc(50% + 1.5rem);"></div>
                <input type="file" id="avatarInput" class="hidden" accept="image/*">
                <p class="text-sm" style="color: var(--gray-500); margin-top: 0.5rem;">Click to change avatar</p>
                <p class="text-xs" style="color: var(--gray-400);">Images are compressed to 10% size</p>
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
            <div class="form-group">
                <label class="form-checkbox">
                    <input type="checkbox" id="telegramBackupToggle" checked>
                    <span>Enable Telegram backup</span>
                </label>
                <p class="text-xs" style="color: var(--gray-500); margin-top: 0.25rem;">
                    Messages, groups, and contacts will be backed up to Telegram
                </p>
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
// ===== LOCALSTORAGE HELPER =====
const Storage = {
    set: (key, value) => {
        try {
            localStorage.setItem(key, JSON.stringify(value));
        } catch (e) {
            console.error('Error saving to localStorage', e);
        }
    },

    get: (key) => {
        try {
            const item = localStorage.getItem(key);
            return item ? JSON.parse(item) : null;
        } catch (e) {
            console.error('Error reading from localStorage', e);
            return null;
        }
    },

    remove: (key) => {
        localStorage.removeItem(key);
    }
};

// ===== GLOBAL STATE =====
let currentUser = null;
let currentChat = null;
let currentChatType = null;
let onlineUsers = [];
let userStatusInterval = null;

// ===== LOCALSTORAGE KEYS =====
const LS_KEYS = {
    USER_PROFILE: 'linka_user_profile',
    INBOX_DATA: 'linka_inbox_data',
    CHAT_MESSAGES: 'linka_chat_messages',
    LAYOUT_SETTINGS: 'linka_layout_settings',
    LOGIN_INFO: 'linka_login_info',
    USER_SETTINGS: 'linka_user_settings'
};

// ===== INITIALIZATION =====
document.addEventListener('DOMContentLoaded', function() {
    // Load saved login info
    const savedLogin = Storage.get(LS_KEYS.LOGIN_INFO);
    if (savedLogin && savedLogin.rememberMe) {
        document.getElementById('loginUsername').value = savedLogin.username || '';
        document.getElementById('rememberMe').checked = true;
    }
    
    checkAuth();
    
    // Update last seen every minute
    setInterval(updateLastSeen, 60000);
    
    // Load online users every 30 seconds
    setInterval(loadOnlineUsers, 30000);
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

async function login() {
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value.trim();
    const rememberMe = document.getElementById('rememberMe').checked;
    
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
            
            // Save login info if remember me is checked
            if (rememberMe) {
                Storage.set(LS_KEYS.LOGIN_INFO, {
                    username: username,
                    rememberMe: true
                });
            } else {
                Storage.remove(LS_KEYS.LOGIN_INFO);
            }
            
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
    const enableBackup = document.getElementById('enableBackup').checked;
    
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
            body: JSON.stringify({ 
                username, 
                name, 
                password, 
                confirm_password: confirmPassword,
                telegram_backup: enableBackup ? 1 : 0
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

function showLoginForm() {
    document.getElementById('loginForm').classList.remove('hidden');
    document.getElementById('registerForm').classList.add('hidden');
}

function showRegisterForm() {
    document.getElementById('loginForm').classList.add('hidden');
    document.getElementById('registerForm').classList.remove('hidden');
}

// ===== APP FUNCTIONS =====
function loadApp() {
    document.getElementById('authScreen').style.display = 'none';
    document.getElementById('appContainer').classList.remove('hidden');
    
    // Load layout settings
    loadLayoutSettings();
    
    loadUserProfile();
    loadInbox();
    loadOnlineUsers();
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
        loadOnlineUsers();
        loadNotifications();
        loadContactRequests();
    }, 3000);
}

// ===== USER STATUS FUNCTIONS =====
async function updateLastSeen() {
    if (currentUser) {
        try {
            await fetch('?api=update_last_seen');
        } catch (error) {
            console.error('Error updating last seen:', error);
        }
    }
}

async function loadOnlineUsers() {
    if (!currentUser) return;
    
    try {
        const response = await fetch('?api=get_online_users');
        const users = await response.json();
        onlineUsers = users;
        
        // Update sidebar online users
        updateSidebarOnlineUsers(users);
        
        // Update modal if open
        if (document.getElementById('onlineUsersModal').classList.contains('active')) {
            updateOnlineUsersModal(users);
        }
    } catch (error) {
        console.error('Error loading online users:', error);
    }
}

function updateSidebarOnlineUsers(users) {
    const container = document.getElementById('onlineUsersList');
    container.innerHTML = '';
    
    if (users.length === 0) {
        container.innerHTML = '<div class="text-center" style="padding: 0.5rem; color: var(--gray-500); font-size: 0.75rem;">No users online</div>';
        return;
    }
    
    // Show only first 5 users in sidebar
    const displayUsers = users.slice(0, 5);
    
    displayUsers.forEach(user => {
        const div = document.createElement('div');
        div.className = 'online-user-item';
        div.onclick = () => {
            openChat(user.username, 'user');
            hideModal('onlineUsersModal');
        };
        
        let avatarSrc = 'avatars/default.png';
        if (user.avatar && user.avatar !== 'default.png') {
            avatarSrc = `avatars/${user.avatar}`;
        }
        
        div.innerHTML = `
            <img src="${avatarSrc}" class="online-user-avatar">
            <div class="status-indicator status-online" style="position: absolute; bottom: 0; right: 0;"></div>
            <div class="online-user-info">
                <div class="online-user-name">${user.name || user.username}</div>
            </div>
        `;
        
        container.appendChild(div);
    });
    
    if (users.length > 5) {
        const moreDiv = document.createElement('div');
        moreDiv.className = 'text-center';
        moreDiv.style.padding = '0.5rem';
        moreDiv.style.fontSize = '0.75rem';
        moreDiv.style.color = 'var(--gray-500)';
        moreDiv.textContent = `+${users.length - 5} more online`;
        moreDiv.onclick = () => showModal('onlineUsersModal');
        moreDiv.style.cursor = 'pointer';
        container.appendChild(moreDiv);
    }
}

function updateOnlineUsersModal(users) {
    const container = document.getElementById('onlineUsersResults');
    container.innerHTML = '';
    
    if (users.length === 0) {
        container.innerHTML = '<div class="text-center" style="padding: 2rem; color: var(--gray-500);">No users online</div>';
        return;
    }
    
    users.forEach(user => {
        const div = document.createElement('div');
        div.className = 'search-item';
        div.onclick = () => {
            openChat(user.username, 'user');
            hideModal('onlineUsersModal');
        };
        
        let avatarSrc = 'avatars/default.png';
        if (user.avatar && user.avatar !== 'default.png') {
            avatarSrc = `avatars/${user.avatar}`;
        }
        
        const lastSeen = new Date(user.last_seen * 1000);
        const now = new Date();
        const diffMinutes = Math.floor((now - lastSeen) / (1000 * 60));
        
        div.innerHTML = `
            <img src="${avatarSrc}" class="search-avatar">
            <div class="status-indicator status-online"></div>
            <div class="search-item-info">
                <div class="search-item-name">${user.name || user.username}</div>
                <div class="search-item-username">@${user.username}</div>
                <div class="search-item-status status-online-text">
                    <i class="fas fa-circle" style="font-size: 0.5rem;"></i> Online now
                </div>
            </div>
        `;
        
        container.appendChild(div);
    });
}

// ===== SEARCH FUNCTION =====
async function searchUsers() {
    const query = document.getElementById('searchInput').value.trim();
    
    if (query.length < 2) {
        document.getElementById('searchResults').innerHTML = `
            <div class="text-center" style="padding: 2rem; color: var(--gray-500);">
                <i class="fas fa-search" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                <p>Type at least 2 characters to search</p>
            </div>
        `;
        return;
    }
    
    try {
        // Show loading
        document.getElementById('searchResults').innerHTML = `
            <div class="text-center" style="padding: 2rem; color: var(--gray-500);">
                <i class="fas fa-spinner fa-spin" style="font-size: 1.5rem;"></i>
                <p>Searching...</p>
            </div>
        `;
        
        const response = await fetch(`?api=search_users?q=${encodeURIComponent(query)}`);
        const users = await response.json();
        
        const container = document.getElementById('searchResults');
        container.innerHTML = '';
        
        if (users.length === 0) {
            container.innerHTML = '<div class="text-center" style="padding: 2rem; color: var(--gray-500);">No users found</div>';
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
            
            const statusClass = user.status === 'online' ? 'status-online' : 'status-offline';
            const statusText = user.status === 'online' ? 'Online now' : user.last_seen_text || 'Offline';
            const statusColor = user.status === 'online' ? 'status-online-text' : 'status-offline-text';
            
            div.innerHTML = `
                <img src="${avatarSrc}" class="search-avatar">
                <div class="search-status ${statusClass}"></div>
                <div class="search-item-info">
                    <div class="search-item-name">${user.name || user.username}</div>
                    <div class="search-item-username">@${user.username}</div>
                    <div class="search-item-status ${statusColor}">
                        <i class="fas fa-circle" style="font-size: 0.5rem;"></i> ${statusText}
                    </div>
                </div>
                ${user.privacy == 1 ? '<span style="color: var(--gray-500); font-size: 0.75rem;">Private</span>' : ''}
            `;
            
            container.appendChild(div);
        });
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

// ===== PROFILE FUNCTIONS =====
async function loadUserProfile() {
    try {
        const response = await fetch(`?api=get_profile`);
        const data = await response.json();
        
        if (data.username) {
            // Update profile display
            document.getElementById('userName').textContent = data.name || data.username;
            document.getElementById('editUsername').value = data.username;
            document.getElementById('editName').value = data.name || '';
            document.getElementById('editBio').value = data.bio || '';
            document.getElementById('editPrivacy').checked = data.privacy == 1;
            document.getElementById('telegramBackupToggle').checked = data.telegram_backup == 1;
            
            // Update status indicator
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
            document.getElementById('editAvatar').src = avatarSrc;
            
            // Save to localStorage
            Storage.set(LS_KEYS.USER_PROFILE, data);
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
            
            // Update localStorage
            const cachedProfile = Storage.get(LS_KEYS.USER_PROFILE) || {};
            cachedProfile.name = name;
            cachedProfile.bio = bio;
            cachedProfile.privacy = privacy;
            Storage.set(LS_KEYS.USER_PROFILE, cachedProfile);
            
            loadUserProfile();
            showToast('Profile updated', 'success');
        }
    } catch (error) {
        showToast('Update failed', 'error');
    }
}

// Handle avatar upload with compression
document.getElementById('avatarInput').addEventListener('change', async function(e) {
    if (e.target.files[0]) {
        let file = e.target.files[0];
        
        // Compress image
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
                    // Update localStorage
                    const cachedProfile = Storage.get(LS_KEYS.USER_PROFILE) || {};
                    cachedProfile.avatar = data.avatar;
                    Storage.set(LS_KEYS.USER_PROFILE, cachedProfile);
                    
                    // Update display
                    const avatarUrl = `avatars/${data.avatar}`;
                    document.getElementById('userAvatar').src = avatarUrl;
                    document.getElementById('editAvatar').src = avatarUrl;
                    
                    showToast('Avatar updated (compressed to 10%)', 'success');
                }
            } catch (error) {
                showToast('Avatar upload failed', 'error');
            }
        };
        reader.readAsDataURL(file);
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
            if (item.avatar) {
                if (item.avatar === 'default.png') {
                    avatarSrc = 'avatars/default.png';
                } else {
                    avatarSrc = `avatars/${item.avatar}`;
                }
            }
            
            if (item.type === 'user') {
                const statusClass = item.status === 'online' ? 'status-online' : 'status-offline';
                
                div.innerHTML = `
                    <img src="${avatarSrc}" class="contact-avatar">
                    <div class="status-indicator ${statusClass}"></div>
                    <div class="contact-info">
                        <h4>${item.name || item.username}</h4>
                        <span>${item.status === 'online' ? 'Online' : 'Offline'}</span>
                    </div>
                `;
            } else {
                div.innerHTML = `
                    <div class="contact-avatar" style="background: var(--gray-300); display: flex; align-items: center; justify-content: center;">
                        <i class="fas fa-users" style="color: var(--gray-600);"></i>
                    </div>
                    <div class="contact-info">
                        <h4>${item.name}</h4>
                        <span>Group chat</span>
                    </div>
                `;
            }
            
            container.appendChild(div);
        });
    } catch (error) {
        console.error('Inbox load error:', error);
    }
}

async function openChat(target, type, groupName = '') {
    currentChat = target;
    currentChatType = type;
    
    document.getElementById('chatInputArea').classList.remove('hidden');
    document.getElementById('chatActions').style.display = 'flex';
    
    if (type === 'user') {
        document.getElementById('chatWith').textContent = target;
        
        // Load user profile for status
        try {
            const response = await fetch(`?api=get_profile?username=${target}`);
            const userData = await response.json();
            
            if (userData.username) {
                // Update status
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
        
        loadMessages();
    } else {
        document.getElementById('chatWith').textContent = groupName || 'Group';
        document.getElementById('chatStatus').textContent = 'Group chat';
        document.getElementById('chatAvatar').src = 'avatars/default.png';
        document.getElementById('chatStatusIndicator').className = 'status-indicator';
        
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
                    <div style="padding: 0.75rem; background: var(--gray-50); border-radius: var(--radius); margin-top: 0.5rem; border: 1px solid var(--gray-200);">
                        <div style="display: flex; align-items: center; gap: 0.75rem;">
                            <i class="fas fa-file" style="font-size: 1.5rem; color: var(--gray-600);"></i>
                            <div style="flex: 1;">
                                <div style="font-weight: 500;">${msg.file_name}</div>
                                <div style="font-size: 0.75rem; color: var(--gray-500);">${formatFileSize(msg.file_size)}</div>
                            </div>
                            <a href="uploads/${msg.file_name}" class="btn" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;" download>
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
    
    if (!message) return;
    
    let apiUrl, payload;
    
    if (currentChatType === 'user') {
        apiUrl = '?api=send_message';
        payload = {
            to: currentChat,
            message: message,
            type: 'text'
        };
    } else {
        apiUrl = '?api=send_group_message';
        payload = {
            group_id: currentChat,
            message: message,
            type: 'text'
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
            
            if (currentChatType === 'user') {
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
                // Send file as message
                if (currentChatType === 'user') {
                    const payload = {
                        to: currentChat,
                        message: '[File]',
                        type: 'file',
                        file_name: data.filename,
                        file_size: data.size
                    };
                    
                    const sendResponse = await fetch('?api=send_message', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });
                    
                    const sendData = await sendResponse.json();
                    
                    if (sendData.success) {
                        loadMessages();
                    }
                }
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

// ===== TELEGRAM BACKUP =====
async function backupData() {
    if (!currentUser) return;
    
    try {
        showToast('Backing up data to Telegram...', 'info');
        const response = await fetch('?api=backup_data', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Data backed up to Telegram successfully', 'success');
        } else {
            showToast('Backup failed', 'error');
        }
    } catch (error) {
        console.error('Backup error:', error);
        showToast('Backup failed', 'error');
    }
}

// ===== SETTINGS =====
async function saveSettings() {
    const theme = document.getElementById('themeSelect').value;
    const notifications = document.getElementById('notificationsToggle').checked ? 1 : 0;
    const telegram_backup = document.getElementById('telegramBackupToggle').checked ? 1 : 0;
    
    try {
        const response = await fetch('?api=update_settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ theme, notifications, telegram_backup })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Save to localStorage
            Storage.set(LS_KEYS.USER_SETTINGS, { theme, notifications, telegram_backup });
            saveLayoutSettings();
            
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
            root.style.setProperty('--gray-50', '#1a1a1a');
            root.style.setProperty('--gray-100', '#262626');
            root.style.setProperty('--gray-200', '#404040');
            root.style.setProperty('--gray-300', '#525252');
            root.style.setProperty('--gray-400', '#737373');
            root.style.setProperty('--gray-500', '#a3a3a3');
            root.style.setProperty('--gray-600', '#d4d4d4');
            root.style.setProperty('--gray-700', '#e5e5e5');
            root.style.setProperty('--gray-800', '#f0f0f0');
            root.style.setProperty('--gray-900', '#f9f9f9');
            break;
        case 'gray':
            root.style.setProperty('--black', '#404040');
            root.style.setProperty('--white', '#f5f5f5');
            root.style.setProperty('--gray-50', '#fafafa');
            root.style.setProperty('--gray-100', '#f5f5f5');
            root.style.setProperty('--gray-200', '#e5e5e5');
            root.style.setProperty('--gray-300', '#d4d4d4');
            root.style.setProperty('--gray-400', '#a3a3a3');
            root.style.setProperty('--gray-500', '#737373');
            root.style.setProperty('--gray-600', '#525252');
            root.style.setProperty('--gray-700', '#404040');
            root.style.setProperty('--gray-800', '#262626');
            root.style.setProperty('--gray-900', '#171717');
            break;
        default: // black
            root.style.setProperty('--black', '#000000');
            root.style.setProperty('--white', '#ffffff');
            root.style.setProperty('--gray-50', '#f9f9f9');
            root.style.setProperty('--gray-100', '#f0f0f0');
            root.style.setProperty('--gray-200', '#e5e5e5');
            root.style.setProperty('--gray-300', '#d4d4d4');
            root.style.setProperty('--gray-400', '#a3a3a3');
            root.style.setProperty('--gray-500', '#737373');
            root.style.setProperty('--gray-600', '#525252');
            root.style.setProperty('--gray-700', '#404040');
            root.style.setProperty('--gray-800', '#262626');
            root.style.setProperty('--gray-900', '#171717');
    }
}

// ===== MODAL FUNCTIONS =====
function showModal(id) {
    if (id === 'searchModal') {
        document.getElementById('searchInput').value = '';
        document.getElementById('searchResults').innerHTML = `
            <div class="text-center" style="padding: 2rem; color: var(--gray-500);">
                <i class="fas fa-search" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                <p>Start typing to search for users</p>
            </div>
        `;
    }
    
    if (id === 'onlineUsersModal') loadOnlineUsers();
    if (id === 'contactsModal') loadContactRequests();
    
    document.getElementById(id).classList.add('active');
}

function hideModal(id) {
    document.getElementById(id).classList.remove('active');
}

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('active');
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

// ===== LAYOUT SETTINGS =====
function loadLayoutSettings() {
    const layout = Storage.get(LS_KEYS.LAYOUT_SETTINGS) || {};
    
    // Apply theme
    if (layout.theme) {
        applyTheme(layout.theme);
        document.getElementById('themeSelect').value = layout.theme;
    }
}

function saveLayoutSettings() {
    const layout = {
        theme: document.getElementById('themeSelect').value,
        sidebarOpen: document.getElementById('sidebar').classList.contains('active')
    };
    Storage.set(LS_KEYS.LAYOUT_SETTINGS, layout);
}

// ===== TOAST FUNCTION =====
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

// ===== OTHER FUNCTIONS =====
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
    } catch (error) {
        console.error('Notifications error:', error);
    }
}

async function loadContactRequests() {
    // Implement contact requests loading
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
        
        if (messages.length === 0) {
            container.innerHTML = `
                <div class="text-center" style="padding: 3rem; color: var(--gray-500);">
                    <p>No messages in this group yet. Start the conversation!</p>
                </div>
            `;
        } else {
            container.scrollTop = container.scrollHeight;
        }
    } catch (error) {
        console.error('Group messages error:', error);
    }
}

function requestNotificationPermission() {
    if ('Notification' in window && Notification.permission === 'granted') {
        showToast('Notifications already enabled', 'success');
    } else if (Notification.permission !== 'denied') {
        Notification.requestPermission().then(permission => {
            if (permission === 'granted') {
                showToast('Notifications enabled', 'success');
            }
        });
    }
}

function clearChat() {
    if (!currentChat) return;
    
    if (confirm('Are you sure you want to clear this chat?')) {
        const cacheKey = currentChatType === 'user' 
            ? `${LS_KEYS.CHAT_MESSAGES}_${currentUser}_${currentChat}`
            : `${LS_KEYS.CHAT_MESSAGES}_group_${currentChat}`;
        
        Storage.remove(cacheKey);
        
        const container = document.getElementById('chatContainer');
        container.innerHTML = `
            <div class="text-center" style="padding: 3rem; color: var(--gray-500);">
                <p>Chat cleared</p>
            </div>
        `;
        
        showToast('Chat cleared', 'success');
    }
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
