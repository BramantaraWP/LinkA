<?php
/* ====================================
   LINKA - COMPLETE SECURE MESSENGER
   ==================================== */

session_start();
date_default_timezone_set('Asia/Jakarta');

// Create database connection
$db = null;
try {
    $db = new PDO("sqlite:data.db");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    die(json_encode(['error' => 'Database connection failed: ' . $e->getMessage()]));
}

// Encryption key (server-side)
define('ENCRYPTION_KEY', 'ENIGMAISMOSTSMARTENCRIPTIONINWW2');
define('MAX_FILE_SIZE', 15 * 1024 * 1024); // 15MB

/* === HELPER FUNCTIONS === */
function sanitize($input) {
    if (is_array($input)) {
        return array_map('sanitize', $input);
    }
    return htmlspecialchars(strip_tags($input), ENT_QUOTES, 'UTF-8');
}

function encryptMessage($message) {
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($message, 'AES-256-CBC', ENCRYPTION_KEY, 0, $iv);
    return base64_encode($iv . $encrypted);
}

function decryptMessage($encrypted) {
    try {
        $data = base64_decode($encrypted);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', ENCRYPTION_KEY, 0, $iv);
        return $decrypted !== false ? $decrypted : '[Encrypted message]';
    } catch (Exception $e) {
        return '[Encrypted message]';
    }
}

function generateToken($length = 32) {
    return bin2hex(random_bytes($length));
}

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function getCurrentUser() {
    return isset($_SESSION['username']) ? $_SESSION['username'] : null;
}

function getUserById($id) {
    global $db;
    $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch();
}

/* === INITIALIZE DATABASE === */
try {
    $db->exec("PRAGMA foreign_keys = ON");
    
    // Users table
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        email TEXT,
        bio TEXT DEFAULT '',
        avatar TEXT DEFAULT 'default',
        theme TEXT DEFAULT 'dark',
        notifications INTEGER DEFAULT 1,
        privacy INTEGER DEFAULT 0,
        status TEXT DEFAULT 'offline',
        last_seen INTEGER,
        created_at INTEGER NOT NULL
    )");
    
    // Messages table
    $db->exec("CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        message_type TEXT DEFAULT 'text',
        file_name TEXT,
        file_path TEXT,
        file_size INTEGER,
        is_read INTEGER DEFAULT 0,
        is_encrypted INTEGER DEFAULT 1,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (sender_id) REFERENCES users(id),
        FOREIGN KEY (receiver_id) REFERENCES users(id)
    )");
    
    // Groups table
    $db->exec("CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        avatar TEXT DEFAULT 'group_default',
        created_by INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (created_by) REFERENCES users(id)
    )");
    
    // Group members table
    $db->exec("CREATE TABLE IF NOT EXISTS group_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        role TEXT DEFAULT 'member',
        joined_at INTEGER NOT NULL,
        FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(group_id, user_id)
    )");
    
    // Group messages table
    $db->exec("CREATE TABLE IF NOT EXISTS group_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        message_type TEXT DEFAULT 'text',
        file_name TEXT,
        file_path TEXT,
        file_size INTEGER,
        is_encrypted INTEGER DEFAULT 1,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
        FOREIGN KEY (sender_id) REFERENCES users(id)
    )");
    
    // Contact requests table
    $db->exec("CREATE TABLE IF NOT EXISTS contact_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user INTEGER NOT NULL,
        to_user INTEGER NOT NULL,
        status TEXT DEFAULT 'pending', -- pending, accepted, rejected
        message TEXT,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (from_user) REFERENCES users(id),
        FOREIGN KEY (to_user) REFERENCES users(id),
        UNIQUE(from_user, to_user)
    )");
    
    // Contacts table (mutual contacts)
    $db->exec("CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user1_id INTEGER NOT NULL,
        user2_id INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (user1_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (user2_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user1_id, user2_id)
    )");
    
    // Notifications table
    $db->exec("CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL, -- message, contact_request, group_invite, etc.
        from_user_id INTEGER,
        group_id INTEGER,
        content TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
    
    // User sessions table
    $db->exec("CREATE TABLE IF NOT EXISTS user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        session_token TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
    
    // Create necessary directories
    if (!file_exists('uploads')) mkdir('uploads', 0755, true);
    if (!file_exists('uploads/avatars')) mkdir('uploads/avatars', 0755, true);
    if (!file_exists('uploads/files')) mkdir('uploads/files', 0755, true);
    
} catch (PDOException $e) {
    error_log("Database initialization error: " . $e->getMessage());
}

/* === API ENDPOINTS === */
if (isset($_GET['api'])) {
    header('Content-Type: application/json');
    
    try {
        $method = $_SERVER['REQUEST_METHOD'];
        $input = json_decode(file_get_contents('php://input'), true) ?? [];
        
        switch ($_GET['api']) {
            /* === AUTHENTICATION === */
            case 'register':
                if ($method !== 'POST') {
                    echo json_encode(['error' => 'Method not allowed']);
                    break;
                }
                
                $username = sanitize($input['username'] ?? '');
                $password = $input['password'] ?? '';
                $confirm_password = $input['confirm_password'] ?? '';
                $name = sanitize($input['name'] ?? '');
                $email = filter_var($input['email'] ?? '', FILTER_SANITIZE_EMAIL);
                
                // Validation
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
                
                // Hash password
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                
                // Create user
                $stmt = $db->prepare("INSERT INTO users (username, password, name, email, created_at) VALUES (?, ?, ?, ?, ?)");
                $stmt->execute([$username, $hashed_password, $name, $email, time()]);
                
                $user_id = $db->lastInsertId();
                
                // Create session
                $session_token = generateToken();
                $expires_at = time() + (30 * 24 * 60 * 60); // 30 days
                
                $stmt = $db->prepare("INSERT INTO user_sessions (user_id, session_token, expires_at, created_at) VALUES (?, ?, ?, ?)");
                $stmt->execute([$user_id, $session_token, $expires_at, time()]);
                
                $_SESSION['user_id'] = $user_id;
                $_SESSION['username'] = $username;
                $_SESSION['session_token'] = $session_token;
                
                echo json_encode([
                    'success' => true,
                    'message' => 'Registration successful',
                    'user' => [
                        'id' => $user_id,
                        'username' => $username,
                        'name' => $name
                    ]
                ]);
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
                
                // Get user
                $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
                $stmt->execute([$username]);
                $user = $stmt->fetch();
                
                if (!$user || !password_verify($password, $user['password'])) {
                    echo json_encode(['error' => 'Invalid credentials']);
                    break;
                }
                
                // Update last seen
                $db->prepare("UPDATE users SET last_seen = ?, status = 'online' WHERE id = ?")
                   ->execute([time(), $user['id']]);
                
                // Create session
                $session_token = generateToken();
                $expires_at = time() + (30 * 24 * 60 * 60);
                
                $stmt = $db->prepare("INSERT INTO user_sessions (user_id, session_token, expires_at, created_at) VALUES (?, ?, ?, ?)");
                $stmt->execute([$user['id'], $session_token, $expires_at, time()]);
                
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['session_token'] = $session_token;
                
                echo json_encode([
                    'success' => true,
                    'message' => 'Login successful',
                    'user' => [
                        'id' => $user['id'],
                        'username' => $user['username'],
                        'name' => $user['name'],
                        'avatar' => $user['avatar']
                    ]
                ]);
                break;
                
            case 'logout':
                if (isset($_SESSION['session_token'])) {
                    $db->prepare("DELETE FROM user_sessions WHERE session_token = ?")
                       ->execute([$_SESSION['session_token']]);
                }
                session_destroy();
                echo json_encode(['success' => true]);
                break;
                
            case 'check_auth':
                if (isLoggedIn()) {
                    $stmt = $db->prepare("SELECT id, username, name, avatar FROM users WHERE id = ?");
                    $stmt->execute([$_SESSION['user_id']]);
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
                
            /* === USER PROFILE === */
            case 'get_profile':
                if (!isLoggedIn()) {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                $user_id = $_GET['user_id'] ?? $_SESSION['user_id'];
                $stmt = $db->prepare("
                    SELECT id, username, name, email, bio, avatar, theme, privacy, 
                           status, last_seen, created_at 
                    FROM users 
                    WHERE id = ?
                ");
                $stmt->execute([$user_id]);
                $profile = $stmt->fetch();
                
                if ($profile) {
                    // Format last seen
                    $profile['last_seen_formatted'] = date('Y-m-d H:i:s', $profile['last_seen']);
                    echo json_encode(['success' => true, 'profile' => $profile]);
                } else {
                    echo json_encode(['error' => 'User not found']);
                }
                break;
                
            case 'update_profile':
                if (!isLoggedIn() || $method !== 'POST') {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                $name = sanitize($input['name'] ?? '');
                $bio = sanitize($input['bio'] ?? '');
                $email = filter_var($input['email'] ?? '', FILTER_SANITIZE_EMAIL);
                $privacy = intval($input['privacy'] ?? 0);
                
                $stmt = $db->prepare("UPDATE users SET name = ?, bio = ?, email = ?, privacy = ? WHERE id = ?");
                $stmt->execute([$name, $bio, $email, $privacy, $_SESSION['user_id']]);
                
                echo json_encode(['success' => true, 'message' => 'Profile updated']);
                break;
                
            case 'update_avatar':
                if (!isLoggedIn() || $method !== 'POST') {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                if (isset($_FILES['avatar']) && $_FILES['avatar']['error'] === 0) {
                    $file = $_FILES['avatar'];
                    $allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
                    
                    if (!in_array($file['type'], $allowed_types)) {
                        echo json_encode(['error' => 'Invalid file type']);
                        break;
                    }
                    
                    if ($file['size'] > 5 * 1024 * 1024) { // 5MB
                        echo json_encode(['error' => 'File too large']);
                        break;
                    }
                    
                    $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
                    $filename = 'avatar_' . $_SESSION['user_id'] . '_' . time() . '.' . $extension;
                    $filepath = 'uploads/avatars/' . $filename;
                    
                    if (move_uploaded_file($file['tmp_name'], $filepath)) {
                        // Delete old avatar if not default
                        $stmt = $db->prepare("SELECT avatar FROM users WHERE id = ?");
                        $stmt->execute([$_SESSION['user_id']]);
                        $old_avatar = $stmt->fetchColumn();
                        
                        if ($old_avatar !== 'default' && file_exists('uploads/avatars/' . $old_avatar)) {
                            unlink('uploads/avatars/' . $old_avatar);
                        }
                        
                        $db->prepare("UPDATE users SET avatar = ? WHERE id = ?")
                           ->execute([$filename, $_SESSION['user_id']]);
                        
                        echo json_encode([
                            'success' => true,
                            'message' => 'Avatar updated',
                            'avatar' => $filename
                        ]);
                    } else {
                        echo json_encode(['error' => 'Upload failed']);
                    }
                } else {
                    echo json_encode(['error' => 'No file uploaded']);
                }
                break;
                
            case 'update_password':
                if (!isLoggedIn() || $method !== 'POST') {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                $current_password = $input['current_password'] ?? '';
                $new_password = $input['new_password'] ?? '';
                $confirm_password = $input['confirm_password'] ?? '';
                
                // Validate
                if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
                    echo json_encode(['error' => 'All fields are required']);
                    break;
                }
                
                if ($new_password !== $confirm_password) {
                    echo json_encode(['error' => 'Passwords do not match']);
                    break;
                }
                
                if (strlen($new_password) < 6) {
                    echo json_encode(['error' => 'Password must be at least 6 characters']);
                    break;
                }
                
                // Verify current password
                $stmt = $db->prepare("SELECT password FROM users WHERE id = ?");
                $stmt->execute([$_SESSION['user_id']]);
                $hashed_password = $stmt->fetchColumn();
                
                if (!password_verify($current_password, $hashed_password)) {
                    echo json_encode(['error' => 'Current password is incorrect']);
                    break;
                }
                
                // Update password
                $new_hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
                $db->prepare("UPDATE users SET password = ? WHERE id = ?")
                   ->execute([$new_hashed_password, $_SESSION['user_id']]);
                
                echo json_encode(['success' => true, 'message' => 'Password updated']);
                break;
                
            /* === MESSAGES === */
            case 'send_message':
                if (!isLoggedIn() || $method !== 'POST') {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                $receiver_id = intval($input['receiver_id'] ?? 0);
                $content = sanitize($input['content'] ?? '');
                $message_type = $input['message_type'] ?? 'text';
                $file_name = sanitize($input['file_name'] ?? '');
                $file_size = intval($input['file_size'] ?? 0);
                
                if (empty($content) && $message_type === 'text') {
                    echo json_encode(['error' => 'Message cannot be empty']);
                    break;
                }
                
                if ($receiver_id === 0) {
                    echo json_encode(['error' => 'Invalid receiver']);
                    break;
                }
                
                // Check if receiver exists
                $stmt = $db->prepare("SELECT id, privacy FROM users WHERE id = ?");
                $stmt->execute([$receiver_id]);
                $receiver = $stmt->fetch();
                
                if (!$receiver) {
                    echo json_encode(['error' => 'Receiver not found']);
                    break;
                }
                
                // Check privacy settings
                if ($receiver['privacy'] === 1) {
                    // Check if contact request exists or if they're contacts
                    $stmt = $db->prepare("
                        SELECT * FROM contact_requests 
                        WHERE ((from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?))
                        AND status = 'accepted'
                    ");
                    $stmt->execute([$_SESSION['user_id'], $receiver_id, $receiver_id, $_SESSION['user_id']]);
                    $contact = $stmt->fetch();
                    
                    if (!$contact) {
                        echo json_encode(['error' => 'You need to be contacts to message this user']);
                        break;
                    }
                }
                
                // Encrypt message content
                $encrypted_content = encryptMessage($content);
                
                // Insert message
                $stmt = $db->prepare("
                    INSERT INTO messages (sender_id, receiver_id, content, message_type, file_name, file_size, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ");
                $stmt->execute([
                    $_SESSION['user_id'],
                    $receiver_id,
                    $encrypted_content,
                    $message_type,
                    $file_name,
                    $file_size,
                    time()
                ]);
                
                $message_id = $db->lastInsertId();
                
                // Create notification for receiver
                $stmt = $db->prepare("
                    INSERT INTO notifications (user_id, type, from_user_id, content, created_at)
                    VALUES (?, 'message', ?, ?, ?)
                ");
                $stmt->execute([
                    $receiver_id,
                    $_SESSION['user_id'],
                    'New message from ' . $_SESSION['username'],
                    time()
                ]);
                
                echo json_encode([
                    'success' => true,
                    'message_id' => $message_id,
                    'created_at' => time()
                ]);
                break;
                
            case 'get_messages':
                if (!isLoggedIn()) {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                $other_user_id = intval($_GET['user_id'] ?? 0);
                $limit = intval($_GET['limit'] ?? 50);
                $offset = intval($_GET['offset'] ?? 0);
                
                if ($other_user_id === 0) {
                    echo json_encode(['error' => 'Invalid user ID']);
                    break;
                }
                
                // Get messages between two users
                $stmt = $db->prepare("
                    SELECT m.*, u1.username as sender_username, u2.username as receiver_username
                    FROM messages m
                    JOIN users u1 ON m.sender_id = u1.id
                    JOIN users u2 ON m.receiver_id = u2.id
                    WHERE (m.sender_id = ? AND m.receiver_id = ?) 
                       OR (m.sender_id = ? AND m.receiver_id = ?)
                    ORDER BY m.created_at DESC
                    LIMIT ? OFFSET ?
                ");
                $stmt->execute([
                    $_SESSION['user_id'],
                    $other_user_id,
                    $other_user_id,
                    $_SESSION['user_id'],
                    $limit,
                    $offset
                ]);
                
                $messages = $stmt->fetchAll();
                
                // Decrypt messages
                foreach ($messages as &$message) {
                    $message['content'] = decryptMessage($message['content']);
                    $message['is_sent'] = ($message['sender_id'] == $_SESSION['user_id']);
                    $message['time_formatted'] = date('H:i', $message['created_at']);
                }
                
                // Mark messages as read
                $db->prepare("
                    UPDATE messages 
                    SET is_read = 1 
                    WHERE receiver_id = ? AND sender_id = ? AND is_read = 0
                ")->execute([$_SESSION['user_id'], $other_user_id]);
                
                echo json_encode([
                    'success' => true,
                    'messages' => array_reverse($messages) // Reverse to get chronological order
                ]);
                break;
                
            case 'search_users':
                if (!isLoggedIn()) {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                $query = sanitize($_GET['q'] ?? '');
                $limit = intval($_GET['limit'] ?? 20);
                
                if (strlen($query) < 2) {
                    echo json_encode(['success' => true, 'users' => []]);
                    break;
                }
                
                $search_query = "%$query%";
                $stmt = $db->prepare("
                    SELECT id, username, name, avatar, status, last_seen
                    FROM users 
                    WHERE (username LIKE ? OR name LIKE ?) 
                      AND id != ?
                    LIMIT ?
                ");
                $stmt->execute([$search_query, $search_query, $_SESSION['user_id'], $limit]);
                
                $users = $stmt->fetchAll();
                
                echo json_encode(['success' => true, 'users' => $users]);
                break;
                
            case 'get_contacts':
                if (!isLoggedIn()) {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                // Get contacts (mutual)
                $stmt = $db->prepare("
                    SELECT u.id, u.username, u.name, u.avatar, u.status, u.last_seen
                    FROM contacts c
                    JOIN users u ON (
                        (c.user1_id = u.id AND c.user2_id = ?) OR 
                        (c.user2_id = u.id AND c.user1_id = ?)
                    )
                    WHERE u.id != ?
                    ORDER BY u.name
                ");
                $stmt->execute([$_SESSION['user_id'], $_SESSION['user_id'], $_SESSION['user_id']]);
                
                $contacts = $stmt->fetchAll();
                
                echo json_encode(['success' => true, 'contacts' => $contacts]);
                break;
                
            /* === CONTACT REQUESTS === */
            case 'send_contact_request':
                if (!isLoggedIn() || $method !== 'POST') {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                $to_user_id = intval($input['user_id'] ?? 0);
                $message = sanitize($input['message'] ?? '');
                
                if ($to_user_id === 0) {
                    echo json_encode(['error' => 'Invalid user']);
                    break;
                }
                
                if ($to_user_id === $_SESSION['user_id']) {
                    echo json_encode(['error' => 'Cannot send request to yourself']);
                    break;
                }
                
                // Check if request already exists
                $stmt = $db->prepare("
                    SELECT * FROM contact_requests 
                    WHERE from_user = ? AND to_user = ? AND status = 'pending'
                ");
                $stmt->execute([$_SESSION['user_id'], $to_user_id]);
                
                if ($stmt->fetch()) {
                    echo json_encode(['error' => 'Request already sent']);
                    break;
                }
                
                // Create request
                $stmt = $db->prepare("
                    INSERT INTO contact_requests (from_user, to_user, message, created_at)
                    VALUES (?, ?, ?, ?)
                ");
                $stmt->execute([$_SESSION['user_id'], $to_user_id, $message, time()]);
                
                // Create notification
                $db->prepare("
                    INSERT INTO notifications (user_id, type, from_user_id, content, created_at)
                    VALUES (?, 'contact_request', ?, ?, ?)
                ")->execute([
                    $to_user_id,
                    $_SESSION['user_id'],
                    'New contact request from ' . $_SESSION['username'],
                    time()
                ]);
                
                echo json_encode(['success' => true, 'message' => 'Contact request sent']);
                break;
                
            case 'get_contact_requests':
                if (!isLoggedIn()) {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                // Get pending requests
                $stmt = $db->prepare("
                    SELECT cr.*, u.username, u.name, u.avatar
                    FROM contact_requests cr
                    JOIN users u ON cr.from_user = u.id
                    WHERE cr.to_user = ? AND cr.status = 'pending'
                    ORDER BY cr.created_at DESC
                ");
                $stmt->execute([$_SESSION['user_id']]);
                
                $requests = $stmt->fetchAll();
                
                echo json_encode(['success' => true, 'requests' => $requests]);
                break;
                
            case 'handle_contact_request':
                if (!isLoggedIn() || $method !== 'POST') {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                $request_id = intval($input['request_id'] ?? 0);
                $action = $input['action'] ?? ''; // 'accept' or 'reject'
                
                if ($request_id === 0 || !in_array($action, ['accept', 'reject'])) {
                    echo json_encode(['error' => 'Invalid request']);
                    break;
                }
                
                // Get request
                $stmt = $db->prepare("
                    SELECT * FROM contact_requests 
                    WHERE id = ? AND to_user = ? AND status = 'pending'
                ");
                $stmt->execute([$request_id, $_SESSION['user_id']]);
                $request = $stmt->fetch();
                
                if (!$request) {
                    echo json_encode(['error' => 'Request not found']);
                    break;
                }
                
                if ($action === 'accept') {
                    // Update request status
                    $db->prepare("UPDATE contact_requests SET status = 'accepted' WHERE id = ?")
                       ->execute([$request_id]);
                    
                    // Create mutual contact
                    $stmt = $db->prepare("
                        INSERT OR IGNORE INTO contacts (user1_id, user2_id, created_at)
                        VALUES (?, ?, ?)
                    ");
                    $stmt->execute([
                        min($request['from_user'], $request['to_user']),
                        max($request['from_user'], $request['to_user']),
                        time()
                    ]);
                    
                    // Create notification for sender
                    $db->prepare("
                        INSERT INTO notifications (user_id, type, from_user_id, content, created_at)
                        VALUES (?, 'contact_accepted', ?, ?, ?)
                    ")->execute([
                        $request['from_user'],
                        $_SESSION['user_id'],
                        'Your contact request was accepted by ' . $_SESSION['username'],
                        time()
                    ]);
                    
                    echo json_encode(['success' => true, 'message' => 'Contact request accepted']);
                } else {
                    // Reject request
                    $db->prepare("UPDATE contact_requests SET status = 'rejected' WHERE id = ?")
                       ->execute([$request_id]);
                    
                    echo json_encode(['success' => true, 'message' => 'Contact request rejected']);
                }
                break;
                
            /* === GROUPS === */
            case 'create_group':
                if (!isLoggedIn() || $method !== 'POST') {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                $name = sanitize($input['name'] ?? '');
                $description = sanitize($input['description'] ?? '');
                $member_ids = $input['members'] ?? [];
                
                if (empty($name)) {
                    echo json_encode(['error' => 'Group name is required']);
                    break;
                }
                
                // Create group
                $stmt = $db->prepare("
                    INSERT INTO groups (name, description, created_by, created_at)
                    VALUES (?, ?, ?, ?)
                ");
                $stmt->execute([$name, $description, $_SESSION['user_id'], time()]);
                
                $group_id = $db->lastInsertId();
                
                // Add creator as admin
                $db->prepare("
                    INSERT INTO group_members (group_id, user_id, role, joined_at)
                    VALUES (?, ?, 'admin', ?)
                ")->execute([$group_id, $_SESSION['user_id'], time()]);
                
                // Add members
                foreach ($member_ids as $member_id) {
                    $member_id = intval($member_id);
                    if ($member_id !== $_SESSION['user_id']) {
                        $db->prepare("
                            INSERT INTO group_members (group_id, user_id, role, joined_at)
                            VALUES (?, ?, 'member', ?)
                        ")->execute([$group_id, $member_id, time()]);
                        
                        // Create notification for member
                        $db->prepare("
                            INSERT INTO notifications (user_id, type, group_id, from_user_id, content, created_at)
                            VALUES (?, 'group_invite', ?, ?, ?, ?)
                        ")->execute([
                            $member_id,
                            $group_id,
                            $_SESSION['user_id'],
                            'You were added to group: ' . $name,
                            time()
                        ]);
                    }
                }
                
                echo json_encode([
                    'success' => true,
                    'group_id' => $group_id,
                    'message' => 'Group created successfully'
                ]);
                break;
                
            case 'get_groups':
                if (!isLoggedIn()) {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                $stmt = $db->prepare("
                    SELECT g.*, gm.role
                    FROM groups g
                    JOIN group_members gm ON g.id = gm.group_id
                    WHERE gm.user_id = ?
                    ORDER BY g.created_at DESC
                ");
                $stmt->execute([$_SESSION['user_id']]);
                
                $groups = $stmt->fetchAll();
                
                echo json_encode(['success' => true, 'groups' => $groups]);
                break;
                
            case 'get_group_messages':
                if (!isLoggedIn()) {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                $group_id = intval($_GET['group_id'] ?? 0);
                $limit = intval($_GET['limit'] ?? 50);
                
                if ($group_id === 0) {
                    echo json_encode(['error' => 'Invalid group']);
                    break;
                }
                
                // Check if user is member
                $stmt = $db->prepare("
                    SELECT * FROM group_members 
                    WHERE group_id = ? AND user_id = ?
                ");
                $stmt->execute([$group_id, $_SESSION['user_id']]);
                
                if (!$stmt->fetch()) {
                    echo json_encode(['error' => 'Not a member']);
                    break;
                }
                
                // Get messages
                $stmt = $db->prepare("
                    SELECT gm.*, u.username, u.avatar
                    FROM group_messages gm
                    JOIN users u ON gm.sender_id = u.id
                    WHERE gm.group_id = ?
                    ORDER BY gm.created_at DESC
                    LIMIT ?
                ");
                $stmt->execute([$group_id, $limit]);
                
                $messages = $stmt->fetchAll();
                
                // Decrypt messages
                foreach ($messages as &$message) {
                    $message['content'] = decryptMessage($message['content']);
                    $message['is_sent'] = ($message['sender_id'] == $_SESSION['user_id']);
                    $message['time_formatted'] = date('H:i', $message['created_at']);
                }
                
                echo json_encode([
                    'success' => true,
                    'messages' => array_reverse($messages)
                ]);
                break;
                
            case 'send_group_message':
                if (!isLoggedIn() || $method !== 'POST') {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                $group_id = intval($input['group_id'] ?? 0);
                $content = sanitize($input['content'] ?? '');
                $message_type = $input['message_type'] ?? 'text';
                
                if (empty($content) && $message_type === 'text') {
                    echo json_encode(['error' => 'Message cannot be empty']);
                    break;
                }
                
                if ($group_id === 0) {
                    echo json_encode(['error' => 'Invalid group']);
                    break;
                }
                
                // Check if user is member
                $stmt = $db->prepare("
                    SELECT * FROM group_members 
                    WHERE group_id = ? AND user_id = ?
                ");
                $stmt->execute([$group_id, $_SESSION['user_id']]);
                
                if (!$stmt->fetch()) {
                    echo json_encode(['error' => 'Not a member']);
                    break;
                }
                
                // Encrypt message
                $encrypted_content = encryptMessage($content);
                
                // Insert message
                $stmt = $db->prepare("
                    INSERT INTO group_messages (group_id, sender_id, content, message_type, created_at)
                    VALUES (?, ?, ?, ?, ?)
                ");
                $stmt->execute([
                    $group_id,
                    $_SESSION['user_id'],
                    $encrypted_content,
                    $message_type,
                    time()
                ]);
                
                $message_id = $db->lastInsertId();
                
                echo json_encode([
                    'success' => true,
                    'message_id' => $message_id
                ]);
                break;
                
            /* === FILE UPLOAD === */
            case 'upload_file':
                if (!isLoggedIn()) {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                if (!isset($_FILES['file'])) {
                    echo json_encode(['error' => 'No file uploaded']);
                    break;
                }
                
                $file = $_FILES['file'];
                
                // Validate file
                if ($file['error'] !== 0) {
                    echo json_encode(['error' => 'Upload error']);
                    break;
                }
                
                if ($file['size'] > MAX_FILE_SIZE) {
                    echo json_encode(['error' => 'File too large (max 15MB)']);
                    break;
                }
                
                // Allowed file types
                $allowed_types = [
                    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
                    'application/pdf', 'application/msword',
                    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                    'text/plain', 'application/zip', 'application/x-rar-compressed'
                ];
                
                if (!in_array($file['type'], $allowed_types)) {
                    echo json_encode(['error' => 'File type not allowed']);
                    break;
                }
                
                // Generate unique filename
                $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
                $filename = 'file_' . $_SESSION['user_id'] . '_' . time() . '_' . bin2hex(random_bytes(8)) . '.' . $extension;
                $filepath = 'uploads/files/' . $filename;
                
                if (move_uploaded_file($file['tmp_name'], $filepath)) {
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
                
            /* === NOTIFICATIONS === */
            case 'get_notifications':
                if (!isLoggedIn()) {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                $limit = intval($_GET['limit'] ?? 20);
                
                $stmt = $db->prepare("
                    SELECT n.*, u.username as from_username, g.name as group_name
                    FROM notifications n
                    LEFT JOIN users u ON n.from_user_id = u.id
                    LEFT JOIN groups g ON n.group_id = g.id
                    WHERE n.user_id = ?
                    ORDER BY n.created_at DESC
                    LIMIT ?
                ");
                $stmt->execute([$_SESSION['user_id'], $limit]);
                
                $notifications = $stmt->fetchAll();
                
                echo json_encode(['success' => true, 'notifications' => $notifications]);
                break;
                
            case 'mark_notification_read':
                if (!isLoggedIn() || $method !== 'POST') {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                $notification_id = intval($input['notification_id'] ?? 0);
                
                if ($notification_id > 0) {
                    $db->prepare("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?")
                       ->execute([$notification_id, $_SESSION['user_id']]);
                }
                
                echo json_encode(['success' => true]);
                break;
                
            /* === SETTINGS === */
            case 'update_settings':
                if (!isLoggedIn() || $method !== 'POST') {
                    echo json_encode(['error' => 'Not authenticated']);
                    break;
                }
                
                $theme = sanitize($input['theme'] ?? 'dark');
                $notifications = intval($input['notifications'] ?? 1);
                
                $db->prepare("UPDATE users SET theme = ?, notifications = ? WHERE id = ?")
                   ->execute([$theme, $notifications, $_SESSION['user_id']]);
                
                echo json_encode(['success' => true, 'message' => 'Settings updated']);
                break;
                
            default:
                echo json_encode(['error' => 'Invalid API endpoint']);
                break;
        }
    } catch (Exception $e) {
        error_log("API Error: " . $e->getMessage());
        echo json_encode(['error' => 'Server error: ' . $e->getMessage()]);
    }
    exit;
}

// If no API call, show the main page
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0, user-scalable=yes">
    <title>LinkA - Secure Messenger</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /* ===== CSS VARIABLES ===== */
        :root {
            --primary-color: #000000;
            --secondary-color: #ffffff;
            --accent-color: #007AFF;
            --danger-color: #FF3B30;
            --success-color: #34C759;
            --warning-color: #FF9500;
            --gray-100: #f5f5f5;
            --gray-200: #e5e5e5;
            --gray-300: #d4d4d4;
            --gray-400: #a3a3a3;
            --gray-500: #737373;
            --gray-600: #525252;
            --gray-700: #404040;
            --gray-800: #262626;
            --gray-900: #171717;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            --radius-sm: 0.25rem;
            --radius: 0.5rem;
            --radius-md: 0.75rem;
            --radius-lg: 1rem;
            --radius-full: 9999px;
        }

        /* ===== DARK THEME ===== */
        .theme-dark {
            --bg-primary: #000000;
            --bg-secondary: #171717;
            --bg-tertiary: #262626;
            --text-primary: #ffffff;
            --text-secondary: #a3a3a3;
            --text-tertiary: #737373;
            --border-color: #404040;
        }

        /* ===== LIGHT THEME ===== */
        .theme-light {
            --bg-primary: #ffffff;
            --bg-secondary: #f5f5f5;
            --bg-tertiary: #e5e5e5;
            --text-primary: #171717;
            --text-secondary: #525252;
            --text-tertiary: #a3a3a3;
            --border-color: #d4d4d4;
        }

        /* ===== BASE STYLES ===== */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            overflow-x: hidden;
            transition: background-color 0.3s, color 0.3s;
        }

        /* ===== TYPOGRAPHY ===== */
        h1, h2, h3, h4, h5, h6 {
            font-weight: 600;
            line-height: 1.2;
        }

        .text-sm { font-size: 0.875rem; }
        .text-base { font-size: 1rem; }
        .text-lg { font-size: 1.125rem; }
        .text-xl { font-size: 1.25rem; }
        .text-2xl { font-size: 1.5rem; }
        .text-3xl { font-size: 1.875rem; }

        .font-normal { font-weight: 400; }
        .font-medium { font-weight: 500; }
        .font-semibold { font-weight: 600; }
        .font-bold { font-weight: 700; }

        /* ===== LAYOUT ===== */
        .container {
            width: 100%;
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 1rem;
        }

        .flex { display: flex; }
        .flex-col { flex-direction: column; }
        .items-center { align-items: center; }
        .items-start { align-items: flex-start; }
        .items-end { align-items: flex-end; }
        .justify-center { justify-content: center; }
        .justify-between { justify-content: space-between; }
        .justify-end { justify-content: flex-end; }
        .gap-1 { gap: 0.25rem; }
        .gap-2 { gap: 0.5rem; }
        .gap-3 { gap: 0.75rem; }
        .gap-4 { gap: 1rem; }
        .gap-6 { gap: 1.5rem; }
        .gap-8 { gap: 2rem; }

        /* ===== SPACING ===== */
        .p-1 { padding: 0.25rem; }
        .p-2 { padding: 0.5rem; }
        .p-3 { padding: 0.75rem; }
        .p-4 { padding: 1rem; }
        .p-6 { padding: 1.5rem; }
        .p-8 { padding: 2rem; }

        .px-2 { padding-left: 0.5rem; padding-right: 0.5rem; }
        .px-3 { padding-left: 0.75rem; padding-right: 0.75rem; }
        .px-4 { padding-left: 1rem; padding-right: 1rem; }
        .py-2 { padding-top: 0.5rem; padding-bottom: 0.5rem; }
        .py-3 { padding-top: 0.75rem; padding-bottom: 0.75rem; }
        .py-4 { padding-top: 1rem; padding-bottom: 1rem; }

        .m-auto { margin: auto; }
        .mt-1 { margin-top: 0.25rem; }
        .mt-2 { margin-top: 0.5rem; }
        .mt-3 { margin-top: 0.75rem; }
        .mt-4 { margin-top: 1rem; }
        .mt-6 { margin-top: 1.5rem; }
        .mt-8 { margin-top: 2rem; }
        .mb-1 { margin-bottom: 0.25rem; }
        .mb-2 { margin-bottom: 0.5rem; }
        .mb-3 { margin-bottom: 0.75rem; }
        .mb-4 { margin-bottom: 1rem; }
        .mb-6 { margin-bottom: 1.5rem; }
        .mb-8 { margin-bottom: 2rem; }

        /* ===== UTILITY CLASSES ===== */
        .hidden { display: none !important; }
        .block { display: block; }
        .inline-block { display: inline-block; }
        .w-full { width: 100%; }
        .w-auto { width: auto; }
        .h-full { height: 100%; }
        .h-screen { height: 100vh; }
        .overflow-hidden { overflow: hidden; }
        .overflow-auto { overflow: auto; }
        .overflow-y-auto { overflow-y: auto; }
        .overflow-x-hidden { overflow-x: hidden; }
        .relative { position: relative; }
        .absolute { position: absolute; }
        .fixed { position: fixed; }
        .sticky { position: sticky; }
        .top-0 { top: 0; }
        .bottom-0 { bottom: 0; }
        .left-0 { left: 0; }
        .right-0 { right: 0; }
        .z-10 { z-index: 10; }
        .z-20 { z-index: 20; }
        .z-30 { z-index: 30; }
        .z-40 { z-index: 40; }
        .z-50 { z-index: 50; }

        /* ===== BUTTONS ===== */
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            padding: 0.625rem 1.25rem;
            border: none;
            border-radius: var(--radius);
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
            text-decoration: none;
            white-space: nowrap;
            user-select: none;
        }

        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .btn-primary {
            background: var(--accent-color);
            color: white;
        }

        .btn-primary:hover:not(:disabled) {
            background: #0056CC;
            transform: translateY(-1px);
        }

        .btn-secondary {
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }

        .btn-secondary:hover:not(:disabled) {
            background: var(--border-color);
        }

        .btn-danger {
            background: var(--danger-color);
            color: white;
        }

        .btn-danger:hover:not(:disabled) {
            background: #CC2A24;
        }

        .btn-success {
            background: var(--success-color);
            color: white;
        }

        .btn-outline {
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-primary);
        }

        .btn-outline:hover:not(:disabled) {
            background: var(--bg-tertiary);
        }

        .btn-sm {
            padding: 0.375rem 0.75rem;
            font-size: 0.75rem;
        }

        .btn-lg {
            padding: 0.75rem 1.5rem;
            font-size: 1rem;
        }

        .btn-icon {
            width: 2.5rem;
            height: 2.5rem;
            padding: 0;
            border-radius: 50%;
        }

        /* ===== FORMS ===== */
        .form-group {
            margin-bottom: 1rem;
        }

        .form-label {
            display: block;
            margin-bottom: 0.5rem;
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--text-primary);
        }

        .form-input {
            width: 100%;
            padding: 0.625rem 0.875rem;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            color: var(--text-primary);
            font-size: 0.875rem;
            transition: border-color 0.2s;
        }

        .form-input:focus {
            outline: none;
            border-color: var(--accent-color);
            box-shadow: 0 0 0 3px rgba(0, 122, 255, 0.1);
        }

        .form-input.error {
            border-color: var(--danger-color);
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
        }

        .form-checkbox input[type="checkbox"] {
            width: 1rem;
            height: 1rem;
            accent-color: var(--accent-color);
        }

        .form-radio-group {
            display: flex;
            gap: 1rem;
        }

        .form-radio {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            cursor: pointer;
        }

        /* ===== AVATARS ===== */
        .avatar {
            width: 2.5rem;
            height: 2.5rem;
            border-radius: 50%;
            object-fit: cover;
            background: var(--bg-tertiary);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-secondary);
            font-weight: 600;
        }

        .avatar-sm {
            width: 2rem;
            height: 2rem;
            font-size: 0.75rem;
        }

        .avatar-lg {
            width: 4rem;
            height: 4rem;
            font-size: 1.5rem;
        }

        .avatar-xl {
            width: 6rem;
            height: 6rem;
            font-size: 2rem;
        }

        /* ===== BADGES ===== */
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 0.125rem 0.5rem;
            border-radius: var(--radius-full);
            font-size: 0.75rem;
            font-weight: 500;
            white-space: nowrap;
        }

        .badge-primary {
            background: var(--accent-color);
            color: white;
        }

        .badge-success {
            background: var(--success-color);
            color: white;
        }

        .badge-danger {
            background: var(--danger-color);
            color: white;
        }

        .badge-warning {
            background: var(--warning-color);
            color: white;
        }

        .badge-secondary {
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }

        /* ===== CARDS ===== */
        .card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            padding: 1rem;
        }

        .card-header {
            padding-bottom: 0.75rem;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 1rem;
        }

        .card-body {
            padding: 0.75rem 0;
        }

        .card-footer {
            padding-top: 0.75rem;
            border-top: 1px solid var(--border-color);
            margin-top: 1rem;
        }

        /* ===== MODALS ===== */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.5);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 50;
            padding: 1rem;
        }

        .modal {
            background: var(--bg-primary);
            border-radius: var(--radius-lg);
            max-width: 100%;
            max-height: 90vh;
            overflow: hidden;
            box-shadow: var(--shadow-lg);
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
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .modal-body {
            padding: 1.5rem;
            overflow-y: auto;
            max-height: 70vh;
        }

        .modal-footer {
            padding: 1rem 1.5rem;
            border-top: 1px solid var(--border-color);
            display: flex;
            gap: 0.5rem;
            justify-content: flex-end;
        }

        /* ===== TOASTS ===== */
        .toast-container {
            position: fixed;
            bottom: 1rem;
            right: 1rem;
            z-index: 100;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .toast {
            padding: 0.75rem 1rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            box-shadow: var(--shadow-md);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            animation: toastSlideIn 0.3s ease;
            max-width: 24rem;
        }

        @keyframes toastSlideIn {
            from {
                opacity: 0;
                transform: translateX(100%);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        .toast-success {
            border-left: 4px solid var(--success-color);
        }

        .toast-error {
            border-left: 4px solid var(--danger-color);
        }

        .toast-warning {
            border-left: 4px solid var(--warning-color);
        }

        .toast-info {
            border-left: 4px solid var(--accent-color);
        }

        /* ===== MESSAGES ===== */
        .message {
            display: flex;
            gap: 0.75rem;
            padding: 0.5rem 1rem;
            margin: 0.25rem 0;
        }

        .message-sent {
            flex-direction: row-reverse;
        }

        .message-content {
            max-width: 70%;
            padding: 0.75rem 1rem;
            border-radius: var(--radius-lg);
            position: relative;
            word-wrap: break-word;
        }

        .message-received .message-content {
            background: var(--bg-tertiary);
            border-bottom-left-radius: var(--radius-sm);
        }

        .message-sent .message-content {
            background: var(--accent-color);
            color: white;
            border-bottom-right-radius: var(--radius-sm);
        }

        .message-time {
            font-size: 0.75rem;
            color: var(--text-tertiary);
            margin-top: 0.25rem;
            text-align: right;
        }

        .message-sent .message-time {
            color: rgba(255, 255, 255, 0.8);
        }

        /* ===== NAVIGATION ===== */
        .nav {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 0.75rem 1rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .nav-brand {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-weight: 600;
        }

        .nav-menu {
            display: flex;
            gap: 1rem;
        }

        .nav-item {
            padding: 0.5rem 0.75rem;
            border-radius: var(--radius);
            cursor: pointer;
            transition: background 0.2s;
        }

        .nav-item:hover {
            background: var(--bg-tertiary);
        }

        .nav-item.active {
            background: var(--accent-color);
            color: white;
        }

        /* ===== SIDEBAR ===== */
        .sidebar {
            width: 18rem;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            height: 100vh;
        }

        .sidebar-header {
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
        }

        .sidebar-body {
            flex: 1;
            overflow-y: auto;
            padding: 1rem;
        }

        .sidebar-footer {
            padding: 1rem;
            border-top: 1px solid var(--border-color);
        }

        .sidebar-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem;
            border-radius: var(--radius);
            cursor: pointer;
            transition: background 0.2s;
            margin-bottom: 0.25rem;
        }

        .sidebar-item:hover {
            background: var(--bg-tertiary);
        }

        .sidebar-item.active {
            background: var(--accent-color);
            color: white;
        }

        /* ===== MAIN CONTENT ===== */
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            height: 100vh;
        }

        .chat-header {
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .chat-body {
            flex: 1;
            overflow-y: auto;
            padding: 1rem;
        }

        .chat-footer {
            padding: 1rem;
            border-top: 1px solid var(--border-color);
        }

        .chat-input {
            width: 100%;
            padding: 0.75rem 1rem;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-full);
            color: var(--text-primary);
            font-size: 0.875rem;
            resize: none;
            max-height: 8rem;
        }

        .chat-input:focus {
            outline: none;
            border-color: var(--accent-color);
        }

        /* ===== LOADING STATES ===== */
        .loading {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }

        .loading-spinner {
            width: 2rem;
            height: 2rem;
            border: 2px solid var(--border-color);
            border-top-color: var(--accent-color);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* ===== RESPONSIVE DESIGN ===== */
        @media (max-width: 768px) {
            .sidebar {
                position: fixed;
                left: -100%;
                top: 0;
                z-index: 40;
                transition: left 0.3s;
                width: 80%;
                max-width: 20rem;
            }
            
            .sidebar.active {
                left: 0;
            }
            
            .mobile-menu-toggle {
                display: block;
            }
            
            .modal {
                width: 95%;
                margin: 0.5rem;
            }
            
            .message-content {
                max-width: 85%;
            }
        }

        @media (min-width: 769px) {
            .mobile-menu-toggle {
                display: none;
            }
        }

        /* ===== SCROLLBAR ===== */
        ::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }

        ::-webkit-scrollbar-track {
            background: transparent;
        }

        ::-webkit-scrollbar-thumb {
            background: var(--border-color);
            border-radius: var(--radius-full);
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--text-tertiary);
        }

        /* ===== ANIMATIONS ===== */
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes slideUp {
            from { transform: translateY(10px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        .fade-in {
            animation: fadeIn 0.3s ease;
        }

        .slide-up {
            animation: slideUp 0.3s ease;
        }

        /* ===== FILE UPLOAD ===== */
        .file-upload {
            border: 2px dashed var(--border-color);
            border-radius: var(--radius);
            padding: 2rem;
            text-align: center;
            cursor: pointer;
            transition: all 0.2s;
        }

        .file-upload:hover {
            border-color: var(--accent-color);
            background: var(--bg-tertiary);
        }

        .file-preview {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 1rem;
            background: var(--bg-tertiary);
            border-radius: var(--radius);
            margin-top: 1rem;
        }

        .file-icon {
            font-size: 2rem;
            color: var(--text-secondary);
        }

        /* ===== STATUS INDICATORS ===== */
        .status {
            width: 0.75rem;
            height: 0.75rem;
            border-radius: 50%;
            border: 2px solid var(--bg-secondary);
            position: absolute;
            bottom: 0;
            right: 0;
        }

        .status-online {
            background: var(--success-color);
        }

        .status-offline {
            background: var(--gray-400);
        }

        .status-away {
            background: var(--warning-color);
        }

        /* ===== EMPTY STATES ===== */
        .empty-state {
            text-align: center;
            padding: 3rem 1rem;
            color: var(--text-tertiary);
        }

        .empty-state-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }

        /* ===== TABS ===== */
        .tabs {
            display: flex;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 1rem;
        }

        .tab {
            padding: 0.75rem 1rem;
            border-bottom: 2px solid transparent;
            cursor: pointer;
            transition: all 0.2s;
        }

        .tab:hover {
            background: var(--bg-tertiary);
        }

        .tab.active {
            border-bottom-color: var(--accent-color);
            color: var(--accent-color);
        }

        /* ===== SEARCH ===== */
        .search-container {
            position: relative;
            margin-bottom: 1rem;
        }

        .search-input {
            width: 100%;
            padding: 0.625rem 2.5rem 0.625rem 0.875rem;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            color: var(--text-primary);
            font-size: 0.875rem;
        }

        .search-icon {
            position: absolute;
            right: 0.875rem;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-tertiary);
        }
    </style>
</head>
<body class="theme-dark">
    <!-- Toast Container -->
    <div class="toast-container" id="toastContainer"></div>

    <!-- Auth Screen -->
    <div id="authScreen" class="h-screen flex items-center justify-center p-4">
        <div class="w-full max-w-md">
            <div class="text-center mb-8">
                <div class="text-3xl mb-2">🔗 LinkA</div>
                <p class="text-gray-400">Secure messaging with end-to-end encryption</p>
            </div>

            <!-- Login Form -->
            <div id="loginForm" class="card">
                <h3 class="text-xl font-semibold mb-4">Login</h3>
                <form id="loginFormElement" class="space-y-4">
                    <div class="form-group">
                        <input type="text" id="loginUsername" class="form-input" placeholder="Username" required>
                    </div>
                    <div class="form-group">
                        <input type="password" id="loginPassword" class="form-input" placeholder="Password" required>
                    </div>
                    <div class="form-group">
                        <label class="form-checkbox">
                            <input type="checkbox" id="rememberMe">
                            <span>Remember me</span>
                        </label>
                    </div>
                    <button type="submit" class="btn btn-primary w-full">Login</button>
                </form>
                <p class="text-center mt-4 text-sm text-gray-400">
                    Don't have an account? 
                    <a href="#" id="showRegister" class="text-blue-400 hover:underline">Register</a>
                </p>
            </div>

            <!-- Register Form -->
            <div id="registerForm" class="card hidden">
                <h3 class="text-xl font-semibold mb-4">Create Account</h3>
                <form id="registerFormElement" class="space-y-4">
                    <div class="form-group">
                        <input type="text" id="registerUsername" class="form-input" placeholder="Username" required>
                    </div>
                    <div class="form-group">
                        <input type="password" id="registerPassword" class="form-input" placeholder="Password" required>
                    </div>
                    <div class="form-group">
                        <input type="password" id="registerConfirmPassword" class="form-input" placeholder="Confirm Password" required>
                    </div>
                    <div class="form-group">
                        <input type="text" id="registerName" class="form-input" placeholder="Full Name" required>
                    </div>
                    <div class="form-group">
                        <input type="email" id="registerEmail" class="form-input" placeholder="Email (optional)">
                    </div>
                    <button type="submit" class="btn btn-primary w-full">Create Account</button>
                </form>
                <p class="text-center mt-4 text-sm text-gray-400">
                    Already have an account? 
                    <a href="#" id="showLogin" class="text-blue-400 hover:underline">Login</a>
                </p>
            </div>
        </div>
    </div>

    <!-- Main App -->
    <div id="appScreen" class="hidden">
        <div class="flex h-screen">
            <!-- Sidebar -->
            <div class="sidebar">
                <div class="sidebar-header">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center gap-3">
                            <div class="avatar" id="userAvatarMain">U</div>
                            <div>
                                <div class="font-semibold" id="userNameMain">User</div>
                                <div class="text-sm text-gray-400" id="userStatusMain">Online</div>
                            </div>
                        </div>
                        <button class="btn btn-icon btn-secondary" id="mobileMenuClose">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                </div>

                <div class="tabs">
                    <div class="tab active" data-tab="chats">Chats</div>
                    <div class="tab" data-tab="contacts">Contacts</div>
                    <div class="tab" data-tab="groups">Groups</div>
                </div>

                <div class="sidebar-body">
                    <!-- Search -->
                    <div class="search-container mb-4">
                        <input type="text" class="search-input" id="searchInput" placeholder="Search...">
                        <i class="fas fa-search search-icon"></i>
                    </div>

                    <!-- Chats Tab -->
                    <div id="chatsTab" class="tab-content">
                        <div class="space-y-2" id="chatsList">
                            <!-- Chats will be loaded here -->
                        </div>
                    </div>

                    <!-- Contacts Tab -->
                    <div id="contactsTab" class="tab-content hidden">
                        <div class="mb-4">
                            <button class="btn btn-primary w-full" id="addContactBtn">
                                <i class="fas fa-user-plus"></i> Add Contact
                            </button>
                        </div>
                        <div class="space-y-2" id="contactsList">
                            <!-- Contacts will be loaded here -->
                        </div>
                    </div>

                    <!-- Groups Tab -->
                    <div id="groupsTab" class="tab-content hidden">
                        <div class="mb-4">
                            <button class="btn btn-primary w-full" id="createGroupBtn">
                                <i class="fas fa-users"></i> Create Group
                            </button>
                        </div>
                        <div class="space-y-2" id="groupsList">
                            <!-- Groups will be loaded here -->
                        </div>
                    </div>
                </div>

                <div class="sidebar-footer">
                    <div class="space-y-2">
                        <div class="sidebar-item" id="profileBtn">
                            <i class="fas fa-user"></i>
                            <span>Profile</span>
                        </div>
                        <div class="sidebar-item" id="settingsBtn">
                            <i class="fas fa-cog"></i>
                            <span>Settings</span>
                        </div>
                        <div class="sidebar-item" id="notificationsBtn">
                            <i class="fas fa-bell"></i>
                            <span>Notifications</span>
                            <span class="badge badge-danger ml-auto hidden" id="notificationBadge">0</span>
                        </div>
                        <div class="sidebar-item text-red-400" id="logoutBtn">
                            <i class="fas fa-sign-out-alt"></i>
                            <span>Logout</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Main Content -->
            <div class="main-content">
                <!-- Chat Header -->
                <div class="chat-header" id="chatHeader">
                    <div class="flex items-center gap-3">
                        <button class="btn btn-icon btn-secondary mobile-menu-toggle" id="mobileMenuToggle">
                            <i class="fas fa-bars"></i>
                        </button>
                        <div id="chatInfo">
                            <div class="text-lg font-semibold">Select a chat</div>
                            <div class="text-sm text-gray-400">Start a conversation</div>
                        </div>
                    </div>
                    <div class="flex items-center gap-2">
                        <button class="btn btn-icon btn-secondary" id="chatInfoBtn">
                            <i class="fas fa-info-circle"></i>
                        </button>
                    </div>
                </div>

                <!-- Chat Body -->
                <div class="chat-body" id="chatBody">
                    <div class="empty-state">
                        <div class="empty-state-icon">
                            <i class="fas fa-comments"></i>
                        </div>
                        <h3 class="text-lg font-semibold mb-2">No chat selected</h3>
                        <p class="text-gray-400">Select a chat from the sidebar or start a new conversation</p>
                    </div>
                </div>

                <!-- Chat Footer -->
                <div class="chat-footer hidden" id="chatFooter">
                    <form id="messageForm" class="flex gap-2">
                        <div class="flex-1">
                            <input type="text" id="messageInput" class="chat-input" placeholder="Type a message..." autocomplete="off">
                        </div>
                        <button type="button" class="btn btn-icon btn-secondary" id="attachBtn">
                            <i class="fas fa-paperclip"></i>
                        </button>
                        <button type="submit" class="btn btn-icon btn-primary">
                            <i class="fas fa-paper-plane"></i>
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- Modals -->
    <!-- Profile Modal -->
    <div id="profileModal" class="modal-overlay hidden">
        <div class="modal w-full max-w-2xl">
            <div class="modal-header">
                <h3 class="text-lg font-semibold">Profile</h3>
                <button class="btn btn-icon btn-secondary" data-close-modal>
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <div class="text-center mb-6">
                    <div class="avatar avatar-xl mx-auto mb-4" id="profileAvatar">U</div>
                    <button class="btn btn-secondary btn-sm" id="changeAvatarBtn">Change Avatar</button>
                </div>
                <form id="profileForm" class="space-y-4">
                    <div class="grid grid-cols-2 gap-4">
                        <div class="form-group">
                            <label class="form-label">Username</label>
                            <input type="text" id="profileUsername" class="form-input" readonly>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Name</label>
                            <input type="text" id="profileName" class="form-input" required>
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Email</label>
                        <input type="email" id="profileEmail" class="form-input">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Bio</label>
                        <textarea id="profileBio" class="form-input form-textarea" rows="3"></textarea>
                    </div>
                    <div class="form-group">
                        <label class="form-checkbox">
                            <input type="checkbox" id="profilePrivacy">
                            <span>Private account (Only contacts can message you)</span>
                        </label>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" data-close-modal>Cancel</button>
                <button class="btn btn-primary" id="saveProfileBtn">Save Changes</button>
            </div>
        </div>
    </div>

    <!-- Settings Modal -->
    <div id="settingsModal" class="modal-overlay hidden">
        <div class="modal w-full max-w-2xl">
            <div class="modal-header">
                <h3 class="text-lg font-semibold">Settings</h3>
                <button class="btn btn-icon btn-secondary" data-close-modal>
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <div class="tabs mb-4">
                    <div class="tab active" data-settings-tab="general">General</div>
                    <div class="tab" data-settings-tab="privacy">Privacy</div>
                    <div class="tab" data-settings-tab="notifications">Notifications</div>
                </div>

                <div id="generalSettings" class="settings-content">
                    <div class="form-group">
                        <label class="form-label">Theme</label>
                        <div class="form-radio-group">
                            <label class="form-radio">
                                <input type="radio" name="theme" value="light" checked>
                                <span>Light</span>
                            </label>
                            <label class="form-radio">
                                <input type="radio" name="theme" value="dark">
                                <span>Dark</span>
                            </label>
                        </div>
                    </div>
                </div>

                <div id="privacySettings" class="settings-content hidden">
                    <div class="form-group">
                        <label class="form-label">Who can message you</label>
                        <select id="privacySetting" class="form-input">
                            <option value="0">Everyone</option>
                            <option value="1">Contacts only</option>
                        </select>
                    </div>
                </div>

                <div id="notificationSettings" class="settings-content hidden">
                    <div class="form-group">
                        <label class="form-checkbox">
                            <input type="checkbox" id="enableNotifications" checked>
                            <span>Enable notifications</span>
                        </label>
                    </div>
                    <button class="btn btn-secondary" id="requestNotificationBtn">
                        Request Notification Permission
                    </button>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" data-close-modal>Close</button>
                <button class="btn btn-primary" id="saveSettingsBtn">Save Settings</button>
            </div>
        </div>
    </div>

    <!-- Add Contact Modal -->
    <div id="addContactModal" class="modal-overlay hidden">
        <div class="modal w-full max-w-md">
            <div class="modal-header">
                <h3 class="text-lg font-semibold">Add Contact</h3>
                <button class="btn btn-icon btn-secondary" data-close-modal>
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <div class="search-container mb-4">
                    <input type="text" class="search-input" id="contactSearch" placeholder="Search users...">
                    <i class="fas fa-search search-icon"></i>
                </div>
                <div id="searchResults" class="space-y-2 max-h-64 overflow-y-auto">
                    <!-- Search results will appear here -->
                </div>
            </div>
        </div>
    </div>

    <!-- Create Group Modal -->
    <div id="createGroupModal" class="modal-overlay hidden">
        <div class="modal w-full max-w-md">
            <div class="modal-header">
                <h3 class="text-lg font-semibold">Create Group</h3>
                <button class="btn btn-icon btn-secondary" data-close-modal>
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <form id="createGroupForm" class="space-y-4">
                    <div class="form-group">
                        <label class="form-label">Group Name</label>
                        <input type="text" id="groupName" class="form-input" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Description</label>
                        <textarea id="groupDescription" class="form-input form-textarea" rows="2"></textarea>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Add Members</label>
                        <div class="search-container mb-2">
                            <input type="text" class="search-input" id="groupMemberSearch" placeholder="Search contacts...">
                            <i class="fas fa-search search-icon"></i>
                        </div>
                        <div id="selectedMembers" class="flex flex-wrap gap-2 mb-4">
                            <!-- Selected members will appear here -->
                        </div>
                        <div id="contactSearchResults" class="space-y-2 max-h-48 overflow-y-auto">
                            <!-- Search results will appear here -->
                        </div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" data-close-modal>Cancel</button>
                <button class="btn btn-primary" id="createGroupSubmitBtn">Create Group</button>
            </div>
        </div>
    </div>

    <!-- Notifications Modal -->
    <div id="notificationsModal" class="modal-overlay hidden">
        <div class="modal w-full max-w-md">
            <div class="modal-header">
                <h3 class="text-lg font-semibold">Notifications</h3>
                <button class="btn btn-icon btn-secondary" data-close-modal>
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <div id="notificationsList" class="space-y-2">
                    <!-- Notifications will appear here -->
                </div>
            </div>
        </div>
    </div>

    <!-- File Upload Modal -->
    <div id="fileUploadModal" class="modal-overlay hidden">
        <div class="modal w-full max-w-md">
            <div class="modal-header">
                <h3 class="text-lg font-semibold">Upload File</h3>
                <button class="btn btn-icon btn-secondary" data-close-modal>
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <div class="file-upload" id="fileDropZone">
                    <i class="fas fa-cloud-upload-alt text-3xl mb-4"></i>
                    <p class="font-medium mb-2">Click to upload or drag and drop</p>
                    <p class="text-sm text-gray-400">Max file size: 15MB</p>
                    <p class="text-xs text-gray-400 mt-2">
                        Supported: Images, PDF, Word, Text, ZIP files
                    </p>
                </div>
                <input type="file" id="fileInput" class="hidden" multiple>
                <div id="filePreview" class="hidden mt-4">
                    <!-- File preview will appear here -->
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" data-close-modal>Cancel</button>
                <button class="btn btn-primary" id="sendFileBtn" disabled>Send</button>
            </div>
        </div>
    </div>

    <!-- Chat Info Modal -->
    <div id="chatInfoModal" class="modal-overlay hidden">
        <div class="modal w-full max-w-md">
            <div class="modal-header">
                <h3 class="text-lg font-semibold" id="chatInfoTitle">Chat Info</h3>
                <button class="btn btn-icon btn-secondary" data-close-modal>
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <div id="chatInfoContent">
                    <!-- Chat info will appear here -->
                </div>
            </div>
        </div>
    </div>

    <script>
        // Global state
        const state = {
            currentUser: null,
            currentChat: null,
            currentChatType: null, // 'user' or 'group'
            notifications: [],
            contacts: [],
            groups: [],
            messages: {},
            selectedFiles: [],
            notificationPermission: Notification.permission,
            autoRefreshInterval: null,
            messagePollingInterval: null
        };

        // DOM Elements
        const elements = {
            // Auth screen
            authScreen: document.getElementById('authScreen'),
            appScreen: document.getElementById('appScreen'),
            loginForm: document.getElementById('loginForm'),
            registerForm: document.getElementById('registerForm'),
            loginFormElement: document.getElementById('loginFormElement'),
            registerFormElement: document.getElementById('registerFormElement'),
            showRegister: document.getElementById('showRegister'),
            showLogin: document.getElementById('showLogin'),
            
            // Main app
            userAvatarMain: document.getElementById('userAvatarMain'),
            userNameMain: document.getElementById('userNameMain'),
            userStatusMain: document.getElementById('userStatusMain'),
            mobileMenuToggle: document.getElementById('mobileMenuToggle'),
            mobileMenuClose: document.getElementById('mobileMenuClose'),
            sidebar: document.querySelector('.sidebar'),
            
            // Tabs
            tabs: document.querySelectorAll('.tab'),
            chatsTab: document.getElementById('chatsTab'),
            contactsTab: document.getElementById('contactsTab'),
            groupsTab: document.getElementById('groupsTab'),
            
            // Lists
            chatsList: document.getElementById('chatsList'),
            contactsList: document.getElementById('contactsList'),
            groupsList: document.getElementById('groupsList'),
            
            // Chat area
            chatHeader: document.getElementById('chatHeader'),
            chatInfo: document.getElementById('chatInfo'),
            chatBody: document.getElementById('chatBody'),
            chatFooter: document.getElementById('chatFooter'),
            messageForm: document.getElementById('messageForm'),
            messageInput: document.getElementById('messageInput'),
            
            // Buttons
            profileBtn: document.getElementById('profileBtn'),
            settingsBtn: document.getElementById('settingsBtn'),
            notificationsBtn: document.getElementById('notificationsBtn'),
            logoutBtn: document.getElementById('logoutBtn'),
            addContactBtn: document.getElementById('addContactBtn'),
            createGroupBtn: document.getElementById('createGroupBtn'),
            attachBtn: document.getElementById('attachBtn'),
            chatInfoBtn: document.getElementById('chatInfoBtn'),
            
            // Modals
            modals: document.querySelectorAll('.modal-overlay'),
            
            // Notification badge
            notificationBadge: document.getElementById('notificationBadge'),
            
            // Toast container
            toastContainer: document.getElementById('toastContainer')
        };

        // ===== UTILITY FUNCTIONS =====
        function showToast(message, type = 'info', duration = 5000) {
            const toast = document.createElement('div');
            toast.className = `toast toast-${type}`;
            toast.innerHTML = `
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : type === 'warning' ? 'exclamation-triangle' : 'info-circle'}"></i>
                <span>${message}</span>
            `;
            
            elements.toastContainer.appendChild(toast);
            
            setTimeout(() => {
                toast.style.animation = 'toastSlideIn 0.3s ease reverse';
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }

        function formatTime(timestamp) {
            const date = new Date(timestamp * 1000);
            const now = new Date();
            const diff = now - date;
            
            if (diff < 24 * 60 * 60 * 1000) {
                return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            } else if (diff < 7 * 24 * 60 * 60 * 1000) {
                return date.toLocaleDateString([], { weekday: 'short' });
            } else {
                return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
            }
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function debounce(func, wait) {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
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
                    if (data instanceof FormData) {
                        options.body = data;
                        delete options.headers['Content-Type'];
                    } else {
                        options.body = JSON.stringify(data);
                    }
                }
                
                const response = await fetch(url, options);
                const result = await response.json();
                
                if (result.error) {
                    throw new Error(result.error);
                }
                
                return result;
            } catch (error) {
                console.error('API Error:', error);
                showToast(error.message || 'API request failed', 'error');
                throw error;
            }
        }

        // ===== AUTHENTICATION =====
        async function checkAuth() {
            try {
                const result = await apiCall('check_auth');
                if (result.authenticated) {
                    state.currentUser = result.user;
                    initApp();
                } else {
                    showAuthScreen();
                }
            } catch (error) {
                showAuthScreen();
            }
        }

        async function login(username, password, rememberMe = false) {
            try {
                const result = await apiCall('login', 'POST', { username, password });
                
                if (result.success) {
                    state.currentUser = result.user;
                    
                    if (rememberMe) {
                        localStorage.setItem('rememberMe', 'true');
                        localStorage.setItem('username', username);
                    } else {
                        localStorage.removeItem('rememberMe');
                        localStorage.removeItem('username');
                    }
                    
                    initApp();
                    showToast('Login successful', 'success');
                }
            } catch (error) {
                // Error handled in apiCall
            }
        }

        async function register(username, password, confirmPassword, name, email) {
            try {
                const result = await apiCall('register', 'POST', {
                    username,
                    password,
                    confirm_password: confirmPassword,
                    name,
                    email
                });
                
                if (result.success) {
                    state.currentUser = result.user;
                    initApp();
                    showToast('Registration successful', 'success');
                }
            } catch (error) {
                // Error handled in apiCall
            }
        }

        async function logout() {
            try {
                await apiCall('logout');
                state.currentUser = null;
                clearInterval(state.autoRefreshInterval);
                clearInterval(state.messagePollingInterval);
                showAuthScreen();
                showToast('Logged out successfully', 'success');
            } catch (error) {
                // Error handled in apiCall
            }
        }

        // ===== APP INITIALIZATION =====
        function initApp() {
            elements.authScreen.classList.add('hidden');
            elements.appScreen.classList.remove('hidden');
            
            // Update user info
            if (state.currentUser) {
                elements.userNameMain.textContent = state.currentUser.name;
                updateUserAvatar(state.currentUser.avatar, state.currentUser.name);
            }
            
            // Load initial data
            loadContacts();
            loadGroups();
            loadNotifications();
            updateUnreadCount();
            
            // Setup auto-refresh
            state.autoRefreshInterval = setInterval(() => {
                loadContacts();
                loadGroups();
                loadNotifications();
            }, 30000); // Every 30 seconds
            
            // Request notification permission
            if (state.notificationPermission === 'default') {
                setTimeout(() => {
                    showToast('Enable notifications to get alerts for new messages', 'info', 10000);
                }, 3000);
            }
            
            // Setup event listeners
            setupEventListeners();
        }

        function showAuthScreen() {
            elements.appScreen.classList.add('hidden');
            elements.authScreen.classList.remove('hidden');
            
            // Check for remembered user
            if (localStorage.getItem('rememberMe') === 'true') {
                const username = localStorage.getItem('username');
                if (username) {
                    document.getElementById('loginUsername').value = username;
                }
            }
        }

        // ===== DATA LOADING =====
        async function loadContacts() {
            try {
                const result = await apiCall('get_contacts');
                if (result.success) {
                    state.contacts = result.contacts;
                    renderContacts();
                }
            } catch (error) {
                console.error('Failed to load contacts:', error);
            }
        }

        async function loadGroups() {
            try {
                const result = await apiCall('get_groups');
                if (result.success) {
                    state.groups = result.groups;
                    renderGroups();
                }
            } catch (error) {
                console.error('Failed to load groups:', error);
            }
        }

        async function loadNotifications() {
            try {
                const result = await apiCall('get_notifications');
                if (result.success) {
                    state.notifications = result.notifications;
                    updateUnreadCount();
                    
                    // Show browser notifications for new unread notifications
                    if (state.notificationPermission === 'granted') {
                        const newNotifications = result.notifications.filter(n => !n.is_read);
                        newNotifications.forEach(notification => {
                            showBrowserNotification(notification);
                        });
                    }
                }
            } catch (error) {
                console.error('Failed to load notifications:', error);
            }
        }

        async function loadMessages(userId = null, groupId = null) {
            if (!userId && !groupId) return;
            
            try {
                let endpoint, params;
                
                if (userId) {
                    endpoint = 'get_messages';
                    params = { user_id: userId };
                    state.currentChat = userId;
                    state.currentChatType = 'user';
                } else if (groupId) {
                    endpoint = 'get_group_messages';
                    params = { group_id: groupId };
                    state.currentChat = groupId;
                    state.currentChatType = 'group';
                }
                
                const result = await apiCall(endpoint, 'GET', params);
                if (result.success) {
                    const chatId = userId || groupId;
                    state.messages[chatId] = result.messages;
                    renderMessages(chatId);
                    
                    // Start polling for new messages
                    if (state.messagePollingInterval) {
                        clearInterval(state.messagePollingInterval);
                    }
                    
                    state.messagePollingInterval = setInterval(() => {
                        pollNewMessages();
                    }, 5000); // Poll every 5 seconds
                }
            } catch (error) {
                console.error('Failed to load messages:', error);
            }
        }

        async function pollNewMessages() {
            if (!state.currentChat) return;
            
            try {
                let endpoint, params;
                
                if (state.currentChatType === 'user') {
                    endpoint = 'get_messages';
                    params = { user_id: state.currentChat };
                } else {
                    endpoint = 'get_group_messages';
                    params = { group_id: state.currentChat };
                }
                
                const result = await apiCall(endpoint, 'GET', params);
                if (result.success && result.messages.length > state.messages[state.currentChat]?.length) {
                    state.messages[state.currentChat] = result.messages;
                    renderMessages(state.currentChat);
                    scrollToBottom();
                }
            } catch (error) {
                console.error('Failed to poll messages:', error);
            }
        }

        // ===== RENDERING =====
        function renderContacts() {
            elements.contactsList.innerHTML = '';
            
            if (state.contacts.length === 0) {
                elements.contactsList.innerHTML = `
                    <div class="empty-state py-8">
                        <p class="text-gray-400">No contacts yet</p>
                        <button class="btn btn-primary btn-sm mt-2" id="addContactFromEmpty">
                            Add Contact
                        </button>
                    </div>
                `;
                return;
            }
            
            state.contacts.forEach(contact => {
                const contactElement = document.createElement('div');
                contactElement.className = 'sidebar-item';
                contactElement.innerHTML = `
                    <div class="relative">
                        <div class="avatar avatar-sm">${contact.name.charAt(0)}</div>
                        <div class="status ${contact.status === 'online' ? 'status-online' : 'status-offline'}"></div>
                    </div>
                    <div class="flex-1">
                        <div class="font-medium">${contact.name}</div>
                        <div class="text-sm text-gray-400">@${contact.username}</div>
                    </div>
                `;
                
                contactElement.addEventListener('click', () => {
                    openChat(contact.id, 'user', contact.name);
                });
                
                elements.contactsList.appendChild(contactElement);
            });
        }

        function renderGroups() {
            elements.groupsList.innerHTML = '';
            
            if (state.groups.length === 0) {
                elements.groupsList.innerHTML = `
                    <div class="empty-state py-8">
                        <p class="text-gray-400">No groups yet</p>
                        <button class="btn btn-primary btn-sm mt-2" id="createGroupFromEmpty">
                            Create Group
                        </button>
                    </div>
                `;
                return;
            }
            
            state.groups.forEach(group => {
                const groupElement = document.createElement('div');
                groupElement.className = 'sidebar-item';
                groupElement.innerHTML = `
                    <div class="avatar avatar-sm">
                        <i class="fas fa-users"></i>
                    </div>
                    <div class="flex-1">
                        <div class="font-medium">${group.name}</div>
                        <div class="text-sm text-gray-400">${group.member_count || 1} members</div>
                    </div>
                `;
                
                groupElement.addEventListener('click', () => {
                    openChat(group.id, 'group', group.name);
                });
                
                elements.groupsList.appendChild(groupElement);
            });
        }

        function renderMessages(chatId) {
            const messages = state.messages[chatId] || [];
            elements.chatBody.innerHTML = '';
            
            if (messages.length === 0) {
                elements.chatBody.innerHTML = `
                    <div class="empty-state py-8">
                        <p class="text-gray-400">No messages yet</p>
                        <p class="text-sm text-gray-400">Start the conversation!</p>
                    </div>
                `;
                return;
            }
            
            messages.forEach(message => {
                const messageElement = document.createElement('div');
                messageElement.className = `message ${message.is_sent ? 'message-sent' : 'message-received'}`;
                
                let content = message.content;
                if (message.message_type === 'file') {
                    content = `
                        <div class="file-preview">
                            <i class="fas fa-file file-icon"></i>
                            <div class="flex-1">
                                <div class="font-medium">${message.file_name}</div>
                                <div class="text-sm text-gray-400">${formatFileSize(message.file_size)}</div>
                            </div>
                            <a href="uploads/files/${message.file_path}" class="btn btn-sm btn-secondary" download>
                                <i class="fas fa-download"></i>
                            </a>
                        </div>
                    `;
                }
                
                messageElement.innerHTML = `
                    <div class="avatar avatar-sm">${message.sender_name?.charAt(0) || 'U'}</div>
                    <div class="message-content">
                        ${content}
                        <div class="message-time">${formatTime(message.created_at)}</div>
                    </div>
                `;
                
                elements.chatBody.appendChild(messageElement);
            });
            
            scrollToBottom();
        }

        function updateUserAvatar(avatar, name) {
            if (avatar && avatar !== 'default') {
                elements.userAvatarMain.style.backgroundImage = `url('uploads/avatars/${avatar}')`;
                elements.userAvatarMain.style.backgroundSize = 'cover';
                elements.userAvatarMain.textContent = '';
            } else {
                elements.userAvatarMain.style.backgroundImage = '';
                elements.userAvatarMain.textContent = name.charAt(0);
            }
        }

        function updateUnreadCount() {
            const unreadCount = state.notifications.filter(n => !n.is_read).length;
            if (unreadCount > 0) {
                elements.notificationBadge.textContent = unreadCount;
                elements.notificationBadge.classList.remove('hidden');
            } else {
                elements.notificationBadge.classList.add('hidden');
            }
        }

        // ===== CHAT FUNCTIONS =====
        function openChat(chatId, type, name) {
            state.currentChat = chatId;
            state.currentChatType = type;
            
            // Update chat header
            elements.chatInfo.innerHTML = `
                <div class="text-lg font-semibold">${name}</div>
                <div class="text-sm text-gray-400">${type === 'user' ? 'Online' : 'Group chat'}</div>
            `;
            
            // Show chat footer
            elements.chatFooter.classList.remove('hidden');
            
            // Load messages
            if (type === 'user') {
                loadMessages(chatId, null);
            } else {
                loadMessages(null, chatId);
            }
            
            // Close mobile menu if open
            if (window.innerWidth <= 768) {
                elements.sidebar.classList.remove('active');
            }
        }

        async function sendMessage(content, type = 'text', fileData = null) {
            if (!state.currentChat || (!content && type === 'text')) return;
            
            try {
                let result;
                
                if (state.currentChatType === 'user') {
                    result = await apiCall('send_message', 'POST', {
                        receiver_id: state.currentChat,
                        content: content,
                        message_type: type,
                        file_name: fileData?.name,
                        file_size: fileData?.size
                    });
                } else {
                    result = await apiCall('send_group_message', 'POST', {
                        group_id: state.currentChat,
                        content: content,
                        message_type: type
                    });
                }
                
                if (result.success) {
                    // Clear input
                    elements.messageInput.value = '';
                    
                    // Add message to local state
                    const newMessage = {
                        id: result.message_id,
                        content: content,
                        message_type: type,
                        is_sent: true,
                        created_at: result.created_at || Math.floor(Date.now() / 1000),
                        sender_name: state.currentUser?.name
                    };
                    
                    if (!state.messages[state.currentChat]) {
                        state.messages[state.currentChat] = [];
                    }
                    
                    state.messages[state.currentChat].push(newMessage);
                    renderMessages(state.currentChat);
                    scrollToBottom();
                    
                    showToast('Message sent', 'success');
                }
            } catch (error) {
                console.error('Failed to send message:', error);
            }
        }

        function scrollToBottom() {
            const chatBody = elements.chatBody;
            chatBody.scrollTop = chatBody.scrollHeight;
        }

        // ===== FILE HANDLING =====
        function handleFileUpload(files) {
            state.selectedFiles = Array.from(files);
            
            // Validate files
            const validFiles = state.selectedFiles.filter(file => {
                if (file.size > 15 * 1024 * 1024) {
                    showToast(`File ${file.name} is too large (max 15MB)`, 'error');
                    return false;
                }
                
                const allowedTypes = [
                    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
                    'application/pdf', 'application/msword',
                    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                    'text/plain', 'application/zip', 'application/x-rar-compressed'
                ];
                
                if (!allowedTypes.includes(file.type)) {
                    showToast(`File type ${file.type} not supported`, 'error');
                    return false;
                }
                
                return true;
            });
            
            state.selectedFiles = validFiles;
            
            if (state.selectedFiles.length > 0) {
                showFilePreview();
            }
        }

        function showFilePreview() {
            const preview = document.getElementById('filePreview');
            preview.innerHTML = '';
            preview.classList.remove('hidden');
            
            state.selectedFiles.forEach((file, index) => {
                const fileElement = document.createElement('div');
                fileElement.className = 'file-preview';
                fileElement.innerHTML = `
                    <i class="fas fa-file file-icon"></i>
                    <div class="flex-1">
                        <div class="font-medium">${file.name}</div>
                        <div class="text-sm text-gray-400">${formatFileSize(file.size)}</div>
                    </div>
                    <button class="btn btn-icon btn-danger btn-sm" data-remove-file="${index}">
                        <i class="fas fa-times"></i>
                    </button>
                `;
                preview.appendChild(fileElement);
            });
            
            document.getElementById('sendFileBtn').disabled = false;
        }

        async function uploadAndSendFiles() {
            if (state.selectedFiles.length === 0) return;
            
            for (const file of state.selectedFiles) {
                const formData = new FormData();
                formData.append('file', file);
                
                try {
                    const result = await apiCall('upload_file', 'POST', formData);
                    
                    if (result.success) {
                        await sendMessage(file.name, 'file', {
                            name: file.name,
                            size: file.size
                        });
                    }
                } catch (error) {
                    console.error('Failed to upload file:', error);
                }
            }
            
            // Clear files
            state.selectedFiles = [];
            document.getElementById('filePreview').innerHTML = '';
            document.getElementById('filePreview').classList.add('hidden');
            document.getElementById('sendFileBtn').disabled = true;
            
            // Close modal
            closeModal('fileUploadModal');
        }

        // ===== NOTIFICATIONS =====
        function showBrowserNotification(notification) {
            if (!('Notification' in window) || Notification.permission !== 'granted') {
                return;
            }
            
            const options = {
                body: notification.content,
                icon: '/favicon.ico',
                tag: notification.id
            };
            
            const notify = new Notification('LinkA', options);
            
            notify.onclick = function() {
                window.focus();
                this.close();
                
                // Mark as read
                apiCall('mark_notification_read', 'POST', {
                    notification_id: notification.id
                });
            };
        }

        async function requestNotificationPermission() {
            if (!('Notification' in window)) {
                showToast('Notifications not supported in this browser', 'error');
                return;
            }
            
            if (Notification.permission === 'granted') {
                state.notificationPermission = 'granted';
                showToast('Notifications already enabled', 'success');
                return;
            }
            
            const permission = await Notification.requestPermission();
            state.notificationPermission = permission;
            
            if (permission === 'granted') {
                showToast('Notifications enabled', 'success');
                
                // Show test notification
                if (Notification.permission === 'granted') {
                    new Notification('LinkA', {
                        body: 'Notifications are now enabled!',
                        icon: '/favicon.ico'
                    });
                }
            }
        }

        // ===== MODAL FUNCTIONS =====
        function openModal(modalId) {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.classList.remove('hidden');
                document.body.style.overflow = 'hidden';
            }
        }

        function closeModal(modalId) {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.classList.add('hidden');
                document.body.style.overflow = '';
            }
        }

        function closeAllModals() {
            elements.modals.forEach(modal => {
                modal.classList.add('hidden');
            });
            document.body.style.overflow = '';
        }

        // ===== EVENT LISTENERS =====
        function setupEventListeners() {
            // Auth forms
            elements.loginFormElement.addEventListener('submit', async (e) => {
                e.preventDefault();
                const username = document.getElementById('loginUsername').value;
                const password = document.getElementById('loginPassword').value;
                const rememberMe = document.getElementById('rememberMe').checked;
                await login(username, password, rememberMe);
            });
            
            elements.registerFormElement.addEventListener('submit', async (e) => {
                e.preventDefault();
                const username = document.getElementById('registerUsername').value;
                const password = document.getElementById('registerPassword').value;
                const confirmPassword = document.getElementById('registerConfirmPassword').value;
                const name = document.getElementById('registerName').value;
                const email = document.getElementById('registerEmail').value;
                
                if (password !== confirmPassword) {
                    showToast('Passwords do not match', 'error');
                    return;
                }
                
                if (password.length < 6) {
                    showToast('Password must be at least 6 characters', 'error');
                    return;
                }
                
                await register(username, password, confirmPassword, name, email);
            });
            
            // Toggle between login/register
            elements.showRegister.addEventListener('click', (e) => {
                e.preventDefault();
                elements.loginForm.classList.add('hidden');
                elements.registerForm.classList.remove('hidden');
            });
            
            elements.showLogin.addEventListener('click', (e) => {
                e.preventDefault();
                elements.registerForm.classList.add('hidden');
                elements.loginForm.classList.remove('hidden');
            });
            
            // Mobile menu
            elements.mobileMenuToggle.addEventListener('click', () => {
                elements.sidebar.classList.add('active');
            });
            
            elements.mobileMenuClose.addEventListener('click', () => {
                elements.sidebar.classList.remove('active');
            });
            
            // Tabs
            elements.tabs.forEach(tab => {
                tab.addEventListener('click', () => {
                    const tabName = tab.dataset.tab;
                    
                    // Update active tab
                    elements.tabs.forEach(t => t.classList.remove('active'));
                    tab.classList.add('active');
                    
                    // Show corresponding content
                    document.querySelectorAll('.tab-content').forEach(content => {
                        content.classList.add('hidden');
                    });
                    
                    document.getElementById(`${tabName}Tab`).classList.remove('hidden');
                });
            });
            
            // Message form
            elements.messageForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const content = elements.messageInput.value.trim();
                if (content) {
                    await sendMessage(content);
                }
            });
            
            // Attach button
            elements.attachBtn.addEventListener('click', () => {
                openModal('fileUploadModal');
            });
            
            // File upload
            const fileDropZone = document.getElementById('fileDropZone');
            const fileInput = document.getElementById('fileInput');
            
            fileDropZone.addEventListener('click', () => {
                fileInput.click();
            });
            
            fileDropZone.addEventListener('dragover', (e) => {
                e.preventDefault();
                fileDropZone.style.borderColor = 'var(--accent-color)';
                fileDropZone.style.background = 'var(--bg-tertiary)';
            });
            
            fileDropZone.addEventListener('dragleave', () => {
                fileDropZone.style.borderColor = '';
                fileDropZone.style.background = '';
            });
            
            fileDropZone.addEventListener('drop', (e) => {
                e.preventDefault();
                fileDropZone.style.borderColor = '';
                fileDropZone.style.background = '';
                
                if (e.dataTransfer.files.length > 0) {
                    handleFileUpload(e.dataTransfer.files);
                }
            });
            
            fileInput.addEventListener('change', (e) => {
                if (e.target.files.length > 0) {
                    handleFileUpload(e.target.files);
                }
            });
            
            // Send file button
            document.getElementById('sendFileBtn').addEventListener('click', uploadAndSendFiles);
            
            // Remove file buttons
            document.addEventListener('click', (e) => {
                if (e.target.closest('[data-remove-file]')) {
                    const index = e.target.closest('[data-remove-file]').dataset.removeFile;
                    state.selectedFiles.splice(index, 1);
                    showFilePreview();
                }
            });
            
            // Navigation buttons
            elements.profileBtn.addEventListener('click', () => {
                openModal('profileModal');
                loadProfile();
            });
            
            elements.settingsBtn.addEventListener('click', () => {
                openModal('settingsModal');
            });
            
            elements.notificationsBtn.addEventListener('click', () => {
                openModal('notificationsModal');
                renderNotifications();
            });
            
            elements.logoutBtn.addEventListener('click', logout);
            
            elements.addContactBtn.addEventListener('click', () => {
                openModal('addContactModal');
            });
            
            elements.createGroupBtn.addEventListener('click', () => {
                openModal('createGroupModal');
                loadContactsForGroup();
            });
            
            elements.chatInfoBtn.addEventListener('click', () => {
                openModal('chatInfoModal');
                loadChatInfo();
            });
            
            // Close modals
            document.addEventListener('click', (e) => {
                if (e.target.classList.contains('modal-overlay') || e.target.closest('[data-close-modal]')) {
                    closeAllModals();
                }
            });
            
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    closeAllModals();
                }
            });
            
            // Request notification permission button
            document.getElementById('requestNotificationBtn')?.addEventListener('click', requestNotificationPermission);
            
            // Search functionality
            const searchInput = document.getElementById('searchInput');
            if (searchInput) {
                searchInput.addEventListener('input', debounce((e) => {
                    searchUsers(e.target.value);
                }, 300));
            }
        }

        // ===== ADDITIONAL FUNCTIONS =====
        async function loadProfile() {
            try {
                const result = await apiCall('get_profile');
                if (result.success) {
                    const profile = result.profile;
                    
                    document.getElementById('profileUsername').value = profile.username;
                    document.getElementById('profileName').value = profile.name;
                    document.getElementById('profileEmail').value = profile.email || '';
                    document.getElementById('profileBio').value = profile.bio || '';
                    document.getElementById('profilePrivacy').checked = profile.privacy === 1;
                    
                    // Update avatar
                    const avatarElement = document.getElementById('profileAvatar');
                    if (profile.avatar && profile.avatar !== 'default') {
                        avatarElement.style.backgroundImage = `url('uploads/avatars/${profile.avatar}')`;
                        avatarElement.style.backgroundSize = 'cover';
                        avatarElement.textContent = '';
                    } else {
                        avatarElement.style.backgroundImage = '';
                        avatarElement.textContent = profile.name.charAt(0);
                    }
                }
            } catch (error) {
                console.error('Failed to load profile:', error);
            }
        }

        async function loadContactsForGroup() {
            const container = document.getElementById('contactSearchResults');
            container.innerHTML = '';
            
            state.contacts.forEach(contact => {
                const contactElement = document.createElement('div');
                contactElement.className = 'sidebar-item';
                contactElement.innerHTML = `
                    <div class="avatar avatar-sm">${contact.name.charAt(0)}</div>
                    <div class="flex-1">
                        <div class="font-medium">${contact.name}</div>
                        <div class="text-sm text-gray-400">@${contact.username}</div>
                    </div>
                    <button class="btn btn-sm btn-primary" data-add-member="${contact.id}">
                        <i class="fas fa-plus"></i>
                    </button>
                `;
                
                container.appendChild(contactElement);
            });
        }

        function loadChatInfo() {
            const content = document.getElementById('chatInfoContent');
            if (!state.currentChat) {
                content.innerHTML = '<p class="text-gray-400">No chat selected</p>';
                return;
            }
            
            if (state.currentChatType === 'user') {
                const contact = state.contacts.find(c => c.id === state.currentChat);
                if (contact) {
                    content.innerHTML = `
                        <div class="text-center mb-4">
                            <div class="avatar avatar-lg mx-auto mb-2">${contact.name.charAt(0)}</div>
                            <h4 class="font-semibold">${contact.name}</h4>
                            <p class="text-gray-400">@${contact.username}</p>
                        </div>
                        <div class="space-y-2">
                            <div>
                                <span class="font-medium">Status:</span>
                                <span class="text-gray-400 ml-2">${contact.status}</span>
                            </div>
                            <div>
                                <span class="font-medium">Last seen:</span>
                                <span class="text-gray-400 ml-2">${formatTime(contact.last_seen)}</span>
                            </div>
                        </div>
                    `;
                }
            } else {
                const group = state.groups.find(g => g.id === state.currentChat);
                if (group) {
                    content.innerHTML = `
                        <div class="text-center mb-4">
                            <div class="avatar avatar-lg mx-auto mb-2">
                                <i class="fas fa-users"></i>
                            </div>
                            <h4 class="font-semibold">${group.name}</h4>
                            <p class="text-gray-400">${group.description || 'No description'}</p>
                        </div>
                        <div>
                            <h5 class="font-medium mb-2">Members</h5>
                            <div id="groupMembersList" class="space-y-2">
                                <!-- Members will be loaded here -->
                            </div>
                        </div>
                    `;
                }
            }
        }

        function renderNotifications() {
            const container = document.getElementById('notificationsList');
            container.innerHTML = '';
            
            if (state.notifications.length === 0) {
                container.innerHTML = '<p class="text-gray-400 text-center py-4">No notifications</p>';
                return;
            }
            
            state.notifications.forEach(notification => {
                const notificationElement = document.createElement('div');
                notificationElement.className = `sidebar-item ${notification.is_read ? '' : 'bg-blue-50 dark:bg-blue-900/20'}`;
                notificationElement.innerHTML = `
                    <div class="avatar avatar-sm">
                        <i class="fas fa-${notification.type === 'message' ? 'envelope' : notification.type === 'contact_request' ? 'user-plus' : 'users'}"></i>
                    </div>
                    <div class="flex-1">
                        <div class="font-medium">${notification.content}</div>
                        <div class="text-sm text-gray-400">${formatTime(notification.created_at)}</div>
                    </div>
                `;
                
                container.appendChild(notificationElement);
            });
        }

        async function searchUsers(query) {
            if (query.length < 2) return;
            
            try {
                const result = await apiCall('search_users', 'GET', { q: query });
                if (result.success) {
                    const container = document.getElementById('searchResults');
                    container.innerHTML = '';
                    
                    result.users.forEach(user => {
                        const userElement = document.createElement('div');
                        userElement.className = 'sidebar-item';
                        userElement.innerHTML = `
                            <div class="avatar avatar-sm">${user.name.charAt(0)}</div>
                            <div class="flex-1">
                                <div class="font-medium">${user.name}</div>
                                <div class="text-sm text-gray-400">@${user.username}</div>
                            </div>
                            <button class="btn btn-sm btn-primary" data-add-contact="${user.id}">
                                <i class="fas fa-user-plus"></i>
                            </button>
                        `;
                        
                        container.appendChild(userElement);
                    });
                }
            } catch (error) {
                console.error('Failed to search users:', error);
            }
        }

        // ===== INITIALIZE =====
        document.addEventListener('DOMContentLoaded', () => {
            checkAuth();
        });
    </script>
</body>
</html>
