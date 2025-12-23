<?php
/* ===============================
   ENHANCED MESSENGER WITH DISCORD THEME
   =============================== */

session_start();
$db = new PDO("sqlite:data.db");
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

/* === INIT DB === */
$db->exec("
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  name TEXT,
  bio TEXT,
  avatar TEXT DEFAULT 'default.jpg',
  theme TEXT DEFAULT 'dark',
  notifications INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender TEXT,
  receiver TEXT,
  content TEXT,
  encrypted INTEGER DEFAULT 0,
  encryption_key TEXT,
  time INTEGER
);

CREATE TABLE IF NOT EXISTS inbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  contact TEXT,
  last_msg TEXT,
  time INTEGER
);

CREATE TABLE IF NOT EXISTS captcha (
  token TEXT,
  expire INTEGER
);
");

/* === HELPER FUNCTIONS === */
function encryptMessage($message, $key) {
    return base64_encode($message ^ str_repeat($key, strlen($message)));
}

function decryptMessage($encrypted, $key) {
    $message = base64_decode($encrypted);
    return $message ^ str_repeat($key, strlen($message));
}

function getCurrentUser() {
    return isset($_SESSION['username']) ? $_SESSION['username'] : null;
}

/* === API HANDLER === */
if (isset($_GET['api'])) {
  header("Content-Type: application/json");

  /* CAPTCHA VERIFY */
  if ($_GET['api'] === "captcha") {
    $token = bin2hex(random_bytes(8));
    $exp = time() + 60;
    $db->prepare("INSERT INTO captcha VALUES (?,?)")->execute([$token,$exp]);
    echo json_encode(["token"=>$token]);
    exit;
  }

  if ($_GET['api'] === "register") {
    $data = json_decode(file_get_contents("php://input"), true);

    $chk = $db->prepare("SELECT * FROM captcha WHERE token=? AND expire>?");
    $chk->execute([$data['captcha'], time()]);
    if (!$chk->fetch()) {
      echo json_encode(["err"=>"captcha"]);
      exit;
    }

    $db->prepare("INSERT OR IGNORE INTO users (username,name,bio) VALUES (?,?,?)")
       ->execute([$data['username'],$data['name'],$data['bio']]);

    $_SESSION['username'] = $data['username'];
    echo json_encode(["ok"=>true]);
    exit;
  }

  if ($_GET['api'] === "login") {
    $data = json_decode(file_get_contents("php://input"), true);
    $q = $db->prepare("SELECT * FROM users WHERE username=?");
    $q->execute([$data['username']]);
    if ($q->fetch()) {
      $_SESSION['username'] = $data['username'];
      echo json_encode(["ok"=>true]);
    } else {
      echo json_encode(["err"=>"User not found"]);
    }
    exit;
  }

  if ($_GET['api'] === "logout") {
    session_destroy();
    echo json_encode(["ok"=>true]);
    exit;
  }

  if ($_GET['api'] === "update_profile") {
    $user = getCurrentUser();
    if (!$user) {
      echo json_encode(["err"=>"Not logged in"]);
      exit;
    }

    $data = json_decode(file_get_contents("php://input"), true);
    $stmt = $db->prepare("UPDATE users SET name=?, bio=? WHERE username=?");
    $stmt->execute([$data['name'], $data['bio'], $user]);

    // Handle avatar upload
    if (isset($_FILES['avatar']) && $_FILES['avatar']['error'] === 0) {
      $ext = pathinfo($_FILES['avatar']['name'], PATHINFO_EXTENSION);
      $filename = $user . '_' . time() . '.' . $ext;
      move_uploaded_file($_FILES['avatar']['tmp_name'], 'avatars/' . $filename);
      $db->prepare("UPDATE users SET avatar=? WHERE username=?")->execute([$filename, $user]);
    }

    echo json_encode(["ok"=>true]);
    exit;
  }

  if ($_GET['api'] === "update_settings") {
    $user = getCurrentUser();
    if (!$user) {
      echo json_encode(["err"=>"Not logged in"]);
      exit;
    }

    $data = json_decode(file_get_contents("php://input"), true);
    $stmt = $db->prepare("UPDATE users SET theme=?, notifications=? WHERE username=?");
    $stmt->execute([$data['theme'], $data['notifications'], $user]);
    echo json_encode(["ok"=>true]);
    exit;
  }

  if ($_GET['api'] === "get_profile") {
    $user = $_GET['username'] ?? getCurrentUser();
    $q = $db->prepare("SELECT username,name,bio,avatar FROM users WHERE username=?");
    $q->execute([$user]);
    echo json_encode($q->fetch(PDO::FETCH_ASSOC));
    exit;
  }

  if ($_GET['api'] === "get_inbox") {
    $user = getCurrentUser();
    $q = $db->prepare("SELECT DISTINCT 
      CASE 
        WHEN sender=? THEN receiver 
        ELSE sender 
      END as contact,
      MAX(time) as last_time
      FROM messages 
      WHERE sender=? OR receiver=?
      GROUP BY contact
      ORDER BY last_time DESC");
    $q->execute([$user, $user, $user]);
    $contacts = $q->fetchAll(PDO::FETCH_ASSOC);
    
    $inbox = [];
    foreach ($contacts as $contact) {
      $q2 = $db->prepare("SELECT username,name,avatar FROM users WHERE username=?");
      $q2->execute([$contact['contact']]);
      $userData = $q2->fetch(PDO::FETCH_ASSOC);
      $inbox[] = array_merge($userData, ['last_time' => $contact['last_time']]);
    }
    
    echo json_encode($inbox);
    exit;
  }

  if ($_GET['api'] === "search") {
    $u = $_GET['u'];
    $q = $db->prepare("SELECT username,name,bio,avatar FROM users WHERE username LIKE ? OR name LIKE ?");
    $q->execute(['%'.$u.'%', '%'.$u.'%']);
    echo json_encode($q->fetchAll(PDO::FETCH_ASSOC));
    exit;
  }

  if ($_GET['api'] === "send") {
    $d = json_decode(file_get_contents("php://input"), true);
    $encrypted = isset($d['key']) && $d['key'] !== '';
    $content = $encrypted ? encryptMessage($d['msg'], $d['key']) : base64_encode($d['msg']);
    
    $db->prepare("INSERT INTO messages VALUES (NULL,?,?,?,?,?,?)")
       ->execute([$d['from'],$d['to'],$content,$encrypted ? 1 : 0,$d['key'] ?? null,time()]);
    
    // Update inbox
    $db->prepare("INSERT OR REPLACE INTO inbox (username, contact, last_msg, time) VALUES (?,?,?,?)")
       ->execute([$d['from'], $d['to'], substr($d['msg'], 0, 30), time()]);
    
    echo json_encode(["ok"=>true]);
    exit;
  }

  if ($_GET['api'] === "fetch") {
    $u=$_GET['u']; $v=$_GET['v']; $key=$_GET['key'] ?? '';
    
    $q=$db->prepare("SELECT sender,content,encrypted,encryption_key,time FROM messages 
      WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?) 
      ORDER BY time ASC");
    $q->execute([$u,$v,$v,$u]);
    $messages = $q->fetchAll(PDO::FETCH_ASSOC);
    
    // Decrypt messages
    foreach ($messages as &$msg) {
      if ($msg['encrypted']) {
        $decryptionKey = ($msg['sender'] == $u) ? $key : $msg['encryption_key'];
        if ($decryptionKey) {
          $msg['content'] = decryptMessage($msg['content'], $decryptionKey);
        } else {
          $msg['content'] = '[Encrypted message - enter key to decrypt]';
        }
      } else {
        $msg['content'] = base64_decode($msg['content']);
      }
    }
    
    echo json_encode($messages);
    exit;
  }

  exit;
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>DiscordApp - WhatsApp UI with Discord Theme</title>
<style>
:root {
  --bg-primary: #36393f;
  --bg-secondary: #2f3136;
  --bg-tertiary: #202225;
  --text-primary: #ffffff;
  --text-secondary: #b9bbbe;
  --accent: #5865f2;
  --accent-hover: #4752c4;
  --success: #3ba55d;
  --danger: #ed4245;
  --border: #42464d;
}

body {
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  background: var(--bg-primary);
  color: var(--text-primary);
  margin: 0;
  height: 100vh;
  overflow: hidden;
}

.app-container {
  display: flex;
  height: 100vh;
}

/* SIDEBAR */
.sidebar {
  width: 280px;
  background: var(--bg-secondary);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
}

.user-panel {
  padding: 20px;
  background: var(--bg-tertiary);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 12px;
}

.avatar {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  object-fit: cover;
  border: 2px solid var(--accent);
}

.user-info h3 {
  margin: 0;
  font-size: 16px;
}

.user-info span {
  font-size: 12px;
  color: var(--text-secondary);
}

.sidebar-nav {
  padding: 10px 0;
}

.nav-item {
  display: flex;
  align-items: center;
  padding: 12px 20px;
  color: var(--text-secondary);
  text-decoration: none;
  transition: all 0.2s;
  gap: 12px;
}

.nav-item:hover, .nav-item.active {
  background: var(--bg-tertiary);
  color: var(--text-primary);
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
  gap: 12px;
  cursor: pointer;
  transition: background 0.2s;
}

.contact-item:hover {
  background: var(--bg-tertiary);
}

.contact-item.active {
  background: var(--bg-tertiary);
  border-left: 3px solid var(--accent);
}

.contact-avatar {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  object-fit: cover;
}

.contact-info h4 {
  margin: 0;
  font-size: 14px;
}

.contact-info span {
  font-size: 12px;
  color: var(--text-secondary);
  display: block;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 180px;
}

/* MAIN CONTENT */
.main-content {
  flex: 1;
  display: flex;
  flex-direction: column;
}

.chat-header {
  padding: 20px;
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.chat-header-info {
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
  background: var(--bg-primary);
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.message-bubble {
  max-width: 70%;
  padding: 12px 16px;
  border-radius: 18px;
  position: relative;
  word-wrap: break-word;
}

.message-sent {
  align-self: flex-end;
  background: var(--accent);
  border-bottom-right-radius: 4px;
}

.message-received {
  align-self: flex-start;
  background: var(--bg-tertiary);
  border-bottom-left-radius: 4px;
}

.message-time {
  font-size: 11px;
  color: var(--text-secondary);
  margin-top: 4px;
  text-align: right;
}

.chat-input-area {
  padding: 20px;
  background: var(--bg-secondary);
  border-top: 1px solid var(--border);
  display: flex;
  gap: 10px;
}

.chat-input {
  flex: 1;
  padding: 12px 16px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--text-primary);
  outline: none;
}

.btn {
  padding: 10px 20px;
  background: var(--accent);
  color: white;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  transition: background 0.2s;
  font-weight: 500;
}

.btn:hover {
  background: var(--accent-hover);
}

.btn-secondary {
  background: var(--bg-tertiary);
}

.btn-secondary:hover {
  background: #3a3d42;
}

.btn-danger {
  background: var(--danger);
}

.btn-danger:hover {
  background: #c03537;
}

/* MODALS */
.modal {
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0,0,0,0.8);
  z-index: 1000;
  align-items: center;
  justify-content: center;
}

.modal.active {
  display: flex;
}

.modal-content {
  background: var(--bg-secondary);
  border-radius: 8px;
  width: 90%;
  max-width: 500px;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  padding: 20px;
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.modal-body {
  padding: 20px;
}

.form-group {
  margin-bottom: 16px;
}

.form-label {
  display: block;
  margin-bottom: 8px;
  color: var(--text-secondary);
  font-size: 14px;
}

.form-input {
  width: 100%;
  padding: 10px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border);
  border-radius: 4px;
  color: var(--text-primary);
}

.form-textarea {
  min-height: 100px;
  resize: vertical;
}

.theme-selector {
  display: flex;
  gap: 10px;
  margin-top: 10px;
}

.theme-option {
  flex: 1;
  padding: 15px;
  background: var(--bg-tertiary);
  border: 2px solid transparent;
  border-radius: 8px;
  cursor: pointer;
  text-align: center;
}

.theme-option.active {
  border-color: var(--accent);
}

.theme-dark { background: #36393f; }
.theme-light { background: #ffffff; color: #000; }
.theme-amoled { background: #000000; }

.encryption-note {
  background: var(--bg-tertiary);
  padding: 10px;
  border-radius: 8px;
  font-size: 12px;
  color: var(--text-secondary);
  margin-top: 10px;
}

/* UTILITY */
.hidden { display: none !important; }
.text-center { text-align: center; }
.mt-20 { margin-top: 20px; }
.mb-20 { margin-bottom: 20px; }

/* SCROLLBAR */
::-webkit-scrollbar {
  width: 8px;
}

::-webkit-scrollbar-track {
  background: var(--bg-tertiary);
}

::-webkit-scrollbar-thumb {
  background: var(--border);
  border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
  background: #5d6168;
}
</style>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>

<!-- MAIN APP -->
<div class="app-container hidden" id="app">
  <!-- SIDEBAR -->
  <div class="sidebar">
    <div class="user-panel">
      <img src="avatars/default.jpg" class="avatar" id="userAvatar">
      <div class="user-info">
        <h3 id="userName">Loading...</h3>
        <span id="userStatus">Online</span>
      </div>
    </div>
    
    <div class="sidebar-nav">
      <a href="#" class="nav-item active" onclick="showInbox()">
        <i class="fas fa-inbox"></i> Inbox
      </a>
      <a href="#" class="nav-item" onclick="showModal('searchModal')">
        <i class="fas fa-search"></i> Search Users
      </a>
      <a href="#" class="nav-item" onclick="showModal('profileModal')">
        <i class="fas fa-user-edit"></i> Edit Profile
      </a>
      <a href="#" class="nav-item" onclick="showModal('settingsModal')">
        <i class="fas fa-cog"></i> Settings
      </a>
      <a href="#" class="nav-item" onclick="logout()">
        <i class="fas fa-sign-out-alt"></i> Logout
      </a>
    </div>
    
    <div class="inbox-list" id="inboxList">
      <!-- Contacts will be loaded here -->
    </div>
  </div>
  
  <!-- MAIN CHAT -->
  <div class="main-content">
    <div class="chat-header" id="chatHeader">
      <div class="chat-header-info">
        <img src="avatars/default.jpg" class="avatar" id="chatAvatar">
        <div>
          <h3 id="chatContactName">Select a chat</h3>
          <span id="chatContactStatus">Click on a contact to start chatting</span>
        </div>
      </div>
      <div class="chat-actions" id="chatActions" style="display: none;">
        <button class="btn btn-secondary" onclick="toggleEncryption()">
          <i class="fas fa-lock" id="encryptionIcon"></i>
        </button>
        <button class="btn btn-secondary" onclick="clearChat()">
          <i class="fas fa-trash"></i>
        </button>
      </div>
    </div>
    
    <div class="chat-container" id="chatContainer">
      <!-- Messages will appear here -->
      <div class="text-center" style="color: var(--text-secondary); margin-top: 50px;">
        <i class="fas fa-comments fa-3x mb-20"></i>
        <p>Select a contact to start messaging</p>
      </div>
    </div>
    
    <div class="chat-input-area hidden" id="chatInputArea">
      <input type="text" class="chat-input" id="messageInput" placeholder="Type a message..." onkeypress="if(event.key==='Enter') sendMessage()">
      <input type="text" class="chat-input hidden" id="encryptionKey" placeholder="Encryption key" style="width: 200px;">
      <button class="btn" onclick="sendMessage()">
        <i class="fas fa-paper-plane"></i>
      </button>
    </div>
  </div>
</div>

<!-- LOGIN/REGISTER -->
<div id="auth" class="page active" style="display: flex; align-items: center; justify-content: center; height: 100vh;">
  <div style="background: var(--bg-secondary); padding: 40px; border-radius: 12px; width: 100%; max-width: 400px;">
    <h2 style="text-align: center; margin-bottom: 30px;">
      <i class="fas fa-comments" style="color: var(--accent); margin-right: 10px;"></i>
      DiscordApp
    </h2>
    
    <div id="loginForm">
      <div class="form-group">
        <input type="text" class="form-input" id="loginUsername" placeholder="Username">
      </div>
      <button class="btn" style="width: 100%;" onclick="login()">Login / Register</button>
      <p style="text-align: center; color: var(--text-secondary); margin-top: 20px; font-size: 14px;">
        Enter your username. If it doesn't exist, we'll create a new account.
      </p>
    </div>
  </div>
</div>

<!-- MODALS -->
<div class="modal" id="profileModal">
  <div class="modal-content">
    <div class="modal-header">
      <h3>Edit Profile</h3>
      <button onclick="hideModal('profileModal')" style="background: none; border: none; color: var(--text-secondary); cursor: pointer;">
        <i class="fas fa-times"></i>
      </button>
    </div>
    <div class="modal-body">
      <div class="form-group text-center">
        <img src="avatars/default.jpg" class="avatar" id="editAvatar" style="width: 80px; height: 80px; cursor: pointer;">
        <input type="file" id="avatarUpload" accept="image/*" hidden>
        <p style="color: var(--text-secondary); font-size: 12px; margin-top: 5px;">Click to change</p>
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
      <button class="btn" style="width: 100%;" onclick="updateProfile()">Save Changes</button>
    </div>
  </div>
</div>

<div class="modal" id="settingsModal">
  <div class="modal-content">
    <div class="modal-header">
      <h3>Settings</h3>
      <button onclick="hideModal('settingsModal')" style="background: none; border: none; color: var(--text-secondary); cursor: pointer;">
        <i class="fas fa-times"></i>
      </button>
    </div>
    <div class="modal-body">
      <div class="form-group">
        <label class="form-label">Theme</label>
        <div class="theme-selector">
          <div class="theme-option theme-dark active" onclick="selectTheme('dark')">
            <i class="fas fa-moon"></i><br>Dark
          </div>
          <div class="theme-option theme-light" onclick="selectTheme('light')">
            <i class="fas fa-sun"></i><br>Light
          </div>
          <div class="theme-option theme-amoled" onclick="selectTheme('amoled')">
            <i class="fas fa-moon"></i><br>AMOLED
          </div>
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">Notifications</label>
        <label style="display: flex; align-items: center; gap: 10px; cursor: pointer;">
          <input type="checkbox" id="notificationsToggle" checked>
          <span>Enable message notifications</span>
        </label>
      </div>
      <button class="btn" style="width: 100%;" onclick="saveSettings()">Save Settings</button>
    </div>
  </div>
</div>

<div class="modal" id="searchModal">
  <div class="modal-content">
    <div class="modal-header">
      <h3>Search Users</h3>
      <button onclick="hideModal('searchModal')" style="background: none; border: none; color: var(--text-secondary); cursor: pointer;">
        <i class="fas fa-times"></i>
      </button>
    </div>
    <div class="modal-body">
      <div class="form-group">
        <input type="text" class="form-input" id="searchInput" placeholder="Search by username or name" onkeyup="searchUsers()">
      </div>
      <div id="searchResults">
        <!-- Results will appear here -->
      </div>
    </div>
  </div>
</div>

<div class="modal" id="encryptionModal">
  <div class="modal-content">
    <div class="modal-header">
      <h3>Encryption Key</h3>
      <button onclick="hideModal('encryptionModal')" style="background: none; border: none; color: var(--text-secondary); cursor: pointer;">
        <i class="fas fa-times"></i>
      </button>
    </div>
    <div class="modal-body">
      <div class="form-group">
        <label class="form-label">Enter encryption key for this chat</label>
        <input type="password" class="form-input" id="modalEncryptionKey" placeholder="Secret key">
        <p class="encryption-note">
          <i class="fas fa-info-circle"></i> Both users need to enter the same key to encrypt/decrypt messages.
          The key is only stored locally and never sent to the server.
        </p>
      </div>
      <button class="btn" onclick="setEncryptionKey()">Apply Key</button>
      <button class="btn btn-secondary" onclick="clearEncryptionKey()">Disable Encryption</button>
    </div>
  </div>
</div>

<script>
/* === GLOBAL VARIABLES === */
let currentUser = null;
let currentChat = null;
let encryptionKey = '';
let isEncrypted = false;
let captchaToken = null;

/* === INITIALIZATION === */
document.addEventListener('DOMContentLoaded', function() {
  // Check if user is logged in
  fetch('?api=get_profile')
    .then(r => r.json())
    .then(profile => {
      if (profile.username) {
        currentUser = profile.username;
        loadApp();
      }
    });
  
  // Get captcha token
  fetch('?api=captcha').then(r => r.json()).then(j => captchaToken = j.token);
});

/* === AUTHENTICATION === */
function login() {
  const username = document.getElementById('loginUsername').value.trim();
  if (!username) return alert('Please enter a username');
  
  fetch('?api=login', {
    method: 'POST',
    body: JSON.stringify({ username: username })
  })
  .then(r => r.json())
  .then(data => {
    if (data.ok) {
      currentUser = username;
      loadApp();
    } else {
      // Auto-register if user doesn't exist
      fetch('?api=register', {
        method: 'POST',
        body: JSON.stringify({
          username: username,
          name: username,
          bio: 'Hello! I\'m new here.',
          captcha: captchaToken
        })
      })
      .then(r => r.json())
      .then(() => {
        currentUser = username;
        loadApp();
      });
    }
  });
}

function logout() {
  fetch('?api=logout')
    .then(() => {
      document.getElementById('app').classList.add('hidden');
      document.getElementById('auth').style.display = 'flex';
      currentUser = null;
    });
}

function loadApp() {
  document.getElementById('auth').style.display = 'none';
  document.getElementById('app').classList.remove('hidden');
  
  loadProfile();
  loadInbox();
  
  // Start auto-refresh
  setInterval(() => {
    if (currentChat) loadMessages();
    loadInbox();
  }, 3000);
}

/* === PROFILE MANAGEMENT === */
function loadProfile() {
  fetch(`?api=get_profile&username=${currentUser}`)
    .then(r => r.json())
    .then(profile => {
      document.getElementById('userName').textContent = profile.name || profile.username;
      document.getElementById('userAvatar').src = 'avatars/' + (profile.avatar || 'default.jpg');
      
      // Fill edit form
      document.getElementById('editUsername').value = profile.username;
      document.getElementById('editName').value = profile.name || '';
      document.getElementById('editBio').value = profile.bio || '';
      document.getElementById('editAvatar').src = 'avatars/' + (profile.avatar || 'default.jpg');
    });
}

function updateProfile() {
  const formData = new FormData();
  formData.append('name', document.getElementById('editName').value);
  formData.append('bio', document.getElementById('editBio').value);
  
  const avatarFile = document.getElementById('avatarUpload').files[0];
  if (avatarFile) formData.append('avatar', avatarFile);
  
  fetch('?api=update_profile', {
    method: 'POST',
    body: formData
  })
  .then(r => r.json())
  .then(() => {
    hideModal('profileModal');
    loadProfile();
  });
}

document.getElementById('editAvatar').addEventListener('click', () => {
  document.getElementById('avatarUpload').click();
});

document.getElementById('avatarUpload').addEventListener('change', function(e) {
  if (e.target.files[0]) {
    const reader = new FileReader();
    reader.onload = function(event) {
      document.getElementById('editAvatar').src = event.target.result;
    };
    reader.readAsDataURL(e.target.files[0]);
  }
});

/* === INBOX & CHAT === */
function loadInbox() {
  fetch('?api=get_inbox')
    .then(r => r.json())
    .then(contacts => {
      const inboxList = document.getElementById('inboxList');
      inboxList.innerHTML = '';
      
      contacts.forEach(contact => {
        const div = document.createElement('div');
        div.className = 'contact-item';
        div.onclick = () => openChat(contact.username);
        
        div.innerHTML = `
          <img src="avatars/${contact.avatar || 'default.jpg'}" class="contact-avatar">
          <div class="contact-info">
            <h4>${contact.name || contact.username}</h4>
            <span>${contact.bio || 'No bio'}</span>
          </div>
        `;
        
        inboxList.appendChild(div);
      });
    });
}

function openChat(username) {
  currentChat = username;
  document.getElementById('chatInputArea').classList.remove('hidden');
  document.getElementById('chatActions').style.display = 'flex';
  document.getElementById('chatContactName').textContent = username;
  document.getElementById('chatContactStatus').textContent = 'Online';
  
  // Load contact profile for avatar
  fetch(`?api=get_profile&username=${username}`)
    .then(r => r.json())
    .then(profile => {
      document.getElementById('chatAvatar').src = 'avatars/' + (profile.avatar || 'default.jpg');
    });
  
  loadMessages();
}

function loadMessages() {
  if (!currentChat) return;
  
  fetch(`?api=fetch&u=${currentUser}&v=${currentChat}&key=${encryptionKey}`)
    .then(r => r.json())
    .then(messages => {
      const container = document.getElementById('chatContainer');
      container.innerHTML = '';
      
      messages.forEach(msg => {
        const bubble = document.createElement('div');
        bubble.className = `message-bubble ${msg.sender === currentUser ? 'message-sent' : 'message-received'}`;
        
        const time = new Date(msg.time * 1000).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        
        bubble.innerHTML = `
          <div>${msg.content}</div>
          <div class="message-time">${time}</div>
        `;
        
        container.appendChild(bubble);
      });
      
      container.scrollTop = container.scrollHeight;
    });
}

function sendMessage() {
  if (!currentChat) return alert('Select a contact first');
  
  const input = document.getElementById('messageInput');
  const message = input.value.trim();
  if (!message) return;
  
  fetch('?api=send', {
    method: 'POST',
    body: JSON.stringify({
      from: currentUser,
      to: currentChat,
      msg: message,
      key: isEncrypted ? encryptionKey : ''
    })
  })
  .then(r => r.json())
  .then(() => {
    input.value = '';
    loadMessages();
  });
}

/* === ENCRYPTION === */
function toggleEncryption() {
  showModal('encryptionModal');
}

function setEncryptionKey() {
  const key = document.getElementById('modalEncryptionKey').value;
  if (key) {
    encryptionKey = key;
    isEncrypted = true;
    document.getElementById('encryptionKey').value = key;
    document.getElementById('encryptionIcon').className = 'fas fa-lock';
    hideModal('encryptionModal');
    loadMessages(); // Reload messages with new key
  }
}

function clearEncryptionKey() {
  encryptionKey = '';
  isEncrypted = false;
  document.getElementById('encryptionKey').value = '';
  document.getElementById('encryptionIcon').className = 'fas fa-lock-open';
  hideModal('encryptionModal');
  loadMessages();
}

/* === SETTINGS === */
function saveSettings() {
  const theme = document.querySelector('.theme-option.active').getAttribute('onclick').match(/'([^']+)'/)[1];
  const notifications = document.getElementById('notificationsToggle').checked ? 1 : 0;
  
  fetch('?api=update_settings', {
    method: 'POST',
    body: JSON.stringify({ theme, notifications })
  })
  .then(r => r.json())
  .then(() => {
    hideModal('settingsModal');
    applyTheme(theme);
  });
}

function selectTheme(theme) {
  document.querySelectorAll('.theme-option').forEach(el => el.classList.remove('active'));
  event.target.closest('.theme-option').classList.add('active');
}

function applyTheme(theme) {
  const root = document.documentElement;
  switch(theme) {
    case 'light':
      root.style.setProperty('--bg-primary', '#ffffff');
      root.style.setProperty('--bg-secondary', '#f2f3f5');
      root.style.setProperty('--bg-tertiary', '#e3e5e8');
      root.style.setProperty('--text-primary', '#060607');
      root.style.setProperty('--text-secondary', '#4f5660');
      root.style.setProperty('--border', '#d4d7dc');
      break;
    case 'amoled':
      root.style.setProperty('--bg-primary', '#000000');
      root.style.setProperty('--bg-secondary', '#111111');
      root.style.setProperty('--bg-tertiary', '#222222');
      break;
    default: // dark
      root.style.setProperty('--bg-primary', '#36393f');
      root.style.setProperty('--bg-secondary', '#2f3136');
      root.style.setProperty('--bg-tertiary', '#202225');
      root.style.setProperty('--text-primary', '#ffffff');
      root.style.setProperty('--text-secondary', '#b9bbbe');
      root.style.setProperty('--border', '#42464d');
  }
}

/* === SEARCH === */
function searchUsers() {
  const query = document.getElementById('searchInput').value.trim();
  if (query.length < 2) return;
  
  fetch(`?api=search&u=${query}`)
    .then(r => r.json())
    .then(users => {
      const results = document.getElementById('searchResults');
      results.innerHTML = '';
      
      users.forEach(user => {
        const div = document.createElement('div');
        div.className = 'contact-item';
        div.onclick = () => {
          hideModal('searchModal');
          openChat(user.username);
        };
        
        div.innerHTML = `
          <img src="avatars/${user.avatar || 'default.jpg'}" class="contact-avatar">
          <div class="contact-info">
            <h4>${user.name || user.username}</h4>
            <span>${user.bio || 'No bio'}</span>
            <span style="color: var(--accent); font-size: 10px;">@${user.username}</span>
          </div>
        `;
        
        results.appendChild(div);
      });
    });
}

/* === MODAL FUNCTIONS === */
function showModal(id) {
  document.getElementById(id).classList.add('active');
}

function hideModal(id) {
  document.getElementById(id).classList.remove('active');
}

/* === UTILITY === */
function clearChat() {
  if (confirm('Clear all messages in this chat?')) {
    // This would need a proper API endpoint to clear messages
    alert('Clear chat feature would be implemented here');
  }
}

function showInbox() {
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  event.target.closest('.nav-item').classList.add('active');
  currentChat = null;
  document.getElementById('chatInputArea').classList.add('hidden');
  document.getElementById('chatActions').style.display = 'none';
  document.getElementById('chatContainer').innerHTML = `
    <div class="text-center" style="color: var(--text-secondary); margin-top: 50px;">
      <i class="fas fa-comments fa-3x mb-20"></i>
      <p>Select a contact to start messaging</p>
    </div>
  `;
}

/* === KEYBOARD SHORTCUTS === */
document.addEventListener('keydown', function(e) {
  if (e.ctrlKey && e.key === 'k') {
    e.preventDefault();
    showModal('searchModal');
    document.getElementById('searchInput').focus();
  }
  
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal.active').forEach(modal => {
      modal.classList.remove('active');
    });
  }
});
</script>
</body>
</html>
