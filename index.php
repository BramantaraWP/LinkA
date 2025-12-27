<?php
/**
 * Simple File Manager - Telegram Storage
 * PHP untuk management metadata saja
 * Upload langsung dari JS ke Telegram
 * WITH LOGIN PROTECTION
 */

// ============================
// CONFIGURATION
// ============================
define('STORAGE_PATH', __DIR__ . '/storage');
define('TELEGRAM_BOT_TOKEN', '8337490666:AAHhTs1w57Ynqs70GP3579IHqo491LHaCl8');

// LOGIN CREDENTIALS - CHANGE THESE!
define('USERNAME', 'admin');      // Ganti dengan username kamu
define('PASSWORD', 'password123'); // Ganti dengan password kuat

// Create storage directory
if (!file_exists(STORAGE_PATH)) {
    mkdir(STORAGE_PATH, 0777, true);
}

// Set timezone
date_default_timezone_set('UTC');

// Start session for login
session_start();

// ============================
// LOGIN CHECK
// ============================
function check_login() {
    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        // Check if login form is submitted
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username']) && isset($_POST['password'])) {
            if ($_POST['username'] === USERNAME && $_POST['password'] === PASSWORD) {
                $_SESSION['logged_in'] = true;
                $_SESSION['username'] = USERNAME;
                return true;
            } else {
                return false;
            }
        }
        return false;
    }
    return true;
}

// If not logged in and not trying to login, show login form
if (!check_login() && !isset($_GET['action'])) {
    show_login_form();
    exit;
}

// ============================
// HELPER FUNCTIONS
// ============================
function format_file_size($bytes) {
    if ($bytes == 0) return "0 B";
    $size_names = ["B", "KB", "MB", "GB"];
    $i = floor(log($bytes, 1024));
    $s = round($bytes / pow(1024, $i), 1);
    return $s . " " . $size_names[$i];
}

function get_file_icon($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $icons = [
        'jpg' => '🖼️', 'jpeg' => '🖼️', 'png' => '🖼️', 'gif' => '🖼️',
        'pdf' => '📕', 'doc' => '📘', 'docx' => '📘',
        'xls' => '📗', 'xlsx' => '📗', 'txt' => '📄',
        'zip' => '🗜️', 'rar' => '🗜️', 'mp4' => '🎬',
        'mp3' => '🎵', 'wav' => '🎵', 'php' => '📝',
        'js' => '📝', 'html' => '📝', 'css' => '📝'
    ];
    return $icons[$ext] ?? '📄';
}

// Fungsi untuk mendapatkan download URL dari Telegram
function get_telegram_file_url($file_id) {
    // Pertama, dapatkan file path dari Telegram
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => 'https://api.telegram.org/bot' . TELEGRAM_BOT_TOKEN . '/getFile',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode(['file_id' => $file_id]),
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_TIMEOUT => 10
    ]);
    
    $response = curl_exec($ch);
    $data = json_decode($response, true);
    curl_close($ch);
    
    if ($data && $data['ok'] && isset($data['result']['file_path'])) {
        return 'https://api.telegram.org/file/bot' . TELEGRAM_BOT_TOKEN . '/' . $data['result']['file_path'];
    }
    
    return false;
}

// ============================
// DOWNLOAD HANDLER
// ============================
if (isset($_GET['download']) && isset($_GET['id'])) {
    // Check login untuk download
    if (!check_login()) {
        header('HTTP/1.0 403 Forbidden');
        echo 'Access denied. Please login first.';
        exit;
    }
    
    $file_id = $_GET['id'];
    $data_file = STORAGE_PATH . '/data.json';
    
    if (file_exists($data_file)) {
        $files = json_decode(file_get_contents($data_file), true);
        
        // Cari file berdasarkan ID
        foreach ($files as $file) {
            if ($file['id'] === $_GET['download']) {
                // Dapatkan download URL dari Telegram
                $download_url = get_telegram_file_url($file['file_id']);
                
                if ($download_url) {
                    // Redirect langsung ke Telegram file URL
                    header('Location: ' . $download_url);
                    exit;
                }
                break;
            }
        }
    }
    
    // Jika tidak ditemukan atau error
    header('HTTP/1.0 404 Not Found');
    echo 'File not found or download link expired';
    exit;
}

// ============================
// LOGIN FORM
// ============================
function show_login_form() {
    $error = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $error = 'Invalid username or password!';
    }
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Login Required</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
            }
            .login-container {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                width: 350px;
            }
            .login-header {
                text-align: center;
                margin-bottom: 30px;
            }
            .login-header h1 {
                color: #333;
                font-size: 24px;
                margin-bottom: 10px;
            }
            .login-header p {
                color: #666;
                font-size: 14px;
            }
            .login-form input {
                width: 100%;
                padding: 12px;
                margin-bottom: 15px;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 14px;
            }
            .login-form input:focus {
                outline: none;
                border-color: #667eea;
            }
            .login-btn {
                width: 100%;
                background: #667eea;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 5px;
                font-size: 16px;
                cursor: pointer;
                transition: background 0.3s;
            }
            .login-btn:hover {
                background: #5a67d8;
            }
            .error {
                background: #fee;
                color: #c33;
                padding: 10px;
                border-radius: 5px;
                margin-bottom: 15px;
                font-size: 14px;
                text-align: center;
            }
            .note {
                margin-top: 20px;
                padding: 10px;
                background: #f5f5f5;
                border-radius: 5px;
                font-size: 12px;
                color: #666;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="login-header">
                <h1>🔒 Private Cloud</h1>
                <p>Please login to continue</p>
            </div>
            
            <?php if ($error): ?>
            <div class="error"><?php echo $error; ?></div>
            <?php endif; ?>
            
            <form class="login-form" method="POST">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit" class="login-btn">Login</button>
            </form>
            
            <div class="note">
                Default: admin / password123<br>
                Change in config section of PHP file
            </div>
        </div>
    </body>
    </html>
    <?php
}

// ============================
// LOGOUT HANDLER
// ============================
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// ============================
// API ENDPOINTS - METADATA MANAGEMENT
// ============================
if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    
    // Check login for API calls too
    if (!check_login()) {
        echo json_encode(['ok' => false, 'error' => 'Not logged in']);
        exit;
    }
    
    $data_file = STORAGE_PATH . '/data.json';
    
    // Load existing data
    $data = file_exists($data_file) ? json_decode(file_get_contents($data_file), true) : [];
    
    switch ($_GET['action']) {
        
        case 'list':
            // Return ALL files (no user filtering since it's private)
            echo json_encode(['ok' => true, 'files' => array_reverse($data)]);
            break;
            
        case 'add':
            // Add file metadata after successful upload
            if (isset($_POST['name']) && isset($_POST['file_id']) && isset($_POST['size'])) {
                $file_data = [
                    'id' => uniqid(),
                    'name' => $_POST['name'],
                    'file_id' => $_POST['file_id'],
                    'size' => (int)$_POST['size'],
                    'date' => date('Y-m-d H:i:s'),
                    'uploader' => $_SESSION['username'] ?? 'admin'
                ];
                
                $data[] = $file_data;
                file_put_contents($data_file, json_encode($data, JSON_PRETTY_PRINT));
                echo json_encode(['ok' => true, 'id' => $file_data['id']]);
            } else {
                echo json_encode(['ok' => false, 'error' => 'Missing parameters']);
            }
            break;
            
        case 'delete':
            if (isset($_GET['id'])) {
                $new_data = [];
                foreach ($data as $file) {
                    if ($file['id'] !== $_GET['id']) {
                        $new_data[] = $file;
                    }
                }
                file_put_contents($data_file, json_encode($new_data, JSON_PRETTY_PRINT));
                echo json_encode(['ok' => true]);
            }
            break;
            
        case 'rename':
            if (isset($_GET['id']) && isset($_GET['name'])) {
                foreach ($data as &$file) {
                    if ($file['id'] === $_GET['id']) {
                        $file['name'] = $_GET['name'];
                        break;
                    }
                }
                file_put_contents($data_file, json_encode($data, JSON_PRETTY_PRINT));
                echo json_encode(['ok' => true]);
            }
            break;
            
        case 'move':
            // Simulate move by renaming with path
            if (isset($_GET['id']) && isset($_GET['path'])) {
                foreach ($data as &$file) {
                    if ($file['id'] === $_GET['id']) {
                        $file['name'] = $_GET['path'] . '/' . basename($file['name']);
                        break;
                    }
                }
                file_put_contents($data_file, json_encode($data, JSON_PRETTY_PRINT));
                echo json_encode(['ok' => true]);
            }
            break;
            
        case 'share':
            if (isset($_GET['id'])) {
                $file = null;
                foreach ($data as $f) {
                    if ($f['id'] === $_GET['id']) {
                        $file = $f;
                        break;
                    }
                }
                if ($file) {
                    // Generate shareable link
                    $share_id = uniqid();
                    $share_file = STORAGE_PATH . '/shares.json';
                    $shares = file_exists($share_file) ? json_decode(file_get_contents($share_file), true) : [];
                    $shares[$share_id] = $file;
                    file_put_contents($share_file, json_encode($shares, JSON_PRETTY_PRINT));
                    
                    $share_url = (isset($_SERVER['HTTPS']) ? 'https://' : 'http://') . 
                                $_SERVER['HTTP_HOST'] . 
                                $_SERVER['SCRIPT_NAME'] . 
                                '?share=' . $share_id;
                    echo json_encode(['ok' => true, 'url' => $share_url]);
                } else {
                    echo json_encode(['ok' => false, 'error' => 'File not found']);
                }
            }
            break;
            
        case 'get_download_url':
            // API untuk mendapatkan download URL
            if (isset($_GET['id'])) {
                $file = null;
                foreach ($data as $f) {
                    if ($f['id'] === $_GET['id']) {
                        $file = $f;
                        break;
                    }
                }
                if ($file) {
                    $download_url = get_telegram_file_url($file['file_id']);
                    if ($download_url) {
                        echo json_encode(['ok' => true, 'url' => $download_url]);
                    } else {
                        echo json_encode(['ok' => false, 'error' => 'Could not get download URL']);
                    }
                } else {
                    echo json_encode(['ok' => false, 'error' => 'File not found']);
                }
            }
            break;
            
        default:
            echo json_encode(['ok' => false, 'error' => 'Unknown action']);
    }
    exit;
}

// ============================
// SHARE VIEW ENDPOINT
// ============================
if (isset($_GET['share'])) {
    $share_file = STORAGE_PATH . '/shares.json';
    if (file_exists($share_file)) {
        $shares = json_decode(file_get_contents($share_file), true);
        if (isset($shares[$_GET['share']])) {
            $file = $shares[$_GET['share']];
            
            // Get download URL for shared file
            $download_url = get_telegram_file_url($file['file_id']);
            
            if (!$download_url) {
                header('HTTP/1.0 404 Not Found');
                echo 'File not found or download link expired';
                exit;
            }
            ?>
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Shared File: <?php echo htmlspecialchars($file['name']); ?></title>
                <style>
                    body { 
                        font-family: Arial, sans-serif; 
                        text-align: center; 
                        padding: 50px; 
                        background: #f5f5f5;
                    }
                    .container {
                        max-width: 600px;
                        margin: 0 auto;
                        background: white;
                        padding: 30px;
                        border-radius: 10px;
                        box-shadow: 0 5px 20px rgba(0,0,0,0.1);
                    }
                    .file-icon { 
                        font-size: 80px; 
                        margin: 20px; 
                    }
                    .download-btn {
                        display: inline-block;
                        background: #4CAF50;
                        color: white;
                        padding: 15px 30px;
                        text-decoration: none;
                        border-radius: 5px;
                        margin: 20px;
                        font-size: 16px;
                        transition: background 0.3s;
                    }
                    .download-btn:hover {
                        background: #45a049;
                    }
                    .file-info {
                        margin: 20px 0;
                        padding: 15px;
                        background: #f9f9f9;
                        border-radius: 5px;
                        text-align: left;
                    }
                    .file-info p {
                        margin: 10px 0;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="file-icon"><?php echo get_file_icon($file['name']); ?></div>
                    <h1><?php echo htmlspecialchars($file['name']); ?></h1>
                    
                    <div class="file-info">
                        <p><strong>Size:</strong> <?php echo format_file_size($file['size']); ?></p>
                        <p><strong>Uploaded:</strong> <?php echo date('F j, Y, g:i a', strtotime($file['date'])); ?></p>
                        <p><strong>Uploader:</strong> <?php echo htmlspecialchars($file['uploader'] ?? 'Unknown'); ?></p>
                    </div>
                    
                    <a href="<?php echo $download_url; ?>" 
                       class="download-btn" download="<?php echo htmlspecialchars($file['name']); ?>">
                       ⬇️ Download File
                    </a>
                    
                    <p style="margin-top: 30px; color: #666; font-size: 14px;">
                        This file was shared from a private cloud storage.
                    </p>
                </div>
            </body>
            </html>
            <?php
            exit;
        }
    }
    header('HTTP/1.0 404 Not Found');
    echo 'Share link expired or not found';
    exit;
}

// ============================
// MAIN HTML INTERFACE
// ============================
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Private Cloud Storage</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: "Segoe UI", Arial, sans-serif;
            font-size: 14px;
            background: #f0f2f5;
            color: #333;
        }
        .container {
            max-width: 1000px;
            margin: 20px auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            border-radius: 8px 8px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            color: white;
        }
        .header-left h1 {
            font-size: 20px;
            font-weight: 500;
            margin-bottom: 5px;
        }
        .header-left p {
            font-size: 13px;
            opacity: 0.9;
        }
        .user-info {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .user-info span {
            font-size: 14px;
        }
        .logout-btn {
            background: rgba(255,255,255,0.2);
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            text-decoration: none;
            display: inline-block;
        }
        .logout-btn:hover {
            background: rgba(255,255,255,0.3);
        }
        .upload-area {
            padding: 20px;
            border-bottom: 1px solid #eee;
            text-align: center;
            background: #f9fafb;
        }
        .upload-btn {
            background: #4CAF50;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .upload-btn:hover {
            background: #45a049;
        }
        .upload-btn:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        .file-table {
            width: 100%;
            border-collapse: collapse;
        }
        .file-table th {
            background: #f8f9fa;
            padding: 12px 15px;
            text-align: left;
            border-bottom: 2px solid #dee2e6;
            font-weight: 600;
            color: #495057;
            font-size: 13px;
        }
        .file-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #e9ecef;
            vertical-align: middle;
        }
        .file-table tr:hover {
            background: #f8f9fa;
        }
        .file-icon {
            font-size: 18px;
            text-align: center;
            width: 40px;
        }
        .file-name {
            max-width: 350px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .file-actions {
            text-align: right;
            white-space: nowrap;
        }
        .action-btn {
            background: none;
            border: 1px solid #dee2e6;
            padding: 4px 8px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
            margin-left: 4px;
            color: #495057;
            transition: all 0.2s;
        }
        .action-btn:hover {
            background: #e9ecef;
            border-color: #ced4da;
        }
        .status {
            margin: 10px 20px;
            padding: 10px;
            border-radius: 5px;
            display: none;
        }
        .status.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
            display: block;
        }
        .status.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
            display: block;
        }
        .loading {
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid #f3f3f3;
            border-top: 2px solid #4285f4;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .empty {
            text-align: center;
            padding: 40px;
            color: #6c757d;
            font-style: italic;
        }
        .progress-bar {
            height: 4px;
            background: #e9ecef;
            margin-top: 15px;
            border-radius: 2px;
            overflow: hidden;
            display: none;
        }
        .progress-fill {
            height: 100%;
            background: #4CAF50;
            width: 0%;
            transition: width 0.3s;
        }
        .search-box {
            margin-top: 15px;
            display: flex;
            gap: 10px;
            justify-content: center;
        }
        .search-box input {
            padding: 8px 12px;
            border: 1px solid #ced4da;
            border-radius: 4px;
            width: 300px;
            font-size: 14px;
        }
        .search-box input:focus {
            outline: none;
            border-color: #80bdff;
            box-shadow: 0 0 0 0.2rem rgba(0,123,255,0.25);
        }
        .stats {
            display: flex;
            gap: 20px;
            justify-content: center;
            margin-top: 15px;
            font-size: 13px;
            color: #6c757d;
        }
        .stat-item {
            background: #f8f9fa;
            padding: 8px 15px;
            border-radius: 4px;
            border: 1px solid #e9ecef;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-left">
                <h1>☁️ Private Cloud Storage</h1>
                <p>All your files in one secure place</p>
            </div>
            <div class="user-info">
                <span>Welcome, <strong><?php echo htmlspecialchars($_SESSION['username'] ?? 'Admin'); ?></strong></span>
                <a href="?logout" class="logout-btn">Logout</a>
            </div>
        </div>
        
        <div class="upload-area">
            <button class="upload-btn" onclick="selectFile()" id="uploadBtn">
                📁 Upload File
            </button>
            <input type="file" id="fileInput" style="display:none;" onchange="uploadToTelegram()">
            
            <div class="search-box">
                <input type="text" id="search" placeholder="Search files by name..." onkeyup="searchFiles()">
            </div>
            
            <div class="stats">
                <div class="stat-item">📊 Total Files: <span id="totalFiles">0</span></div>
                <div class="stat-item">💾 Total Size: <span id="totalSize">0 B</span></div>
            </div>
            
            <div class="progress-bar" id="progressBar">
                <div class="progress-fill" id="progressFill"></div>
            </div>
            <p style="margin-top: 10px; color: #6c757d; font-size: 12px;">
                Max file size: 50MB (Telegram limit) • Files stored securely in Telegram
            </p>
        </div>
        
        <div class="status" id="status"></div>
        
        <table class="file-table" id="fileTable">
            <thead>
                <tr>
                    <th style="width:40px"></th>
                    <th>Name</th>
                    <th style="width:100px">Size</th>
                    <th style="width:150px">Date</th>
                    <th style="width:120px">Uploader</th>
                    <th style="width:250px">Actions</th>
                </tr>
            </thead>
            <tbody id="fileList">
                <!-- Files will be loaded here -->
            </tbody>
        </table>
    </div>

    <script>
    // Telegram Bot Token
    const BOT_TOKEN = '8337490666:AAHhTs1w57Ynqs70GP3579IHqo491LHaCl8';
    const CHAT_ID = '-1003632097565';
    let files = [];
    let isUploading = false;

    // Load files on page load
    document.addEventListener('DOMContentLoaded', loadFiles);

    function selectFile() {
        if (isUploading) {
            showStatus('Please wait for current upload to finish', 'error');
            return;
        }
        document.getElementById('fileInput').click();
    }

    async function uploadToTelegram() {
        const fileInput = document.getElementById('fileInput');
        const file = fileInput.files[0];
        
        if (!file) return;
        
        // Reset input
        fileInput.value = '';
        
        // Check file size (Telegram limit: 50MB for bots)
        if (file.size > 50 * 1024 * 1024) {
            showStatus('File too large. Max: 50MB', 'error');
            return;
        }
        
        // Start upload
        isUploading = true;
        const uploadBtn = document.getElementById('uploadBtn');
        const progressBar = document.getElementById('progressBar');
        const progressFill = document.getElementById('progressFill');
        
        uploadBtn.disabled = true;
        uploadBtn.innerHTML = '<span class="loading"></span> Uploading...';
        progressBar.style.display = 'block';
        progressFill.style.width = '0%';
        
        // Prepare form data for Telegram
        const formData = new FormData();
        formData.append('chat_id', CHAT_ID);
        formData.append('document', file);
        
        // Show progress
        let progress = 0;
        const progressInterval = setInterval(() => {
            progress += 5;
            if (progress > 90) progress = 90;
            progressFill.style.width = progress + '%';
        }, 200);
        
        try {
            // Upload directly to Telegram
            const response = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendDocument`, {
                method: 'POST',
                body: formData
            });
            
            clearInterval(progressInterval);
            progressFill.style.width = '100%';
            
            const result = await response.json();
            
            if (result.ok) {
                const fileId = result.result.document.file_id;
                const fileSize = result.result.document.file_size;
                
                // Save metadata to our server
                const metadata = new FormData();
                metadata.append('name', file.name);
                metadata.append('file_id', fileId);
                metadata.append('size', fileSize);
                
                const saveResponse = await fetch('?action=add', {
                    method: 'POST',
                    body: metadata
                });
                
                const saveResult = await saveResponse.json();
                
                if (saveResult.ok) {
                    showStatus('✅ File uploaded successfully: ' + file.name, 'success');
                    await loadFiles();
                } else {
                    showStatus('⚠️ File uploaded but metadata not saved', 'error');
                }
            } else {
                showStatus('❌ Telegram upload failed: ' + (result.description || 'Unknown error'), 'error');
            }
        } catch (error) {
            clearInterval(progressInterval);
            showStatus('❌ Upload error: ' + error.message, 'error');
        } finally {
            // Reset UI
            setTimeout(() => {
                progressBar.style.display = 'none';
                progressFill.style.width = '0%';
                uploadBtn.disabled = false;
                uploadBtn.textContent = '📁 Upload File';
                isUploading = false;
            }, 1000);
        }
    }

    async function loadFiles() {
        try {
            const response = await fetch('?action=list');
            const result = await response.json();
            
            if (result.ok) {
                files = result.files;
                displayFiles();
                updateStats();
            }
        } catch (error) {
            console.error('Error loading files:', error);
            document.getElementById('fileList').innerHTML = 
                '<tr><td colspan="6" class="empty">Error loading files. Please refresh.</td></tr>';
        }
    }

    function displayFiles() {
        const container = document.getElementById('fileList');
        
        if (files.length === 0) {
            container.innerHTML = '<tr><td colspan="6" class="empty">No files yet. Upload your first file!</td></tr>';
            return;
        }
        
        let html = '';
        
        files.forEach(file => {
            const icon = getFileIcon(file.name);
            const size = formatFileSize(file.size);
            const date = formatDate(file.date);
            const uploader = file.uploader || 'Unknown';
            
            html += `
                <tr>
                    <td class="file-icon">${icon}</td>
                    <td class="file-name" title="${file.name}">${file.name}</td>
                    <td>${size}</td>
                    <td>${date}</td>
                    <td>${uploader}</td>
                    <td class="file-actions">
                        <button class="action-btn" onclick="downloadFile('${file.id}')" title="Download">⬇️</button>
                        <button class="action-btn" onclick="shareFile('${file.id}')" title="Share">🔗</button>
                        <button class="action-btn" onclick="previewFile('${file.id}')" title="Preview">👁️</button>
                        <button class="action-btn" onclick="renameFile('${file.id}')" title="Rename">✏️</button>
                        <button class="action-btn" onclick="deleteFile('${file.id}')" title="Delete">🗑️</button>
                    </td>
                </tr>
            `;
        });
        
        container.innerHTML = html;
    }

    function updateStats() {
        const totalFiles = files.length;
        let totalSize = 0;
        
        files.forEach(file => {
            totalSize += file.size;
        });
        
        document.getElementById('totalFiles').textContent = totalFiles;
        document.getElementById('totalSize').textContent = formatFileSize(totalSize);
    }

    function getFileIcon(filename) {
        const ext = filename.split('.').pop().toLowerCase();
        const icons = {
            'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️',
            'pdf': '📕', 'doc': '📘', 'docx': '📘',
            'xls': '📗', 'xlsx': '📗', 'txt': '📄',
            'zip': '🗜️', 'rar': '🗜️', 'mp4': '🎬',
            'mp3': '🎵', 'wav': '🎵', 'php': '📝',
            'js': '📝', 'html': '📝', 'css': '📝'
        };
        return icons[ext] || '📄';
    }

    function formatFileSize(bytes) {
        if (!bytes) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    function formatDate(dateString) {
        try {
            const date = new Date(dateString);
            const now = new Date();
            const diff = now - date;
            
            if (date.toDateString() === now.toDateString()) {
                return 'Today ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
            }
            
            if (diff < 7 * 24 * 60 * 60 * 1000) {
                const days = Math.floor(diff / (24 * 60 * 60 * 1000));
                return days + ' days ago';
            }
            
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        } catch {
            return 'Unknown';
        }
    }

    async function downloadFile(fileId) {
        const file = files.find(f => f.id === fileId);
        if (!file) return;
        
        // Show loading
        showStatus('🔄 Getting download link...', 'success');
        
        try {
            // Get download URL from server
            const response = await fetch(`?action=get_download_url&id=${fileId}`);
            const result = await response.json();
            
            if (result.ok && result.url) {
                // Open download in new tab
                window.open(result.url, '_blank');
                showStatus('📥 Download started: ' + file.name, 'success');
            } else {
                showStatus('❌ Could not get download link', 'error');
            }
        } catch (error) {
            // Fallback: Use direct download endpoint
            window.open(`?download=${fileId}&id=${file.file_id}`, '_blank');
            showStatus('📥 Download started: ' + file.name, 'success');
        }
    }

    async function previewFile(fileId) {
        const file = files.find(f => f.id === fileId);
        if (!file) return;
        
        const ext = file.name.split('.').pop().toLowerCase();
        const isImage = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'].includes(ext);
        
        if (isImage) {
            // Get image URL first
            const response = await fetch(`?action=get_download_url&id=${fileId}`);
            const result = await response.json();
            
            if (result.ok && result.url) {
                window.open(result.url, '_blank');
                showStatus('👁️ Opening image preview...', 'success');
            } else {
                showStatus('❌ Could not load image', 'error');
            }
        } else {
            // For non-images, show info in alert
            const info = `
File: ${file.name}
Size: ${formatFileSize(file.size)}
Uploaded: ${formatDate(file.date)}
Uploader: ${file.uploader || 'Unknown'}

To download: Click the download button.
            `;
            alert(info);
        }
    }

    async function shareFile(fileId) {
        try {
            const response = await fetch(`?action=share&id=${fileId}`);
            const result = await response.json();
            
            if (result.ok) {
                // Copy to clipboard
                navigator.clipboard.writeText(result.url).then(() => {
                    showStatus('🔗 Share link copied to clipboard!', 'success');
                }).catch(() => {
                    // Fallback
                    const input = document.createElement('input');
                    input.value = result.url;
                    document.body.appendChild(input);
                    input.select();
                    document.execCommand('copy');
                    document.body.removeChild(input);
                    showStatus('🔗 Share link copied!', 'success');
                });
            }
        } catch (error) {
            showStatus('❌ Failed to create share link', 'error');
        }
    }

    async function renameFile(fileId) {
        const file = files.find(f => f.id === fileId);
        if (!file) return;
        
        const newName = prompt('Enter new name:', file.name);
        if (!newName || newName === file.name) return;
        
        try {
            const response = await fetch(`?action=rename&id=${fileId}&name=${encodeURIComponent(newName)}`);
            const result = await response.json();
            
            if (result.ok) {
                showStatus('✏️ File renamed to: ' + newName, 'success');
                await loadFiles();
            }
        } catch (error) {
            showStatus('❌ Failed to rename file', 'error');
        }
    }

    async function deleteFile(fileId) {
        const file = files.find(f => f.id === fileId);
        if (!file) return;
        
        if (!confirm(`Are you sure you want to delete "${file.name}"?\nThis action cannot be undone.`)) return;
        
        try {
            const response = await fetch(`?action=delete&id=${fileId}`);
            const result = await response.json();
            
            if (result.ok) {
                showStatus('🗑️ File deleted: ' + file.name, 'success');
                await loadFiles();
            }
        } catch (error) {
            showStatus('❌ Failed to delete file', 'error');
        }
    }

    function searchFiles() {
        const searchTerm = document.getElementById('search').value.toLowerCase();
        const rows = document.querySelectorAll('#fileList tr');
        
        let visibleCount = 0;
        
        rows.forEach(row => {
            if (row.classList.contains('empty')) return;
            
            const fileName = row.querySelector('.file-name').textContent.toLowerCase();
            if (fileName.includes(searchTerm)) {
                row.style.display = '';
                visibleCount++;
            } else {
                row.style.display = 'none';
            }
        });
        
        // Show message if no results
        if (visibleCount === 0 && searchTerm !== '') {
            if (!document.querySelector('.no-results')) {
                const container = document.getElementById('fileList');
                container.innerHTML += `
                    <tr class="no-results"><td colspan="6" class="empty">No files match "${searchTerm}"</td></tr>
                `;
            }
        }
    }

    function showStatus(message, type) {
        const status = document.getElementById('status');
        status.textContent = message;
        status.className = 'status ' + type;
        
        setTimeout(() => {
            status.className = 'status';
        }, 3000);
    }

    // Drag and drop support
    document.addEventListener('dragover', (e) => {
        e.preventDefault();
        document.body.style.backgroundColor = '#e8f4f8';
    });
    
    document.addEventListener('dragleave', (e) => {
        e.preventDefault();
        document.body.style.backgroundColor = '';
    });
    
    document.addEventListener('drop', (e) => {
        e.preventDefault();
        document.body.style.backgroundColor = '';
        
        if (isUploading) {
            showStatus('Please wait for current upload to finish', 'error');
            return;
        }
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            document.getElementById('fileInput').files = files;
            uploadToTelegram();
        }
    });
    </script>
</body>
</html>
