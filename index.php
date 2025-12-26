<?php
// ==============================================
// TELEDRIVE - Unlimited Storage via Telegram
// Single File Version by BroDev
// ==============================================

// ================= CONFIG =====================
session_start();
header('Content-Type: text/html; charset=utf-8');

// TELEGRAM CONFIG (GANTI DENGAN MILIKMU!)
define('BOT_TOKEN', '8337490666:AAHhTs1w57Ynqs70GP3579IHqo491LHaCl8');
define('CHANNEL_ID', '-1003632097565');
define('TELEGRAM_API', 'https://api.telegram.org/bot');

// DATABASE CONFIG
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'teledrive');

// FILE CONFIG
define('MAX_FILE_SIZE', 2000 * 1024 * 1024); // 2GB untuk premium
define('TEMP_DIR', __DIR__ . '/temp/');
define('ENCRYPT_KEY', 'your-secret-key-here-change-me');

// Create temp dir if not exists
if (!file_exists(TEMP_DIR)) {
    mkdir(TEMP_DIR, 0777, true);
}

// ================= DATABASE ===================
class Database {
    private $conn;
    
    public function __construct() {
        $this->conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        
        if ($this->conn->connect_error) {
            // Auto create database and tables
            $this->createDatabase();
        }
        
        $this->createTables();
    }
    
    private function createDatabase() {
        $tempConn = new mysqli(DB_HOST, DB_USER, DB_PASS);
        $tempConn->query("CREATE DATABASE IF NOT EXISTS " . DB_NAME . " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        $tempConn->select_db(DB_NAME);
        $this->conn = $tempConn;
    }
    
    private function createTables() {
        $sql = "
        CREATE TABLE IF NOT EXISTS devices (
            fingerprint VARCHAR(64) PRIMARY KEY,
            ip_address VARCHAR(45),
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS files (
            id INT AUTO_INCREMENT PRIMARY KEY,
            fingerprint VARCHAR(64),
            file_name VARCHAR(255),
            file_size BIGINT,
            telegram_file_id VARCHAR(255),
            telegram_message_id INT,
            parent_id INT DEFAULT NULL,
            is_folder BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_trashed BOOLEAN DEFAULT FALSE,
            INDEX idx_fingerprint (fingerprint),
            INDEX idx_parent (parent_id)
        );
        ";
        
        $this->conn->multi_query($sql);
        while ($this->conn->next_result()) {;} // Clear multi_query buffer
    }
    
    public function registerDevice($fingerprint, $ip, $userAgent) {
        $stmt = $this->conn->prepare("
            INSERT INTO devices (fingerprint, ip_address, user_agent) 
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE 
            ip_address = VALUES(ip_address),
            user_agent = VALUES(user_agent),
            last_seen = CURRENT_TIMESTAMP
        ");
        $stmt->bind_param("sss", $fingerprint, $ip, $userAgent);
        return $stmt->execute();
    }
    
    public function saveFile($fingerprint, $fileName, $fileSize, $telegramFileId, $telegramMessageId, $parentId = null) {
        $stmt = $this->conn->prepare("
            INSERT INTO files (fingerprint, file_name, file_size, telegram_file_id, telegram_message_id, parent_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        $stmt->bind_param("ssisii", $fingerprint, $fileName, $fileSize, $telegramFileId, $telegramMessageId, $parentId);
        return $stmt->execute();
    }
    
    public function createFolder($fingerprint, $folderName, $parentId = null) {
        $stmt = $this->conn->prepare("
            INSERT INTO files (fingerprint, file_name, is_folder, parent_id)
            VALUES (?, ?, TRUE, ?)
        ");
        $stmt->bind_param("ssi", $fingerprint, $folderName, $parentId);
        return $stmt->execute();
    }
    
    public function getUserFiles($fingerprint, $parentId = null, $trashed = false) {
        $query = "
            SELECT * FROM files 
            WHERE fingerprint = ? 
            AND parent_id " . ($parentId === null ? "IS NULL" : "= ?") . "
            AND is_trashed = ?
            ORDER BY is_folder DESC, file_name ASC
        ";
        
        $stmt = $this->conn->prepare($query);
        
        if ($parentId === null) {
            $stmt->bind_param("si", $fingerprint, $trashed);
        } else {
            $stmt->bind_param("sii", $fingerprint, $parentId, $trashed);
        }
        
        $stmt->execute();
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    }
    
    public function getFileInfo($fileId, $fingerprint) {
        $stmt = $this->conn->prepare("
            SELECT * FROM files 
            WHERE id = ? AND fingerprint = ?
        ");
        $stmt->bind_param("is", $fileId, $fingerprint);
        $stmt->execute();
        return $stmt->get_result()->fetch_assoc();
    }
    
    public function moveToTrash($fileId, $fingerprint) {
        $stmt = $this->conn->prepare("
            UPDATE files SET is_trashed = TRUE 
            WHERE id = ? AND fingerprint = ?
        ");
        $stmt->bind_param("is", $fileId, $fingerprint);
        return $stmt->execute();
    }
    
    public function deletePermanently($fileId, $fingerprint) {
        // Get Telegram file ID first (optional: delete from Telegram)
        $file = $this->getFileInfo($fileId, $fingerprint);
        
        $stmt = $this->conn->prepare("
            DELETE FROM files 
            WHERE id = ? AND fingerprint = ?
        ");
        $stmt->bind_param("is", $fileId, $fingerprint);
        return $stmt->execute();
    }
}

// ================= TELEGRAM HANDLER ============
class TelegramHandler {
    public static function uploadFile($filePath, $fileName) {
        $url = TELEGRAM_API . BOT_TOKEN . '/sendDocument';
        
        $postFields = [
            'chat_id' => CHANNEL_ID,
            'document' => new CURLFile($filePath),
            'caption' => substr($fileName, 0, 200)
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postFields);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_TIMEOUT, 300); // 5 minutes timeout
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode === 200) {
            $result = json_decode($response, true);
            if ($result['ok']) {
                return [
                    'success' => true,
                    'file_id' => $result['result']['document']['file_id'],
                    'message_id' => $result['result']['message_id'],
                    'file_size' => $result['result']['document']['file_size']
                ];
            }
        }
        
        return ['success' => false, 'error' => 'Telegram upload failed'];
    }
    
    public static function getDownloadLink($fileId) {
        // Get file path from Telegram
        $url = TELEGRAM_API . BOT_TOKEN . '/getFile?file_id=' . urlencode($fileId);
        $response = @file_get_contents($url);
        
        if ($response) {
            $result = json_decode($response, true);
            if ($result['ok']) {
                $filePath = $result['result']['file_path'];
                return 'https://api.telegram.org/file/bot' . BOT_TOKEN . '/' . $filePath;
            }
        }
        
        return false;
    }
    
    public static function deleteFromTelegram($messageId) {
        // Optional: Delete message from channel
        $url = TELEGRAM_API . BOT_TOKEN . '/deleteMessage';
        $postData = [
            'chat_id' => CHANNEL_ID,
            'message_id' => $messageId
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);
        
        return json_decode($response, true);
    }
}

// ================= DEVICE FINGERPRINT ==========
class DeviceFingerprint {
    public static function generate() {
        // Get client info
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        
        // Generate fingerprint components
        $components = [
            'ip' => $ip,
            'ua' => $userAgent,
            'lang' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            'timezone' => isset($_POST['tz']) ? $_POST['tz'] : 'UTC',
            'screen' => isset($_POST['screen']) ? $_POST['screen'] : '0x0',
            'canvas' => isset($_POST['canvas']) ? $_POST['canvas'] : ''
        ];
        
        // Create unique fingerprint
        $fingerprintString = implode('|', $components);
        $fingerprint = hash('sha256', $fingerprintString);
        
        // Also check localStorage fingerprint from JS
        if (isset($_POST['local_storage_fp'])) {
            $fingerprint = hash('sha256', $fingerprint . $_POST['local_storage_fp']);
        }
        
        return [
            'fingerprint' => $fingerprint,
            'ip' => $ip,
            'user_agent' => $userAgent
        ];
    }
}

// ================= API ENDPOINTS ===============
$db = new Database();

// Handle API requests
if (isset($_GET['action'])) {
    $fingerprintData = DeviceFingerprint::generate();
    $fingerprint = $fingerprintData['fingerprint'];
    
    // Register/update device
    $db->registerDevice(
        $fingerprint,
        $fingerprintData['ip'],
        $fingerprintData['user_agent']
    );
    
    switch ($_GET['action']) {
        case 'register_device':
            echo json_encode([
                'success' => true,
                'fingerprint' => $fingerprint,
                'message' => 'Device registered'
            ]);
            exit;
            
        case 'upload_file':
            if (isset($_FILES['file'])) {
                $file = $_FILES['file'];
                $parentId = isset($_POST['parent_id']) ? intval($_POST['parent_id']) : null;
                
                // Validate file
                if ($file['error'] !== UPLOAD_ERR_OK) {
                    echo json_encode(['success' => false, 'error' => 'Upload error']);
                    exit;
                }
                
                if ($file['size'] > MAX_FILE_SIZE) {
                    echo json_encode(['success' => false, 'error' => 'File too large']);
                    exit;
                }
                
                // Upload to Telegram
                $tempFile = TEMP_DIR . uniqid() . '_' . basename($file['name']);
                move_uploaded_file($file['tmp_name'], $tempFile);
                
                $uploadResult = TelegramHandler::uploadFile($tempFile, $file['name']);
                
                if ($uploadResult['success']) {
                    // Save to database
                    $db->saveFile(
                        $fingerprint,
                        $file['name'],
                        $uploadResult['file_size'],
                        $uploadResult['file_id'],
                        $uploadResult['message_id'],
                        $parentId
                    );
                    
                    echo json_encode([
                        'success' => true,
                        'file_id' => $uploadResult['file_id'],
                        'file_size' => $uploadResult['file_size']
                    ]);
                } else {
                    echo json_encode(['success' => false, 'error' => 'Upload failed']);
                }
                
                // Cleanup temp file
                @unlink($tempFile);
            }
            exit;
            
        case 'create_folder':
            $folderName = $_POST['folder_name'] ?? 'New Folder';
            $parentId = isset($_POST['parent_id']) ? intval($_POST['parent_id']) : null;
            
            if ($db->createFolder($fingerprint, $folderName, $parentId)) {
                echo json_encode(['success' => true]);
            } else {
                echo json_encode(['success' => false]);
            }
            exit;
            
        case 'list_files':
            $parentId = isset($_GET['parent_id']) ? intval($_GET['parent_id']) : null;
            $trashed = isset($_GET['trashed']) ? boolval($_GET['trashed']) : false;
            
            $files = $db->getUserFiles($fingerprint, $parentId, $trashed);
            echo json_encode(['success' => true, 'files' => $files]);
            exit;
            
        case 'download_file':
            $fileId = intval($_GET['file_id']);
            $fileInfo = $db->getFileInfo($fileId, $fingerprint);
            
            if ($fileInfo && !$fileInfo['is_folder']) {
                $downloadLink = TelegramHandler::getDownloadLink($fileInfo['telegram_file_id']);
                if ($downloadLink) {
                    header("Location: $downloadLink");
                    exit;
                }
            }
            echo 'File not found';
            exit;
            
        case 'delete_file':
            $fileId = intval($_POST['file_id']);
            $permanent = isset($_POST['permanent']) ? boolval($_POST['permanent']) : false;
            
            if ($permanent) {
                $success = $db->deletePermanently($fileId, $fingerprint);
            } else {
                $success = $db->moveToTrash($fileId, $fingerprint);
            }
            
            echo json_encode(['success' => $success]);
            exit;
    }
}

// ================= HTML UI =====================
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudDrive - Unlimited Free Storage</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        }

        :root {
            --primary: #0067d0;
            --primary-dark: #0050a0;
            --sidebar-width: 260px;
            --topbar-height: 70px;
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        body {
            background: #f5f5f5;
            display: flex;
            height: 100vh;
            overflow: hidden;
            transition: var(--transition);
        }

        /* ===== SIDEBAR ===== */
        .sidebar {
            width: var(--sidebar-width);
            background: white;
            border-right: 1px solid #e1e1e1;
            display: flex;
            flex-direction: column;
            height: 100vh;
            transition: var(--transition);
            position: fixed;
            left: 0;
            z-index: 1000;
            box-shadow: 2px 0 10px rgba(0,0,0,0.05);
        }

        .logo {
            padding: 22px 20px;
            display: flex;
            align-items: center;
            gap: 12px;
            border-bottom: 1px solid #e1e1e1;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
        }

        .logo i {
            font-size: 28px;
        }

        .logo h1 {
            font-size: 24px;
            font-weight: 600;
        }

        .logo .tagline {
            font-size: 12px;
            opacity: 0.9;
            margin-left: auto;
        }

        .user-info {
            padding: 20px;
            display: flex;
            align-items: center;
            gap: 12px;
            border-bottom: 1px solid #e1e1e1;
        }

        .avatar {
            width: 40px;
            height: 40px;
            background: var(--primary);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 18px;
        }

        .user-details {
            flex: 1;
            overflow: hidden;
        }

        .device-id {
            font-weight: 600;
            color: #333;
            font-size: 14px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            display: block;
        }

        .device-info {
            font-size: 12px;
            color: #666;
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .nav-menu {
            flex: 1;
            padding: 20px 0;
            overflow-y: auto;
        }

        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 14px 20px;
            text-decoration: none;
            color: #555;
            transition: var(--transition);
            font-size: 14px;
            border-left: 3px solid transparent;
        }

        .nav-item i {
            width: 20px;
            text-align: center;
            font-size: 16px;
        }

        .nav-item:hover {
            background: #f0f7ff;
            color: var(--primary);
            border-left-color: var(--primary);
        }

        .nav-item.active {
            background: #f0f7ff;
            color: var(--primary);
            border-left-color: var(--primary);
            font-weight: 600;
        }

        .nav-item.badge {
            position: relative;
        }

        .badge-count {
            position: absolute;
            right: 20px;
            background: var(--primary);
            color: white;
            border-radius: 10px;
            padding: 2px 8px;
            font-size: 12px;
        }

        .storage-info {
            padding: 20px;
            background: #f8f9fa;
            border-top: 1px solid #e1e1e1;
        }

        .storage-text {
            display: flex;
            justify-content: space-between;
            font-size: 13px;
            margin-bottom: 8px;
            color: #666;
        }

        .storage-text .free {
            color: var(--primary);
            font-weight: 600;
        }

        .progress-bar {
            height: 6px;
            background: #e0e0e0;
            border-radius: 3px;
            overflow: hidden;
        }

        .progress {
            height: 100%;
            background: linear-gradient(90deg, var(--primary) 0%, #00c6ff 100%);
            border-radius: 3px;
            width: 35%;
            transition: width 0.5s ease;
        }

        /* ===== SIDEBAR TOGGLE ===== */
        .sidebar-toggle {
            position: fixed;
            top: 20px;
            left: 20px;
            z-index: 1001;
            background: white;
            border: 1px solid #ddd;
            border-radius: 50%;
            width: 45px;
            height: 45px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: var(--transition);
            display: none;
        }

        .sidebar-toggle:hover {
            background: #f5f5f5;
            transform: scale(1.05);
        }

        .sidebar-toggle i {
            font-size: 20px;
            color: #333;
        }

        /* ===== MAIN CONTENT ===== */
        .main-content {
            flex: 1;
            margin-left: var(--sidebar-width);
            transition: var(--transition);
            height: 100vh;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }

        .top-bar {
            height: var(--topbar-height);
            background: white;
            border-bottom: 1px solid #e1e1e1;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 25px;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .breadcrumb {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 15px;
        }

        .breadcrumb a {
            text-decoration: none;
            color: #666;
            padding: 5px 10px;
            border-radius: 4px;
            transition: var(--transition);
        }

        .breadcrumb a:hover {
            background: #f0f0f0;
            color: var(--primary);
        }

        .breadcrumb .separator {
            color: #999;
            font-size: 12px;
        }

        .actions {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: var(--transition);
            background: #f0f0f0;
            color: #333;
        }

        .btn:hover {
            background: #e0e0e0;
            transform: translateY(-1px);
        }

        .btn-primary {
            background: var(--primary);
            color: white;
        }

        .btn-primary:hover {
            background: var(--primary-dark);
            box-shadow: 0 4px 12px rgba(0,103,208,0.2);
        }

        .search-box {
            position: relative;
            width: 250px;
        }

        .search-box i {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #999;
        }

        .search-box input {
            width: 100%;
            padding: 12px 20px 12px 45px;
            border: 1px solid #ddd;
            border-radius: 30px;
            font-size: 14px;
            transition: var(--transition);
            background: #f8f9fa;
        }

        .search-box input:focus {
            outline: none;
            border-color: var(--primary);
            background: white;
            box-shadow: 0 0 0 3px rgba(0,103,208,0.1);
        }

        /* ===== FILE GRID ===== */
        .file-grid {
            flex: 1;
            padding: 25px;
            overflow-y: auto;
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 20px;
            align-content: start;
        }

        .file-item {
            background: white;
            border: 1px solid #e8e8e8;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            transition: var(--transition);
            cursor: pointer;
            position: relative;
        }

        .file-item:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            border-color: var(--primary);
        }

        .file-icon {
            font-size: 48px;
            color: var(--primary);
            margin-bottom: 15px;
        }

        .file-icon.folder {
            color: #ffb300;
        }

        .file-name {
            font-weight: 600;
            font-size: 14px;
            color: #333;
            margin-bottom: 5px;
            word-break: break-word;
            max-height: 40px;
            overflow: hidden;
            text-overflow: ellipsis;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
        }

        .file-size {
            font-size: 12px;
            color: #666;
        }

        .file-date {
            font-size: 11px;
            color: #999;
            margin-top: 5px;
        }

        .file-actions {
            position: absolute;
            top: 10px;
            right: 10px;
            opacity: 0;
            transition: var(--transition);
        }

        .file-item:hover .file-actions {
            opacity: 1;
        }

        .file-action-btn {
            background: white;
            border: 1px solid #ddd;
            border-radius: 4px;
            width: 30px;
            height: 30px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            margin-bottom: 5px;
            transition: var(--transition);
        }

        .file-action-btn:hover {
            background: var(--primary);
            color: white;
            border-color: var(--primary);
        }

        /* ===== CONTEXT MENU ===== */
        .context-menu {
            position: fixed;
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
            min-width: 200px;
            z-index: 10000;
            display: none;
        }

        .context-menu a {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 12px 20px;
            text-decoration: none;
            color: #333;
            font-size: 14px;
            transition: var(--transition);
        }

        .context-menu a:hover {
            background: #f0f7ff;
            color: var(--primary);
        }

        .context-menu hr {
            border: none;
            height: 1px;
            background: #eee;
            margin: 5px 0;
        }

        /* ===== UPLOAD MODAL ===== */
        .upload-modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 10000;
        }

        .upload-content {
            background: white;
            border-radius: 15px;
            width: 90%;
            max-width: 500px;
            max-height: 80vh;
            overflow-y: auto;
        }

        .upload-header {
            padding: 20px;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .upload-list {
            padding: 20px;
        }

        .upload-item {
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 15px;
            border: 1px solid #eee;
            border-radius: 8px;
            margin-bottom: 10px;
        }

        .upload-progress {
            flex: 1;
            height: 6px;
            background: #eee;
            border-radius: 3px;
            overflow: hidden;
        }

        .upload-progress-bar {
            height: 100%;
            background: linear-gradient(90deg, var(--primary) 0%, #00c6ff 100%);
            border-radius: 3px;
            width: 0%;
            transition: width 0.3s ease;
        }

        /* ===== RESPONSIVE ===== */
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
            }
            
            .sidebar.active {
                transform: translateX(0);
            }
            
            .sidebar-toggle {
                display: flex;
            }
            
            .main-content {
                margin-left: 0;
            }
            
            .file-grid {
                grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
                padding: 15px;
                gap: 15px;
            }
            
            .top-bar {
                padding: 0 15px;
                flex-wrap: wrap;
                height: auto;
                padding: 15px;
            }
            
            .actions {
                order: -1;
                width: 100%;
                margin-bottom: 15px;
                justify-content: space-between;
            }
            
            .search-box {
                width: 100%;
                margin-top: 15px;
            }
        }

        @media (max-width: 480px) {
            .file-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .btn span {
                display: none;
            }
            
            .btn {
                padding: 10px;
            }
        }

        /* ===== ANIMATIONS ===== */
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .file-item {
            animation: slideIn 0.3s ease backwards;
        }

        /* ===== LOADING ===== */
        .loading {
            text-align: center;
            padding: 50px;
            color: #666;
        }

        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid var(--primary);
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* ===== DRAG & DROP ===== */
        .drop-zone {
            border: 2px dashed #ccc;
            border-radius: 10px;
            padding: 40px;
            text-align: center;
            color: #666;
            transition: var(--transition);
            margin-bottom: 20px;
            cursor: pointer;
        }

        .drop-zone:hover, .drop-zone.dragover {
            border-color: var(--primary);
            background: #f0f7ff;
            color: var(--primary);
        }
    </style>
</head>
<body>
    <!-- Sidebar Toggle Button (Mobile) -->
    <div class="sidebar-toggle" id="sidebarToggle">
        <i class="fas fa-bars"></i>
    </div>

    <!-- Sidebar -->
    <div class="sidebar" id="sidebar">
        <div class="logo">
            <i class="fas fa-cloud"></i>
            <h1>CloudDrive</h1>
            <span class="tagline">UNLIMITED</span>
        </div>
        
        <div class="user-info">
            <div class="avatar" id="deviceAvatar">C</div>
            <div class="user-details">
                <span class="device-id" id="deviceId">Loading device ID...</span>
                <div class="device-info">
                    <i class="fas fa-desktop"></i>
                    <span id="deviceType">This Device</span>
                </div>
            </div>
        </div>
        
        <div class="nav-menu">
            <a href="#" class="nav-item active" data-view="my-files">
                <i class="fas fa-folder"></i> My Files
            </a>
            <a href="#" class="nav-item" data-view="recent">
                <i class="fas fa-clock"></i> Recent
                <span class="badge-count">12</span>
            </a>
            <a href="#" class="nav-item" data-view="photos">
                <i class="fas fa-images"></i> Photos
            </a>
            <a href="#" class="nav-item" data-view="documents">
                <i class="fas fa-file-alt"></i> Documents
            </a>
            <a href="#" class="nav-item" data-view="shared">
                <i class="fas fa-share-alt"></i> Shared
            </a>
            <a href="#" class="nav-item" data-view="trash">
                <i class="fas fa-trash"></i> Trash
                <span class="badge-count" id="trashCount">0</span>
            </a>
        </div>
        
        <div class="storage-info">
            <div class="storage-text">
                <span>Storage</span>
                <span class="free">UNLIMITED</span>
            </div>
            <div class="progress-bar">
                <div class="progress" style="width: 35%"></div>
            </div>
        </div>
    </div>
    
    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Bar -->
        <header class="top-bar">
            <div class="breadcrumb" id="breadcrumb">
                <a href="#" data-path="root">My Files</a>
            </div>
            
            <div class="actions">
                <button class="btn" onclick="createFolder()">
                    <i class="fas fa-folder-plus"></i> <span>New Folder</span>
                </button>
                <div class="upload-btn">
                    <input type="file" id="fileUpload" multiple style="display: none" onchange="handleFileSelect(this.files)">
                    <button class="btn btn-primary" onclick="document.getElementById('fileUpload').click()">
                        <i class="fas fa-upload"></i> <span>Upload</span>
                    </button>
                </div>
                <div class="search-box">
                    <i class="fas fa-search"></i>
                    <input type="text" placeholder="Search files..." id="searchInput">
                </div>
            </div>
        </header>
        
        <!-- Drop Zone -->
        <div class="drop-zone" id="dropZone" onclick="document.getElementById('fileUpload').click()">
            <i class="fas fa-cloud-upload-alt" style="font-size: 48px; margin-bottom: 20px;"></i>
            <h3>Drag & Drop files here</h3>
            <p>Or click to browse files (Max 2GB per file)</p>
        </div>
        
        <!-- File Grid -->
        <div class="file-grid" id="fileGrid">
            <div class="loading">
                <div class="spinner"></div>
                <p>Loading your files...</p>
            </div>
        </div>
    </div>
    
    <!-- Context Menu -->
    <div class="context-menu" id="contextMenu">
        <a href="#" onclick="openFile()"><i class="fas fa-eye"></i> Open</a>
        <a href="#" onclick="downloadFile()"><i class="fas fa-download"></i> Download</a>
        <a href="#" onclick="renameFile()"><i class="fas fa-edit"></i> Rename</a>
        <a href="#" onclick="shareFile()"><i class="fas fa-share-alt"></i> Share</a>
        <hr>
        <a href="#" onclick="deleteFile()" style="color: #e53935;"><i class="fas fa-trash"></i> Move to Trash</a>
    </div>
    
    <!-- Upload Modal -->
    <div class="upload-modal" id="uploadModal">
        <div class="upload-content">
            <div class="upload-header">
                <h3>Uploading Files</h3>
                <button class="btn" onclick="closeUploadModal()">Close</button>
            </div>
            <div class="upload-list" id="uploadList">
                <!-- Upload items will be added here -->
            </div>
        </div>
    </div>

    <script>
        // ================== GLOBAL VARIABLES ==================
        let deviceFingerprint = '';
        let currentFolder = null;
        let selectedFile = null;
        let contextMenuVisible = false;
        let uploadQueue = [];
        let isUploading = false;

        // ================== DEVICE FINGERPRINT ==================
        async function generateFingerprint() {
            // Get browser fingerprint components
            const components = [];
            
            // 1. Canvas fingerprint
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            if (ctx) {
                ctx.textBaseline = "top";
                ctx.font = "16px Arial";
                ctx.fillStyle = "#f60";
                ctx.fillRect(125, 1, 62, 20);
                ctx.fillStyle = "#069";
                ctx.fillText("TeleDrive", 2, 15);
                components.push(canvas.toDataURL());
            }
            
            // 2. Screen properties
            components.push(`${screen.width}x${screen.height}`);
            components.push(screen.colorDepth);
            components.push(navigator.hardwareConcurrency || 'unknown');
            
            // 3. Browser properties
            components.push(navigator.userAgent);
            components.push(navigator.language);
            components.push(new Date().getTimezoneOffset());
            components.push(navigator.platform);
            components.push(navigator.vendor || 'unknown');
            
            // 4. Performance timing
            if (performance && performance.memory) {
                components.push(performance.memory.jsHeapSizeLimit);
            }
            
            // 5. Check localStorage for existing fingerprint
            let storedFingerprint = localStorage.getItem('device_fingerprint');
            
            if (!storedFingerprint) {
                // Generate new fingerprint
                const fingerprintString = components.join('::');
                const encoder = new TextEncoder();
                const data = encoder.encode(fingerprintString);
                const hashBuffer = await crypto.subtle.digest('SHA-256', data);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                storedFingerprint = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                localStorage.setItem('device_fingerprint', storedFingerprint);
            }
            
            deviceFingerprint = storedFingerprint;
            
            // Update UI
            document.getElementById('deviceId').textContent = 
                'Device: ' + storedFingerprint.substring(0, 8) + '...';
            document.getElementById('deviceAvatar').textContent = 
                storedFingerprint.substring(0, 1).toUpperCase();
            
            // Register device with server
            await fetch('?action=register_device', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: new URLSearchParams({
                    local_storage_fp: storedFingerprint,
                    tz: new Date().getTimezoneOffset(),
                    screen: `${screen.width}x${screen.height}`,
                    canvas: components[0] || ''
                })
            });
            
            return storedFingerprint;
        }

        // ================== FILE MANAGEMENT ==================
        async function loadFiles() {
            const fileGrid = document.getElementById('fileGrid');
            fileGrid.innerHTML = '<div class="loading"><div class="spinner"></div><p>Loading your files...</p></div>';
            
            try {
                const response = await fetch(`?action=list_files&parent_id=${currentFolder || ''}`);
                const data = await response.json();
                
                if (data.success) {
                    renderFiles(data.files);
                }
            } catch (error) {
                fileGrid.innerHTML = `<div class="loading" style="color: #e53935;">
                    <i class="fas fa-exclamation-triangle" style="font-size: 48px; margin-bottom: 20px;"></i>
                    <p>Failed to load files. Please refresh.</p>
                </div>`;
            }
        }

        function renderFiles(files) {
            const fileGrid = document.getElementById('fileGrid');
            
            if (files.length === 0) {
                fileGrid.innerHTML = `
                    <div style="grid-column: 1 / -1; text-align: center; padding: 50px; color: #666;">
                        <i class="fas fa-folder-open" style="font-size: 64px; margin-bottom: 20px; opacity: 0.5;"></i>
                        <h3>No files yet</h3>
                        <p>Upload files or create folders to get started</p>
                    </div>
                `;
                return;
            }
            
            let html = '';
            
            files.forEach(file => {
                const isFolder = file.is_folder == 1 || file.is_folder === true;
                const icon = isFolder ? 'fa-folder' : getFileIcon(file.file_name);
                const iconClass = isFolder ? 'folder' : '';
                const size = isFolder ? '' : formatFileSize(file.file_size);
                const date = new Date(file.created_at).toLocaleDateString();
                
                html += `
                    <div class="file-item" 
                         data-file-id="${file.id}"
                         data-is-folder="${isFolder}"
                         data-file-name="${file.file_name}"
                         oncontextmenu="showContextMenu(event, ${file.id}); return false;"
                         onclick="${isFolder ? `enterFolder(${file.id}, '${file.file_name}')` : `downloadFile(${file.id})`}">
                        
                        <div class="file-actions">
                            <div class="file-action-btn" onclick="event.stopPropagation(); shareFile(${file.id})">
                                <i class="fas fa-share-alt"></i>
                            </div>
                            <div class="file-action-btn" onclick="event.stopPropagation(); deleteFile(${file.id})">
                                <i class="fas fa-trash"></i>
                            </div>
                        </div>
                        
                        <div class="file-icon ${iconClass}">
                            <i class="fas ${icon}"></i>
                        </div>
                        
                        <div class="file-name">${file.file_name}</div>
                        <div class="file-size">${size}</div>
                        <div class="file-date">${date}</div>
                    </div>
                `;
            });
            
            fileGrid.innerHTML = html;
        }

        function getFileIcon(filename) {
            const ext = filename.split('.').pop().toLowerCase();
            const icons = {
                pdf: 'fa-file-pdf',
                doc: 'fa-file-word',
                docx: 'fa-file-word',
                txt: 'fa-file-alt',
                jpg: 'fa-file-image',
                jpeg: 'fa-file-image',
                png: 'fa-file-image',
                gif: 'fa-file-image',
                mp4: 'fa-file-video',
                mp3: 'fa-file-audio',
                zip: 'fa-file-archive',
                rar: 'fa-file-archive',
                exe: 'fa-cog',
                xls: 'fa-file-excel',
                xlsx: 'fa-file-excel',
                ppt: 'fa-file-powerpoint',
                pptx: 'fa-file-powerpoint'
            };
            return icons[ext] || 'fa-file';
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // ================== FOLDER NAVIGATION ==================
        function enterFolder(folderId, folderName) {
            currentFolder = folderId;
            
            // Update breadcrumb
            const breadcrumb = document.getElementById('breadcrumb');
            breadcrumb.innerHTML += `
                <span class="separator"><i class="fas fa-chevron-right"></i></span>
                <a href="#" data-path="${folderId}" onclick="goToFolder(${folderId})">${folderName}</a>
            `;
            
            loadFiles();
        }

        function goToFolder(folderId) {
            const breadcrumb = document.getElementById('breadcrumb');
            const links = breadcrumb.querySelectorAll('a');
            let newHtml = '';
            
            for (let link of links) {
                newHtml += link.outerHTML;
                const path = link.getAttribute('data-path');
                if (path == folderId) break;
                newHtml += '<span class="separator"><i class="fas fa-chevron-right"></i></span>';
            }
            
            breadcrumb.innerHTML = newHtml;
            currentFolder = folderId;
            loadFiles();
        }

        // ================== FILE UPLOAD ==================
        function handleFileSelect(files) {
            for (let file of files) {
                uploadQueue.push({
                    file: file,
                    id: 'file_' + Date.now() + '_' + Math.random(),
                    progress: 0
                });
            }
            
            showUploadModal();
            processUploadQueue();
        }

        async function uploadFile(fileItem) {
            return new Promise((resolve, reject) => {
                const formData = new FormData();
                formData.append('file', fileItem.file);
                formData.append('parent_id', currentFolder || '');
                
                const xhr = new XMLHttpRequest();
                
                xhr.upload.onprogress = (e) => {
                    if (e.lengthComputable) {
                        const progress = Math.round((e.loaded / e.total) * 100);
                        updateUploadProgress(fileItem.id, progress);
                    }
                };
                
                xhr.onload = () => {
                    if (xhr.status === 200) {
                        try {
                            const response = JSON.parse(xhr.responseText);
                            if (response.success) {
                                resolve(response);
                            } else {
                                reject(new Error(response.error || 'Upload failed'));
                            }
                        } catch (e) {
                            reject(new Error('Invalid response'));
                        }
                    } else {
                        reject(new Error('HTTP error ' + xhr.status));
                    }
                };
                
                xhr.onerror = () => reject(new Error('Network error'));
                
                xhr.open('POST', '?action=upload_file');
                xhr.send(formData);
            });
        }

        async function processUploadQueue() {
            if (isUploading || uploadQueue.length === 0) return;
            
            isUploading = true;
            
            while (uploadQueue.length > 0) {
                const fileItem = uploadQueue[0];
                
                try {
                    const result = await uploadFile(fileItem);
                    updateUploadStatus(fileItem.id, 'success', 'Upload complete');
                    uploadQueue.shift();
                    
                    // Reload files list after successful upload
                    loadFiles();
                } catch (error) {
                    updateUploadStatus(fileItem.id, 'error', error.message);
                    uploadQueue.shift();
                }
                
                // Small delay between uploads
                await new Promise(resolve => setTimeout(resolve, 500));
            }
            
            isUploading = false;
        }

        function showUploadModal() {
            const modal = document.getElementById('uploadModal');
            const uploadList = document.getElementById('uploadList');
            
            // Clear existing list
            uploadList.innerHTML = '';
            
            // Add current queue items
            uploadQueue.forEach(item => {
                const div = document.createElement('div');
                div.className = 'upload-item';
                div.id = `upload_${item.id}`;
                div.innerHTML = `
                    <i class="fas fa-file"></i>
                    <div style="flex: 1;">
                        <div style="font-weight: 600; margin-bottom: 5px;">${item.file.name}</div>
                        <div class="upload-progress">
                            <div class="upload-progress-bar" style="width: 0%"></div>
                        </div>
                    </div>
                    <div style="font-size: 12px; color: #666;">0%</div>
                `;
                uploadList.appendChild(div);
            });
            
            modal.style.display = 'flex';
        }

        function updateUploadProgress(uploadId, progress) {
            const element = document.getElementById(`upload_${uploadId}`);
            if (element) {
                const progressBar = element.querySelector('.upload-progress-bar');
                const percentText = element.querySelector('div:last-child');
                
                if (progressBar) progressBar.style.width = progress + '%';
                if (percentText) percentText.textContent = progress + '%';
            }
        }

        function updateUploadStatus(uploadId, status, message) {
            const element = document.getElementById(`upload_${uploadId}`);
            if (element) {
                if (status === 'success') {
                    element.innerHTML = `
                        <i class="fas fa-check" style="color: #4caf50;"></i>
                        <div style="flex: 1;">
                            <div style="font-weight: 600; margin-bottom: 5px;">${message}</div>
                        </div>
                    `;
                } else {
                    element.innerHTML = `
                        <i class="fas fa-times" style="color: #e53935;"></i>
                        <div style="flex: 1;">
                            <div style="font-weight: 600; margin-bottom: 5px;">Upload failed</div>
                            <div style="font-size: 12px; color: #e53935;">${message}</div>
                        </div>
                    `;
                }
            }
        }

        function closeUploadModal() {
            document.getElementById('uploadModal').style.display = 'none';
        }

        // ================== FILE OPERATIONS ==================
        async function createFolder() {
            const folderName = prompt('Enter folder name:', 'New Folder');
            if (!folderName || !folderName.trim()) return;
            
            try {
                const response = await fetch('?action=create_folder', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: new URLSearchParams({
                        folder_name: folderName.trim(),
                        parent_id: currentFolder || ''
                    })
                });
                
                const data = await response.json();
                if (data.success) {
                    loadFiles();
                }
            } catch (error) {
                alert('Failed to create folder');
            }
        }

        function downloadFile(fileId) {
            if (!fileId && selectedFile) {
                fileId = selectedFile;
            }
            
            if (fileId) {
                window.open(`?action=download_file&file_id=${fileId}`, '_blank');
            }
        }

        async function deleteFile(fileId) {
            if (!fileId && selectedFile) {
                fileId = selectedFile;
            }
            
            if (!fileId || !confirm('Move to Trash?')) return;
            
            try {
                const response = await fetch('?action=delete_file', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: new URLSearchParams({
                        file_id: fileId
                    })
                });
                
                const data = await response.json();
                if (data.success) {
                    loadFiles();
                }
            } catch (error) {
                alert('Failed to delete file');
            }
        }

        // ================== CONTEXT MENU ==================
        function showContextMenu(event, fileId) {
            event.preventDefault();
            selectedFile = fileId;
            
            const contextMenu = document.getElementById('contextMenu');
            contextMenu.style.display = 'block';
            contextMenu.style.left = event.pageX + 'px';
            contextMenu.style.top = event.pageY + 'px';
            contextMenuVisible = true;
            
            // Hide context menu when clicking elsewhere
            setTimeout(() => {
                document.addEventListener('click', hideContextMenu);
            }, 100);
        }

        function hideContextMenu() {
            if (contextMenuVisible) {
                document.getElementById('contextMenu').style.display = 'none';
                document.removeEventListener('click', hideContextMenu);
                contextMenuVisible = false;
            }
        }

        // ================== DRAG & DROP ==================
        function setupDragAndDrop() {
            const dropZone = document.getElementById('dropZone');
            
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                dropZone.addEventListener(eventName, preventDefaults, false);
            });
            
            function preventDefaults(e) {
                e.preventDefault();
                e.stopPropagation();
            }
            
            ['dragenter', 'dragover'].forEach(eventName => {
                dropZone.addEventListener(eventName, highlight, false);
            });
            
            ['dragleave', 'drop'].forEach(eventName => {
                dropZone.addEventListener(eventName, unhighlight, false);
            });
            
            function highlight() {
                dropZone.classList.add('dragover');
            }
            
            function unhighlight() {
                dropZone.classList.remove('dragover');
            }
            
            dropZone.addEventListener('drop', handleDrop, false);
            
            function handleDrop(e) {
                const dt = e.dataTransfer;
                const files = dt.files;
                
                if (files.length > 0) {
                    handleFileSelect(files);
                }
            }
        }

        // ================== SIDEBAR TOGGLE ==================
        function setupSidebarToggle() {
            const sidebarToggle = document.getElementById('sidebarToggle');
            const sidebar = document.getElementById('sidebar');
            
            sidebarToggle.addEventListener('click', () => {
                sidebar.classList.toggle('active');
                sidebarToggle.innerHTML = sidebar.classList.contains('active') 
                    ? '<i class="fas fa-times"></i>'
                    : '<i class="fas fa-bars"></i>';
            });
            
            // Auto-hide sidebar on mobile
            if (window.innerWidth <= 768) {
                sidebar.classList.remove('active');
            }
        }

        // ================== INITIALIZATION ==================
        async function init() {
            // Generate device fingerprint
            await generateFingerprint();
            
            // Load initial files
            loadFiles();
            
            // Setup event listeners
            setupDragAndDrop();
            setupSidebarToggle();
            
            // Setup search
            document.getElementById('searchInput').addEventListener('input', function(e) {
                // Implement search functionality here
                console.log('Search:', e.target.value);
            });
            
            // Setup navigation
            document.querySelectorAll('.nav-item').forEach(item => {
                item.addEventListener('click', function(e) {
                    e.preventDefault();
                    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
                    this.classList.add('active');
                    
                    // Handle different views
                    const view = this.getAttribute('data-view');
                    console.log('Switching to view:', view);
                    
                    if (view === 'trash') {
                        // Load trashed files
                    } else if (view === 'my-files') {
                        currentFolder = null;
                        document.getElementById('breadcrumb').innerHTML = 
                            '<a href="#" data-path="root">My Files</a>';
                        loadFiles();
                    }
                });
            });
            
            // Hide context menu on ESC
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    hideContextMenu();
                }
            });
            
            console.log('TeleDrive initialized with fingerprint:', deviceFingerprint);
        }

        // Start the application
        window.addEventListener('DOMContentLoaded', init);
    </script>
</body>
</html>
