<?php
session_start();
include 'config.php';

// Register User
if (isset($_POST['register'])) {
    $username = $_POST['username'] ?? null;
    $email = $_POST['email'] ?? null;
    $password = password_hash($_POST['password'] ?? '', PASSWORD_BCRYPT);
    
    // Pastikan username belum ada
    $checkUserSql = "SELECT * FROM users WHERE username = :username";
    $checkStmt = $conn->prepare($checkUserSql);
    $checkStmt->execute(['username' => $username]);
    
    if ($checkStmt->rowCount() > 0) {
        echo "Username already exists!";
    } else {
        $sql = "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['username' => $username, 'email' => $email, 'password' => $password]);

        // Redirect to login page after signup
        header("Location: login.php");
        exit(); // Pastikan untuk keluar setelah redirect
    }
}

// Login User
if (isset($_POST['login'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $sql = "SELECT * FROM users WHERE username = :username";
    $stmt = $conn->prepare($sql);
    $stmt->execute(['username' => $username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['username'] = $user['username'];
        
        // Debugging line
        echo "Logged in as: " . $_SESSION['username']; // Check the username
        
        header("Location: index.php");
        exit(); // Pastikan untuk keluar setelah redirect
    } else {
        header("Location: login.php?error=1");
        exit();
    }
}


// Logout User
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: login.php");
    exit(); // Pastikan untuk keluar setelah redirect
}
?>
