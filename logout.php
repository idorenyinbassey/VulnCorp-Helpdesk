<?php
if (session_status() === PHP_SESSION_NONE) { session_start(); }
setcookie('remember_token', '', time() - 3600, '/');
session_unset();
session_destroy();
header('Location: /index.php');
exit;
