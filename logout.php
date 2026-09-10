<?php
require_once dirname(__FILE__) . '/includes/compat.php';
if (session_id() === '') { session_start(); }
setcookie('remember_token', '', time() - 3600, '/');
session_unset();
session_destroy();
header('Location: ' . app_base() . '/index.php');
exit;
