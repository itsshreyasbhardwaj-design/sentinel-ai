<?php
// Intentionally insecure fixture for Sentinel AI's test suite. Do not deploy.

// SQL injection through variable interpolation.
$result = mysqli_query($conn, "SELECT * FROM users WHERE email = '$email'");

// Command injection.
system("convert " . $_GET['file'] . " output.png");

// Dynamic code evaluation.
eval($_POST['expression']);

// Object injection through unserialize.
$session = unserialize($_COOKIE['session']);

// Local file inclusion.
include($_GET['page'] . '.php');
