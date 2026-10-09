<?php
declare(strict_types=1);
require __DIR__ . '/auth.php';

// Seguridad en el despliegue: cookie de sesión endurecida y solo por HTTPS.
session_start(['cookie_secure' => true, 'cookie_httponly' => true,
               'cookie_samesite' => 'Strict', 'use_strict_mode' => true]);

if ($_SERVER['REQUEST_METHOD'] !== 'POST'
    || !hash_equals($_SESSION['csrf'] ?? '', (string)($_POST['csrf'] ?? ''))) {
    http_response_code(400);
    exit('Solicitud no válida');
}

$db = conectar(getenv('LOGIN_DSN') ?: 'sqlite:/var/lib/app/usuarios.db');
$id = autenticar($db, (string)($_POST['user'] ?? ''), (string)($_POST['pass'] ?? ''),
                 $_SERVER['REMOTE_ADDR']);

if ($id === null) {
    http_response_code(401);
    exit('Usuario o contraseña incorrectos');   // mensaje genérico, igual para todos los casos
}
session_regenerate_id(true);                    // evita la fijación de sesión
$_SESSION['uid'] = $id;
header('Location: /inicio');
