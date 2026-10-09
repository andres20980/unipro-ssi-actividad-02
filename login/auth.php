<?php
declare(strict_types=1);

// Seguridad en el diseño: una única función de autenticación, sencilla y revisable.
const MAX_FALLOS = 5;          // intentos fallidos permitidos...
const VENTANA_SEG = 900;       // ...en una ventana de 15 minutos

function conectar(string $dsn): PDO {
    // Seguridad por defecto: errores como excepciones y sin emulación de sentencias preparadas.
    return new PDO($dsn, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
}

function bloqueado(PDO $db, string $usuario, string $ip, int $ahora): bool {
    $st = $db->prepare('SELECT COUNT(*) FROM login_fallido
                        WHERE (usuario = :u OR ip = :ip) AND instante > :desde');
    $st->execute([':u' => $usuario, ':ip' => $ip, ':desde' => $ahora - VENTANA_SEG]);
    return (int)$st->fetchColumn() >= MAX_FALLOS;
}

// Devuelve el id del usuario autenticado o null. Ante cualquier fallo, deniega (fallar de forma segura).
function autenticar(PDO $db, string $usuario, string $clave, string $ip, ?int $ahora = null): ?int {
    $ahora ??= time();
    try {
        if ($usuario === '' || strlen($usuario) > 64 || strlen($clave) > 256) {
            return null;                                   // validación de entrada
        }
        if (bloqueado($db, $usuario, $ip, $ahora)) {
            return null;                                   // límite de intentos
        }
        // Consulta parametrizada: la entrada nunca forma parte del texto SQL.
        $st = $db->prepare('SELECT id, hash_clave FROM users WHERE username = :u');
        $st->execute([':u' => $usuario]);
        $fila = $st->fetch(PDO::FETCH_ASSOC);
        if ($fila !== false && password_verify($clave, $fila['hash_clave'])) {
            return (int)$fila['id'];
        }
        $db->prepare('INSERT INTO login_fallido (usuario, ip, instante) VALUES (:u, :ip, :t)')
           ->execute([':u' => $usuario, ':ip' => $ip, ':t' => $ahora]);
        error_log("login fallido usuario=$usuario ip=$ip");   // detalle solo en el log
        return null;
    } catch (Throwable $e) {
        error_log('error de autenticación: ' . $e->getMessage());
        return null;
    }
}
