<?php
declare(strict_types=1);
require __DIR__ . '/auth.php';
ini_set('error_log', '/dev/null');

$db = conectar('sqlite::memory:');
$db->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, hash_clave TEXT)');
$db->exec('CREATE TABLE login_fallido (usuario TEXT, ip TEXT, instante INTEGER)');
$db->prepare('INSERT INTO users (username, hash_clave) VALUES (?, ?)')
   ->execute(['ana', password_hash('Corr3cta!2026', PASSWORD_ARGON2ID)]);

$t = 1_000_000;
$casos = [
    ['credenciales correctas',            'ana', 'Corr3cta!2026',      '10.10.1.5', true],
    ['contraseña incorrecta',             'ana', 'otra',               '10.10.1.5', false],
    ["comillas en la entrada (literal)",  "ana' OR '1'='1", 'x',       '10.10.1.6', false],
    ['usuario inexistente',               'root', 'x',                 '10.10.1.7', false],
];
foreach ($casos as [$desc, $u, $p, $ip, $esperado]) {
    $ok = autenticar($db, $u, $p, $ip, $t) !== null;
    printf("%s -> %-9s %s\n", mb_str_pad($desc, 34), $ok ? 'ACEPTADO' : 'RECHAZADO', $ok === $esperado ? '[OK]' : '[FALLO]');
}
echo "\nFuerza bruta desde 203.0.113.50 contra 'ana':\n";
for ($i = 1; $i <= 5; $i++) { autenticar($db, 'ana', "prueba$i", '203.0.113.50', $t + $i); }
$ok = autenticar($db, 'ana', 'Corr3cta!2026', '203.0.113.50', $t + 6) !== null;
printf("%s -> ", mb_str_pad("6º intento con la clave buena", 34)); printf("%-9s %s\n", $ok ? 'ACEPTADO' : 'BLOQUEADO', $ok ? '[FALLO]' : '[OK]');
$ok = autenticar($db, 'ana', 'Corr3cta!2026', '203.0.113.50', $t + 6 + VENTANA_SEG) !== null;
printf("%s -> ", mb_str_pad("pasados 15 minutos", 34)); printf("%-9s %s\n", $ok ? 'ACEPTADO' : 'BLOQUEADO', $ok ? '[OK]' : '[FALLO]');
$h = $db->query("SELECT hash_clave FROM users")->fetchColumn();
echo "\nHash almacenado: " . substr($h, 0, 46) . "...\n";
