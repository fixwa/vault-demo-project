<?php

namespace Pablo\Vault2\Utils;

use PDOStatement;

class Settings
{
    public static function read(string $key): ?string
    {
        $dbh = new \PDO('mysql:host=127.0.0.1;dbname=demo', 'root', 'sdvrwgz46ezg0uatc2h6dvy8n');
        $stm = $dbh->query("SELECT * FROM settings WHERE name ='" . $key . "'");
        $token = $stm->fetchObject();

        if (!$token) {
            return null;
        }

        return $token->value;
    }

    public static function write(string $key, string $value): bool|PDOStatement
    {
        $dbh = new \PDO('mysql:host=127.0.0.1;dbname=demo', 'root', 'sdvrwgz46ezg0uatc2h6dvy8n');
        $dbh->query("DELETE FROM settings WHERE name='" . $key . "'");
        return $dbh->query("INSERT INTO settings(name, value) VALUES('" . $key . "', '" . $value . "')");
    }
}
