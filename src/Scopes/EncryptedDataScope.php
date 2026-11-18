<?php

namespace Tualo\Office\EncryptedData\Scopes;

use Tualo\Office\Basic\Scope;

class EncryptedDataScope extends Scope
{
    protected static string $identifier = 'encrypted-data';
    protected static array $name = [
        'EN' => 'Encrypted Data',
        'DE' => 'Verschlüsselte Daten',
    ];
    protected static array $description = [
        'EN' => 'Access and manage encrypted data.',
        'DE' => 'Auf verschlüsselte Daten zugreifen und sie verwalten.',
    ];
}
