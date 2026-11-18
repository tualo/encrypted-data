<?php

namespace Tualo\Office\EncryptedData\Scopes;

use Tualo\Office\Basic\Scope;

class EncryptedDataKeysScope extends Scope
{
    protected static string $identifier = 'encrypted-data-keys';
    protected static array $name = [
        'EN' => 'Encrypted Data Keys',
        'DE' => 'Verschlüsselte Daten Schlüssel',
    ];
    protected static array $description = [
        'EN' => 'Access and manage encrypted data keys.',
        'DE' => 'Auf verschlüsselte Daten Schlüssel zugreifen und sie verwalten.',
    ];
}
