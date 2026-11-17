<?php

namespace Tualo\Office\EncryptedData\Checks;

use Tualo\Office\Basic\PostCheck;
use Tualo\Office\Basic\TualoApplication as App;

class Tables extends PostCheck
{
    public static function test(array $config)
    {
        $clientdb = App::get('clientDB');
        if (is_null($clientdb)) return;
        $tables = [
            'encrypted_data_keys' => [
                'columns' => [
                    'fingerprint' => 'varchar(64)',
                    'username' => 'varchar(50)',
                    'keyname' => 'varchar(100)',
                    'publickey' => 'text',
                    'created' => 'datetime',
                    'revoked' => 'datetime',
                ]
            ],
            'encrypted_data' => [
                'columns' => [
                    'id' => 'varchar(36)',
                    'context' => 'varchar(100)',
                    'label' => 'varchar(255)',
                    'owner' => 'varchar(50)',
                    'datatype' => 'varchar(20)',
                    'iv' => 'varchar(64)',
                    'ciphertext' => 'mediumtext',
                    'created' => 'datetime',
                    'modified' => 'datetime',
                ]
            ],
            'encrypted_data_recipients' => [
                'columns' => [
                    'data_id' => 'varchar(36)',
                    'fingerprint' => 'varchar(64)',
                    'wrapped_key' => 'text',
                    'added_by' => 'varchar(50)',
                    'created' => 'datetime',
                ]
            ],
        ];
        self::tableCheck(
            'ds',
            $tables,
            "please run the following command: `./tm install-sql-encrypted-data --client " . $clientdb->dbname . "`",
            "please run the following command: `./tm install-sql-encrypted-data --client " . $clientdb->dbname . "`"
        );
    }
}
