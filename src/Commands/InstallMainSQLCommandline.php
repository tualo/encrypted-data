<?php

namespace Tualo\Office\EncryptedData\Commands;

use Garden\Cli\Cli;
use Garden\Cli\Args;
use Tualo\Office\Basic\ICommandline;
use Tualo\Office\Basic\TualoApplication as App;
use Tualo\Office\Basic\PostCheck;

class InstallMainSQLCommandline implements ICommandline
{
    public static function getCommandName(): string
    {
        return 'install-sql-encrypted-data';
    }

    public static function setup(Cli $cli)
    {
        $cli->command(self::getCommandName())
            ->description('installs needed sql tables for the encrypted-data module')
            ->opt('client', 'only use this client', true, 'string');
    }

    public static function setupClients(string $msg, string $clientName, string $file, callable $callback)
    {
        $_SERVER['REQUEST_URI'] = '';
        $_SERVER['REQUEST_METHOD'] = 'none';
        App::run();

        $session = App::get('session');
        $sessiondb = $session->db;
        $dbs = $sessiondb->direct('select username db_user, password db_pass, id db_name, host db_host, port db_port from macc_clients ');
        foreach ($dbs as $db) {
            if (($clientName != '') && ($clientName != $db['db_name'])) {
                continue;
            } else {
                App::set('clientDB', $session->newDBByRow($db));
                PostCheck::formatPrint(['blue'], $msg . '(' . $db['db_name'] . '):  ');
                $callback($file);
                PostCheck::formatPrintLn(['green'], "\t" . ' done');
            }
        }
    }

    public static function run(Args $args)
    {
        $files = [
            'install/encrypted_data_keys' => 'setup encrypted_data_keys',
            'install/encrypted_data' => 'setup encrypted_data',
            'install/encrypted_data_recipients' => 'setup encrypted_data_recipients',
        ];

        foreach ($files as $file => $msg) {
            $installSQL = function (string $file) {
                $filename = dirname(__DIR__) . '/sql/' . $file . '.sql';
                $sql = file_get_contents($filename);
                $sql = preg_replace('!/\*.*?\*/!s', '', $sql);
                $sql = preg_replace('#^\s*\-\-.+$#m', '', $sql);

                $singleStatements = App::get('clientDB')->explode_by_delimiter($sql);
                foreach ($singleStatements as $commandIndex => $statement) {
                    try {
                        App::get('clientDB')->execute($statement);
                        App::get('clientDB')->moreResults();
                    } catch (\Exception $e) {
                        echo PHP_EOL;
                        PostCheck::formatPrintLn(['red'], $e->getMessage() . ': commandIndex => ' . $commandIndex);
                    }
                }
            };
            $clientName = $args->getOpt('client');
            if (is_null($clientName)) $clientName = '';
            self::setupClients($msg, $clientName, $file, $installSQL);
        }
    }
}
