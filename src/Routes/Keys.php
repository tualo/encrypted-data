<?php

namespace Tualo\Office\EncryptedData\Routes;

use Tualo\Office\Basic\TualoApplication as App;
use Tualo\Office\Basic\Route as BasicRoute;
use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\Crypt\RSA\PublicKey as RSAPublicKey;

use Tualo\Office\EncryptedData\Scopes\EncryptedDataKeysScope;

/**
 * Schlüsselverwaltung.
 *
 * Es werden ausschließlich ÖFFENTLICHE Schlüssel angenommen und gespeichert.
 * Der private Schlüssel wird im Browser erzeugt und verlässt diesen nie
 * (Download als Datei + optional IndexedDB des Browsers).
 */
class Keys extends \Tualo\Office\Basic\RouteWrapper
{
    public static function scope(): string
    {
        return EncryptedDataKeysScope::identifier();
    }

    /**
     * SHA-256-Fingerprint (hex, lowercase) über den DER-kodierten SPKI-Body
     * eines PEM-Public-Keys. Identisch zur clientseitigen Berechnung
     * (SHA-256 über das Ergebnis von crypto.subtle.exportKey('spki', ...)).
     */
    public static function fingerprint(string $pem): string
    {
        $body = preg_replace('/-----(BEGIN|END)[^-]+-----/', '', $pem);
        $der = base64_decode(preg_replace('/\s+/', '', (string)$body), true);
        if ($der === false || $der === '') throw new \Exception('Der Schlüssel konnte nicht gelesen werden');
        return hash('sha256', $der);
    }

    public static function register()
    {
        /**
         * Eigenen Public Key registrieren.
         * POST publickey (PEM, SPKI), keyname
         */
        BasicRoute::add('/encrypted-data/keys/register', function () {
            App::contenttype('application/json');
            try {
                $db = App::get('session')->getDB();
                if (!isset($_REQUEST['publickey']) || !is_string($_REQUEST['publickey'])) throw new \Exception('Attribut publickey wird vermisst');
                if (!isset($_REQUEST['keyname']) || !is_string($_REQUEST['keyname']) || trim($_REQUEST['keyname']) == '') throw new \Exception('Attribut keyname wird vermisst');
                if (stripos($_REQUEST['publickey'], 'PRIVATE KEY') !== false) throw new \Exception('Es dürfen nur öffentliche Schlüssel hochgeladen werden!');

                $key = PublicKeyLoader::loadPublicKey($_REQUEST['publickey']);
                if (!($key instanceof RSAPublicKey)) throw new \Exception('Der Schlüssel kann nicht verwendet werden (RSA Public Key erwartet)');
                if ($key->getLength() < 2048) throw new \Exception('Die Schlüssellänge ist zu kurz (mindestens 2048 Bit)');

                $fingerprint = Keys::fingerprint($_REQUEST['publickey']);

                $db->direct(
                    'insert into encrypted_data_keys (fingerprint, username, keyname, publickey)
                     values ({fingerprint}, @sessionuser, {keyname}, {publickey})',
                    [
                        'fingerprint' => $fingerprint,
                        'keyname' => trim($_REQUEST['keyname']),
                        'publickey' => $_REQUEST['publickey'],
                    ]
                );
                App::result('fingerprint', $fingerprint);
                App::result('success', true);
            } catch (\Exception $e) {
                App::result('msg', $e->getMessage());
            }
        }, ['post'], true, [], self::scope());

        /**
         * Alle aktiven Public Keys auflisten (für die Empfängerauswahl beim Teilen).
         * Enthält keine Geheimnisse: Public Keys sind per Definition öffentlich.
         */
        BasicRoute::add('/encrypted-data/keys', function () {
            App::contenttype('application/json');
            try {
                $db = App::get('session')->getDB();
                $list = $db->direct(
                    'select fingerprint, username, keyname, publickey, created,
                            (username = @sessionuser) own
                     from encrypted_data_keys
                     where revoked is null
                     order by username, keyname'
                );
                App::result('data', $list);
                App::result('success', true);
            } catch (\Exception $e) {
                App::result('msg', $e->getMessage());
            }
        }, ['get'], true, [], self::scope());

        /**
         * Eigene Schlüssel (inkl. widerrufener) auflisten.
         */
        BasicRoute::add('/encrypted-data/keys/my', function () {
            App::contenttype('application/json');
            try {
                $db = App::get('session')->getDB();
                $list = $db->direct(
                    'select fingerprint, username, keyname, publickey, created, revoked
                     from encrypted_data_keys
                     where username = @sessionuser
                     order by created desc'
                );
                App::result('data', $list);
                App::result('success', true);
            } catch (\Exception $e) {
                App::result('msg', $e->getMessage());
            }
        }, ['get'], true, [], self::scope());

        /**
         * Eigenen Schlüssel widerrufen. Bereits verschlüsselte Daten bleiben
         * mit dem Schlüssel lesbar, es dürfen aber keine neuen Daten mehr für
         * ihn verschlüsselt werden.
         * POST fingerprint
         */
        BasicRoute::add('/encrypted-data/keys/revoke', function () {
            App::contenttype('application/json');
            try {
                $db = App::get('session')->getDB();
                if (!isset($_REQUEST['fingerprint']) || !is_string($_REQUEST['fingerprint'])) throw new \Exception('Attribut fingerprint wird vermisst');
                $row = $db->singleRow(
                    'select fingerprint from encrypted_data_keys where fingerprint = {fingerprint} and username = @sessionuser',
                    ['fingerprint' => $_REQUEST['fingerprint']]
                );
                if ($row === false) throw new \Exception('Schlüssel nicht gefunden oder keine Berechtigung');
                $db->direct(
                    'update encrypted_data_keys set revoked = now() where fingerprint = {fingerprint} and username = @sessionuser and revoked is null',
                    ['fingerprint' => $_REQUEST['fingerprint']]
                );
                App::result('success', true);
            } catch (\Exception $e) {
                App::result('msg', $e->getMessage());
            }
        }, ['post'], true, [], self::scope());
    }
}
