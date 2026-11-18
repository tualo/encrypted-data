<?php

namespace Tualo\Office\EncryptedData\Routes;

use Tualo\Office\Basic\TualoApplication as App;
use Tualo\Office\Basic\Route as BasicRoute;
use Ramsey\Uuid\Uuid;
use Tualo\Office\EncryptedData\Scopes\EncryptedDataScope;

/**
 * Verwaltung verschlüsselter Datenelemente.
 *
 * Der Server speichert ausschließlich Ciphertext, IV und pro Empfänger
 * RSA-OAEP-gewrappte AES-Schlüssel. Ver- und Entschlüsselung sowie das
 * Wrapping für weitere Empfänger finden ausschließlich im Browser statt.
 */
class Data extends \Tualo\Office\Basic\RouteWrapper
{
    public static function scope(): string
    {
        return EncryptedDataScope::identifier();
    }

    /**
     * Empfängerliste aus dem Request lesen und validieren.
     * Erwartet JSON: [{"fingerprint":"...","wrapped_key":"..."}, ...]
     */
    private static function parseRecipients($db): array
    {
        if (!isset($_REQUEST['recipients']) || !is_string($_REQUEST['recipients'])) throw new \Exception('Attribut recipients wird vermisst');
        $recipients = json_decode($_REQUEST['recipients'], true);
        if (!is_array($recipients) || count($recipients) == 0) throw new \Exception('Es muss mindestens ein Empfänger angegeben werden');
        foreach ($recipients as $recipient) {
            if (!isset($recipient['fingerprint']) || !is_string($recipient['fingerprint'])) throw new \Exception('Empfänger ohne fingerprint');
            if (!isset($recipient['wrapped_key']) || !is_string($recipient['wrapped_key']) || $recipient['wrapped_key'] == '') throw new \Exception('Empfänger ohne wrapped_key');
            $row = $db->singleRow(
                'select fingerprint from encrypted_data_keys where fingerprint = {fingerprint} and revoked is null',
                ['fingerprint' => $recipient['fingerprint']]
            );
            if ($row === false) throw new \Exception('Unbekannter oder widerrufener Empfänger-Schlüssel: ' . $recipient['fingerprint']);
        }
        return $recipients;
    }

    private static function insertRecipients($db, string $id, array $recipients): void
    {
        foreach ($recipients as $recipient) {
            $db->direct(
                'replace into encrypted_data_recipients (data_id, fingerprint, wrapped_key, added_by)
                 values ({data_id}, {fingerprint}, {wrapped_key}, (select @sessionuser))',
                [
                    'data_id' => $id,
                    'fingerprint' => $recipient['fingerprint'],
                    'wrapped_key' => $recipient['wrapped_key'],
                ]
            );
        }
    }

    public static function register()
    {
        /**
         * Datenelement anlegen oder (als Besitzer) komplett neu verschlüsselt speichern.
         * POST id?, context?, label?, datatype (single|shared), iv, ciphertext, recipients (JSON)
         */
        BasicRoute::add('/encrypted-data/save', function () {
            App::contenttype('application/json');
            try {
                $db = App::get('session')->getDB();
                foreach (['iv', 'ciphertext'] as $attr) {
                    if (!isset($_REQUEST[$attr]) || !is_string($_REQUEST[$attr]) || $_REQUEST[$attr] == '') throw new \Exception('Attribut ' . $attr . ' wird vermisst');
                }
                $datatype = isset($_REQUEST['datatype']) && $_REQUEST['datatype'] == 'shared' ? 'shared' : 'single';
                $recipients = self::parseRecipients($db);

                $id = isset($_REQUEST['id']) && is_string($_REQUEST['id']) && $_REQUEST['id'] != '' ? $_REQUEST['id'] : '';
                if ($id != '') {
                    $row = $db->singleRow('select id, owner from encrypted_data where id = {id}', ['id' => $id]);
                    if ($row === false) throw new \Exception('Datenelement nicht gefunden');
                    $owner = $db->singleRow('select id from encrypted_data where id = {id} and owner = @sessionuser', ['id' => $id]);
                    if ($owner === false) throw new \Exception('Nur der Besitzer darf das Datenelement überschreiben');
                    $db->direct(
                        'update encrypted_data set context = {context}, label = {label}, datatype = {datatype}, iv = {iv}, ciphertext = {ciphertext} where id = {id}',
                        [
                            'id' => $id,
                            'context' => isset($_REQUEST['context']) ? (string)$_REQUEST['context'] : '',
                            'label' => isset($_REQUEST['label']) ? (string)$_REQUEST['label'] : '',
                            'datatype' => $datatype,
                            'iv' => $_REQUEST['iv'],
                            'ciphertext' => $_REQUEST['ciphertext'],
                        ]
                    );
                    // Beim Überschreiben wird ein neuer AES-Schlüssel verwendet,
                    // daher müssen alle Empfänger neu gewrappt mitgeliefert werden.
                    $db->direct('delete from encrypted_data_recipients where data_id = {id}', ['id' => $id]);
                } else {
                    $id = Uuid::uuid4()->toString();
                    $db->direct(
                        'insert into encrypted_data (id, context, label, owner, datatype, iv, ciphertext)
                         values ({id}, {context}, {label}, @sessionuser, {datatype}, {iv}, {ciphertext})',
                        [
                            'id' => $id,
                            'context' => isset($_REQUEST['context']) ? (string)$_REQUEST['context'] : '',
                            'label' => isset($_REQUEST['label']) ? (string)$_REQUEST['label'] : '',
                            'datatype' => $datatype,
                            'iv' => $_REQUEST['iv'],
                            'ciphertext' => $_REQUEST['ciphertext'],
                        ]
                    );
                }
                self::insertRecipients($db, $id, $recipients);
                App::result('id', $id);
                App::result('success', true);
            } catch (\Exception $e) {
                App::result('msg', $e->getMessage());
            }
        }, ['post'], true, [], self::scope());

        /**
         * Alle Datenelemente auflisten, bei denen der Nutzer Besitzer oder
         * Empfänger ist. Es werden nur Metadaten geliefert, keine Schlüssel.
         */
        BasicRoute::add('/encrypted-data/list', function () {
            App::contenttype('application/json');
            try {
                $db = App::get('session')->getDB();
                $list = $db->direct(
                    'select d.id, d.context, d.label, d.owner, d.datatype, d.created, d.modified,
                            (d.owner = @sessionuser) own,
                            (select count(*) from encrypted_data_recipients r2 where r2.data_id = d.id) recipient_count
                     from encrypted_data d
                     where d.owner = @sessionuser
                        or exists (
                            select 1
                            from encrypted_data_recipients r
                            join encrypted_data_keys k on k.fingerprint = r.fingerprint
                            where r.data_id = d.id and k.username = @sessionuser
                        )
                     order by d.modified desc'
                );
                App::result('data', $list);
                App::result('success', true);
            } catch (\Exception $e) {
                App::result('msg', $e->getMessage());
            }
        }, ['get'], true, [], self::scope());

        /**
         * Ein Datenelement lesen. Gewrappte AES-Schlüssel werden nur für die
         * eigenen Schlüssel des anfragenden Nutzers ausgeliefert
         * (Least-Privilege, auch wenn fremde Wrapped Keys ohne den passenden
         * Private Key wertlos sind).
         */
        BasicRoute::add('/encrypted-data/get/(?P<id>[\w\-]+)', function ($matches) {
            App::contenttype('application/json');
            try {
                $db = App::get('session')->getDB();
                $item = $db->singleRow(
                    'select d.id, d.context, d.label, d.owner, d.datatype, d.iv, d.ciphertext, d.created, d.modified,
                            (d.owner = @sessionuser) own
                     from encrypted_data d
                     where d.id = {id}
                       and (d.owner = @sessionuser
                        or exists (
                            select 1
                            from encrypted_data_recipients r
                            join encrypted_data_keys k on k.fingerprint = r.fingerprint
                            where r.data_id = d.id and k.username = @sessionuser
                        ))',
                    ['id' => $matches['id']]
                );
                if ($item === false) throw new \Exception('Datenelement nicht gefunden oder keine Berechtigung');

                $myKeys = $db->direct(
                    'select r.fingerprint, r.wrapped_key
                     from encrypted_data_recipients r
                     join encrypted_data_keys k on k.fingerprint = r.fingerprint
                     where r.data_id = {id} and k.username = @sessionuser',
                    ['id' => $matches['id']]
                );
                $recipients = $db->direct(
                    'select r.fingerprint, k.username, k.keyname, r.added_by, r.created
                     from encrypted_data_recipients r
                     join encrypted_data_keys k on k.fingerprint = r.fingerprint
                     where r.data_id = {id}
                     order by k.username',
                    ['id' => $matches['id']]
                );
                App::result('data', $item);
                App::result('mykeys', $myKeys);
                App::result('recipients', $recipients);
                App::result('success', true);
            } catch (\Exception $e) {
                App::result('msg', $e->getMessage());
            }
        }, ['get'], true, [], self::scope());

        /**
         * Datenelement mit weiteren Empfängern teilen. Teilen darf, wer das
         * Element selbst entschlüsseln kann (Besitzer oder Empfänger), denn
         * nur diese Person kann den AES-Schlüssel clientseitig neu wrappen.
         * POST id, recipients (JSON)
         */
        BasicRoute::add('/encrypted-data/share', function () {
            App::contenttype('application/json');
            try {
                $db = App::get('session')->getDB();
                if (!isset($_REQUEST['id']) || !is_string($_REQUEST['id'])) throw new \Exception('Attribut id wird vermisst');
                $item = $db->singleRow(
                    'select d.id from encrypted_data d
                     where d.id = {id}
                       and (d.owner = @sessionuser
                        or exists (
                            select 1
                            from encrypted_data_recipients r
                            join encrypted_data_keys k on k.fingerprint = r.fingerprint
                            where r.data_id = d.id and k.username = @sessionuser
                        ))',
                    ['id' => $_REQUEST['id']]
                );
                if ($item === false) throw new \Exception('Datenelement nicht gefunden oder keine Berechtigung');
                $recipients = self::parseRecipients($db);
                self::insertRecipients($db, $_REQUEST['id'], $recipients);
                $db->direct('update encrypted_data set datatype = \'shared\' where id = {id}', ['id' => $_REQUEST['id']]);
                App::result('success', true);
            } catch (\Exception $e) {
                App::result('msg', $e->getMessage());
            }
        }, ['post'], true, [], self::scope());

        /**
         * Einen Empfänger entfernen (nur Besitzer). Achtung: rein
         * organisatorisch - was ein Empfänger bereits entschlüsselt hat,
         * kann technisch nicht zurückgeholt werden.
         * POST id, fingerprint
         */
        BasicRoute::add('/encrypted-data/unshare', function () {
            App::contenttype('application/json');
            try {
                $db = App::get('session')->getDB();
                if (!isset($_REQUEST['id']) || !is_string($_REQUEST['id'])) throw new \Exception('Attribut id wird vermisst');
                if (!isset($_REQUEST['fingerprint']) || !is_string($_REQUEST['fingerprint'])) throw new \Exception('Attribut fingerprint wird vermisst');
                $item = $db->singleRow(
                    'select id from encrypted_data where id = {id} and owner = @sessionuser',
                    ['id' => $_REQUEST['id']]
                );
                if ($item === false) throw new \Exception('Nur der Besitzer darf Empfänger entfernen');
                $db->direct(
                    'delete from encrypted_data_recipients where data_id = {id} and fingerprint = {fingerprint}',
                    ['id' => $_REQUEST['id'], 'fingerprint' => $_REQUEST['fingerprint']]
                );
                App::result('success', true);
            } catch (\Exception $e) {
                App::result('msg', $e->getMessage());
            }
        }, ['post'], true, [], self::scope());

        /**
         * Datenelement löschen (nur Besitzer).
         * POST id
         */
        BasicRoute::add('/encrypted-data/delete', function () {
            App::contenttype('application/json');
            try {
                $db = App::get('session')->getDB();
                if (!isset($_REQUEST['id']) || !is_string($_REQUEST['id'])) throw new \Exception('Attribut id wird vermisst');
                $item = $db->singleRow(
                    'select id from encrypted_data where id = {id} and owner = @sessionuser',
                    ['id' => $_REQUEST['id']]
                );
                if ($item === false) throw new \Exception('Nur der Besitzer darf das Datenelement löschen');
                $db->direct('delete from encrypted_data_recipients where data_id = {id}', ['id' => $_REQUEST['id']]);
                $db->direct('delete from encrypted_data where id = {id}', ['id' => $_REQUEST['id']]);
                App::result('success', true);
            } catch (\Exception $e) {
                App::result('msg', $e->getMessage());
            }
        }, ['post'], true, [], self::scope());
    }
}
