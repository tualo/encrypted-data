Ext.define('Tualo.EncryptedData.controller.Keys', {
    extend: 'Ext.app.ViewController',
    alias: 'controller.encrypteddata_keys_controller',

    requires: [
        'Tualo.EncryptedData.Crypto',
        'Tualo.EncryptedData.KeyStore'
    ],

    onReady: function () {
        this.loadKeys();
    },

    toast: function (title, html) {
        Ext.toast({ html: html, title: title, align: 't', iconCls: 'fa fa-warning' });
    },

    loadKeys: function () {
        var me = this;
        (async function () {
            try {
                var response = await fetch('./encrypted-data/keys/my', { headers: { 'Accept': 'application/json' } });
                var o = await response.json();
                if (!o.success) throw new Error(o.msg || 'Schlüssel konnten nicht geladen werden');
                var local = await Tualo.EncryptedData.KeyStore.listKeys();
                var localFps = local.map(function (row) { return row.fingerprint; });
                var data = o.data.map(function (row) {
                    row.local = localFps.indexOf(row.fingerprint) !== -1;
                    return row;
                });
                me.getViewModel().getStore('mykeys').setData(data);
            } catch (e) {
                me.toast('Fehler', e.message);
            }
        })();
    },

    generateKey: function () {
        var me = this;
        Ext.Msg.prompt('Neuer Schlüssel', 'Name des Schlüssels:', function (btn, keyname) {
            if (btn !== 'ok' || !keyname || Ext.String.trim(keyname) === '') return;
            keyname = Ext.String.trim(keyname);
            (async function () {
                try {
                    var result = await Tualo.EncryptedData.Crypto.generateAndRegister(keyname);
                    // Die PEM-Datei ist das einzige Backup des privaten Schlüssels!
                    Tualo.EncryptedData.Crypto.download(keyname + '-private.key.asc', result.privatePEM);
                    Ext.toast({
                        html: 'Schlüssel erzeugt. Bitte die heruntergeladene private Schlüsseldatei sicher aufbewahren - sie ist das einzige Backup!',
                        title: 'Schlüssel erzeugt',
                        align: 't',
                        iconCls: 'fa fa-key'
                    });
                    me.loadKeys();
                } catch (e) {
                    me.toast('Fehler', e.message);
                }
            })();
        });
    },

    importKey: function () {
        var me = this;
        var input = document.createElement('input');
        input.type = 'file';
        input.accept = '.asc,.pem,.key,.txt';
        input.style.display = 'none';
        input.addEventListener('change', function () {
            if (!input.files || input.files.length === 0) return;
            var reader = new FileReader();
            reader.onload = function () {
                (async function () {
                    try {
                        var pem = reader.result;
                        var Crypto = Tualo.EncryptedData.Crypto;
                        var pub = await Crypto.publicKeyFromPrivatePEM(pem);
                        var fingerprint = await Crypto.fingerprint(pub);
                        var store = me.getViewModel().getStore('mykeys');
                        var rec = store.findRecord('fingerprint', fingerprint, 0, false, true, true);
                        if (!rec) throw new Error('Zu diesem privaten Schlüssel ist kein registrierter Schlüssel vorhanden (Fingerprint stimmt nicht überein).');
                        var priv = await Crypto.importPrivateKeyPEM(pem, false);
                        await Tualo.EncryptedData.KeyStore.savePrivateKey(fingerprint, rec.get('keyname'), priv);
                        Ext.toast({
                            html: 'Privater Schlüssel wurde in diesem Browser hinterlegt.',
                            title: 'Import',
                            align: 't',
                            iconCls: 'fa fa-key'
                        });
                        me.loadKeys();
                    } catch (e) {
                        me.toast('Import fehlgeschlagen', e.message);
                    }
                })();
            };
            reader.readAsText(input.files[0]);
        });
        document.body.appendChild(input);
        input.click();
        document.body.removeChild(input);
    },

    revokeKey: function () {
        var me = this;
        var selection = this.lookup('keysgrid').getSelection();
        if (selection.length === 0) {
            me.toast('Hinweis', 'Bitte einen Schlüssel auswählen.');
            return;
        }
        var rec = selection[0];
        Ext.Msg.confirm(
            'Schlüssel widerrufen',
            'Soll der Schlüssel "' + rec.get('keyname') + '" widerrufen werden? Für ihn können danach keine neuen Daten mehr verschlüsselt werden.',
            function (btn) {
                if (btn !== 'yes') return;
                (async function () {
                    try {
                        var response = await fetch('./encrypted-data/keys/revoke', {
                            method: 'POST',
                            headers: {
                                'Accept': 'application/json',
                                'Content-Type': 'application/x-www-form-urlencoded'
                            },
                            body: (new URLSearchParams({ fingerprint: rec.get('fingerprint') })).toString()
                        });
                        var o = await response.json();
                        if (!o.success) throw new Error(o.msg || 'Widerruf fehlgeschlagen');
                        Tualo.EncryptedData.Crypto._publicKeys = null;
                        me.loadKeys();
                    } catch (e) {
                        me.toast('Fehler', e.message);
                    }
                })();
            }
        );
    },

    removeLocalKey: function () {
        var me = this;
        var selection = this.lookup('keysgrid').getSelection();
        if (selection.length === 0) {
            me.toast('Hinweis', 'Bitte einen Schlüssel auswählen.');
            return;
        }
        var rec = selection[0];
        Ext.Msg.confirm(
            'Aus Browser entfernen',
            'Privaten Schlüssel "' + rec.get('keyname') + '" aus diesem Browser entfernen? Ohne die PEM-Sicherungsdatei können die Daten dann nicht mehr entschlüsselt werden.',
            function (btn) {
                if (btn !== 'yes') return;
                (async function () {
                    try {
                        await Tualo.EncryptedData.KeyStore.removeKey(rec.get('fingerprint'));
                        me.loadKeys();
                    } catch (e) {
                        me.toast('Fehler', e.message);
                    }
                })();
            }
        );
    }
});
