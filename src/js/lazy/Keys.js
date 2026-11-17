/**
 * Schlüsselverwaltung: eigene Schlüsselpaare erzeugen (im Browser),
 * private Schlüssel importieren (nur lokal, IndexedDB) und
 * öffentliche Schlüssel widerrufen.
 */
Ext.define('Tualo.EncryptedData.Keys', {
    extend: 'Ext.Container',
    requires: [
        'Tualo.EncryptedData.controller.Keys',
        'Tualo.EncryptedData.models.Keys'
    ],
    layout: 'fit',
    controller: 'encrypteddata_keys_controller',
    viewModel: {
        type: 'encrypteddata_keys_model'
    },
    listeners: {
        boxReady: 'onReady'
    },
    items: [{
        xtype: 'grid',
        reference: 'keysgrid',
        bind: {
            store: '{mykeys}'
        },
        columns: [
            { text: 'Name', dataIndex: 'keyname', flex: 1 },
            {
                text: 'Fingerprint', dataIndex: 'fingerprint', flex: 2,
                renderer: function (value) {
                    return Tualo.EncryptedData.Crypto.formatFingerprint(value);
                }
            },
            { text: 'Erstellt', dataIndex: 'created', width: 150 },
            {
                text: 'Status', dataIndex: 'revoked', width: 110,
                renderer: function (value) {
                    return value ? '<span style="color:#c00">widerrufen</span>' : 'aktiv';
                }
            },
            {
                text: 'Privater Schlüssel in diesem Browser', dataIndex: 'local', width: 220,
                renderer: function (value) {
                    return value ? '<i class="fa fa-check" style="color:#090"></i> verfügbar'
                        : '<i class="fa fa-times" style="color:#c00"></i> nicht verfügbar';
                }
            }
        ],
        tbar: [
            {
                text: 'Neuen Schlüssel erzeugen',
                iconCls: 'fa fa-key',
                handler: 'generateKey'
            },
            {
                text: 'Privaten Schlüssel importieren',
                iconCls: 'fa fa-upload',
                handler: 'importKey'
            },
            '-',
            {
                text: 'Widerrufen',
                iconCls: 'fa fa-ban',
                handler: 'revokeKey'
            },
            {
                text: 'Aus Browser entfernen',
                iconCls: 'fa fa-trash',
                handler: 'removeLocalKey'
            },
            '->',
            {
                iconCls: 'fa fa-refresh',
                handler: 'loadKeys'
            }
        ]
    }]
});
