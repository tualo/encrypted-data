/**
 * Verwaltung verschlüsselter Datenelemente: anlegen, entschlüsselt
 * anzeigen, mit weiteren Nutzern/Diensten teilen, löschen.
 * Sämtliche Kryptografie findet im Browser statt.
 */
Ext.define('Tualo.EncryptedData.Items', {
    extend: 'Ext.Container',
    requires: [
        'Tualo.EncryptedData.controller.Items',
        'Tualo.EncryptedData.models.Items'
    ],
    layout: 'fit',
    controller: 'encrypteddata_items_controller',
    viewModel: {
        type: 'encrypteddata_items_model'
    },
    listeners: {
        boxReady: 'onReady'
    },
    items: [{
        xtype: 'grid',
        reference: 'itemsgrid',
        bind: {
            store: '{items}'
        },
        columns: [
            { text: 'Bezeichnung', dataIndex: 'label', flex: 1 },
            { text: 'Kontext', dataIndex: 'context', width: 140 },
            {
                text: 'Typ', dataIndex: 'datatype', width: 110,
                renderer: function (value) {
                    return value === 'shared' ? 'gemeinsam' : 'einzeln';
                }
            },
            { text: 'Besitzer', dataIndex: 'owner', width: 120 },
            { text: 'Empfänger', dataIndex: 'recipient_count', width: 100, align: 'right' },
            { text: 'Geändert', dataIndex: 'modified', width: 150 }
        ],
        tbar: [
            {
                text: 'Neu',
                iconCls: 'fa fa-plus',
                handler: 'createItem'
            },
            {
                text: 'Anzeigen',
                iconCls: 'fa fa-unlock',
                handler: 'viewItem'
            },
            {
                text: 'Teilen',
                iconCls: 'fa fa-share-alt',
                handler: 'shareItem'
            },
            '-',
            {
                text: 'Löschen',
                iconCls: 'fa fa-trash',
                handler: 'deleteItem'
            },
            '->',
            {
                iconCls: 'fa fa-refresh',
                handler: 'loadItems'
            }
        ]
    }]
});
