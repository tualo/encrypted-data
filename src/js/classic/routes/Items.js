Ext.define('Tualo.routes.EncryptedDataItems', {
    statics: {
        load: async function () {
            return [
                {
                    name: 'Verschlüsselte Daten: Datenelemente',
                    path: '#encrypted-data/items'
                }
            ]
        }
    },
    url: 'encrypted-data/items',
    handler: {
        action: function () {
            Ext.getApplication().addView('Tualo.EncryptedData.Items');
        },
        before: function (action, cnt) {
            let fn = Ext.require, txt = 'Tualo.EncryptedData' + '.Items';
            fn(txt, function () {
                action.resume();
            }, this);
        }
    }
});
