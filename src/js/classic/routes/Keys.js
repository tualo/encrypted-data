Ext.define('Tualo.routes.EncryptedDataKeys', {
    statics: {
        load: async function () {
            return [
                {
                    name: 'Verschlüsselte Daten: Schlüssel',
                    path: '#encrypted-data/keys'
                }
            ]
        }
    },
    url: 'encrypted-data/keys',
    handler: {
        action: function () {
            Ext.getApplication().addView('Tualo.EncryptedData.Keys');
        },
        before: function (action, cnt) {
            let fn = Ext.require, txt = 'Tualo.EncryptedData' + '.Keys';
            fn(txt, function () {
                action.resume();
            }, this);
        }
    }
});
