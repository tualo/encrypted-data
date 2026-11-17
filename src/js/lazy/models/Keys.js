Ext.define('Tualo.EncryptedData.models.Keys', {
    extend: 'Ext.app.ViewModel',
    alias: 'viewmodel.encrypteddata_keys_model',
    stores: {
        mykeys: {
            fields: ['fingerprint', 'keyname', 'username', 'publickey', 'created', 'revoked', 'local'],
            proxy: { type: 'memory' },
            data: []
        }
    }
});
