Ext.define('Tualo.EncryptedData.models.Items', {
    extend: 'Ext.app.ViewModel',
    alias: 'viewmodel.encrypteddata_items_model',
    stores: {
        items: {
            fields: ['id', 'context', 'label', 'owner', 'datatype', 'created', 'modified', 'own', 'recipient_count'],
            proxy: { type: 'memory' },
            data: []
        }
    }
});
