/**
 * Mehrzeiliger verschlüsselter Texteingabebereich (textarea).
 *
 *     {
 *         xtype: 'encrypteddataarea',
 *         fieldLabel: 'Geheime Notizen',
 *         recipients: [] // optional: zusätzliche Empfänger-Fingerprints
 *     }
 *
 * Verhalten identisch zu Tualo.EncryptedData.field.EncryptedField.
 */
Ext.define('Tualo.EncryptedData.field.EncryptedArea', {
    extend: 'Ext.form.field.TextArea',
    xtype: 'encrypteddataarea',

    requires: [
        'Tualo.EncryptedData.field.Mixin'
    ],

    mixins: [
        'Tualo.EncryptedData.field.Mixin'
    ],

    /**
     * @cfg {String[]} recipients
     * Zusätzliche Empfänger-Fingerprints; die eigenen aktiven Schlüssel
     * werden immer automatisch ergänzt.
     */
    recipients: null,

    triggers: {
        edlock: {
            cls: 'fa fa-lock',
            weight: 1,
            handler: function () {
                this.edToggleLock();
            }
        }
    }
});
