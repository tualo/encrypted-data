/**
 * Einzeiliges verschlüsseltes Textfeld.
 *
 *     {
 *         xtype: 'encrypteddatafield',
 *         fieldLabel: 'Geheimnis',
 *         recipients: [] // optional: zusätzliche Empfänger-Fingerprints
 *     }
 *
 * Der Feldwert (getValue / Submit) ist immer der verschlüsselte
 * Envelope-JSON-String, nie der Klartext. Über das Schloss-Trigger-Icon
 * wird zwischen ver- und entschlüsselter Ansicht umgeschaltet.
 */
Ext.define('Tualo.EncryptedData.field.EncryptedField', {
    extend: 'Ext.form.field.Text',
    xtype: 'encrypteddatafield',

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
