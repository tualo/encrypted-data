/**
 * Gemeinsame Logik für verschlüsselte Formularfelder
 * (Tualo.EncryptedData.field.EncryptedField / EncryptedArea).
 *
 * Das Feld arbeitet mit zwei Zuständen:
 *
 *  - verriegelt (Standard): Der Feldwert ist ein Envelope (JSON-String,
 *    siehe Tualo.EncryptedData.Crypto). Angezeigt wird nur ein Platzhalter,
 *    das Feld ist nicht editierbar.
 *  - entriegelt: Der Inhalt wurde mit dem privaten Schlüssel des Nutzers
 *    entschlüsselt und kann bearbeitet werden. Änderungen werden gepuffert
 *    automatisch neu verschlüsselt, der Klartext verlässt den Browser nie.
 *
 * getValue()/getSubmitValue() liefern immer den Envelope-String, niemals
 * den Klartext. Vor einem programmatischen Submit sollte
 * `await field.ensureEncrypted()` aufgerufen werden, damit eine evtl.
 * noch laufende Verschlüsselung abgeschlossen ist.
 *
 * Konfiguration:
 *  - recipients: Array zusätzlicher Empfänger-Fingerprints (optional).
 *    Die eigenen aktiven Schlüssel des Nutzers werden immer ergänzt.
 */
Ext.define('Tualo.EncryptedData.field.Mixin', {
    extend: 'Ext.Mixin',

    requires: [
        'Tualo.EncryptedData.Crypto',
        'Tualo.EncryptedData.KeyStore'
    ],

    mixinConfig: {
        id: 'encrypteddatafield',
        after: {
            initComponent: 'initEncryptedField'
        }
    },

    lockedText: '••••• verschlüsselt •••••',

    initEncryptedField: function () {
        this.edLocked = true;
        this.edEnvelope = null;
        this.edPlainLoaded = false;
        this.edEncryptTask = new Ext.util.DelayedTask(this.edEncryptNow, this);
        this.edPending = null;
        this.setEditable(false);
        this.on('change', this.onEdChange, this);
        this.on('blur', this.onEdBlur, this);
        this.on('afterrender', this.edUpdateTriggerUi, this);
    },

    /* ------------------------------------------------ Wert-Handling */

    setValue: function (value) {
        var Crypto = Tualo.EncryptedData.Crypto;
        if (Crypto.isEnvelope(value)) {
            this.edEnvelope = value;
            this.edPlainLoaded = false;
            this.edLocked = true;
            this.edSilent = true;
            this.callParent([this.lockedText]);
            this.edSilent = false;
            this.setEditable(false);
            this.edUpdateTriggerUi();
            return this;
        }
        if (value === null || value === undefined || value === '') {
            this.edEnvelope = null;
            this.edPlainLoaded = true;
            this.edLocked = false;
            this.edSilent = true;
            this.callParent(['']);
            this.edSilent = false;
            this.setEditable(true);
            this.edUpdateTriggerUi();
            return this;
        }
        // Klartext (z.B. Benutzereingabe im entriegelten Zustand)
        return this.callParent([value]);
    },

    getValue: function () {
        if (this.edEnvelope !== null) return this.edEnvelope;
        if (this.edLocked) return '';
        var raw = this.callParent();
        // Noch nicht verschlüsselter Neu-Inhalt: niemals Klartext liefern
        return (raw === this.lockedText) ? '' : (this.edEnvelope || '');
    },

    getSubmitValue: function () {
        return this.getValue();
    },

    /**
     * Wartet auf eine evtl. laufende Verschlüsselung und liefert den
     * aktuellen Envelope-String.
     * @return {Promise<String>}
     */
    ensureEncrypted: async function () {
        this.edEncryptTask.cancel();
        await this.edEncryptNow();
        return this.edEnvelope || '';
    },

    /* ------------------------------------------------ Ereignisse */

    onEdChange: function () {
        if (this.edSilent || this.edLocked || !this.edPlainLoaded) return;
        this.edEncryptTask.delay(400);
    },

    onEdBlur: function () {
        if (this.edLocked || !this.edPlainLoaded) return;
        this.edEncryptTask.cancel();
        this.edEncryptNow();
    },

    /* ------------------------------------------------ Verschlüsselung */

    edCollectRecipients: async function () {
        var Crypto = Tualo.EncryptedData.Crypto;
        var all = await Crypto.loadPublicKeys();
        var wanted = this.recipients || [];
        var result = [], seen = {};
        Ext.each(all, function (key) {
            var isOwn = (key.own == 1 || key.own === true);
            if ((isOwn || wanted.indexOf(key.fingerprint) !== -1) && !seen[key.fingerprint]) {
                seen[key.fingerprint] = true;
                result.push(key);
            }
        });
        if (result.length === 0) {
            throw new Error('Kein eigener Schlüssel vorhanden. Bitte zuerst unter "Meine Schlüssel" einen Schlüssel erzeugen.');
        }
        return result;
    },

    edEncryptNow: function () {
        var me = this;
        if (me.edPending) return me.edPending;
        if (me.edLocked || !me.edPlainLoaded) return Promise.resolve();
        var plain = me.getRawValue();
        me.edPending = (async function () {
            try {
                if (plain === '') {
                    me.edEnvelope = null;
                } else {
                    var Crypto = Tualo.EncryptedData.Crypto;
                    var recipients = await me.edCollectRecipients();
                    var envelope = await Crypto.encrypt(plain, recipients);
                    me.edEnvelope = Crypto.stringifyEnvelope(envelope);
                }
                me.fireEvent('encrypted', me, me.edEnvelope);
            } catch (e) {
                me.markInvalid(e.message);
                me.fireEvent('encryptionfailed', me, e);
            } finally {
                me.edPending = null;
            }
        })();
        return me.edPending;
    },

    /* ------------------------------------------------ Entschlüsselung */

    edDecrypt: async function () {
        var Crypto = Tualo.EncryptedData.Crypto;
        var KeyStore = Tualo.EncryptedData.KeyStore;
        var envelope = Crypto.parseEnvelope(this.edEnvelope);
        var fingerprints = Object.keys(envelope.keys);
        for (var i = 0; i < fingerprints.length; i++) {
            var stored = await KeyStore.getPrivateKey(fingerprints[i]);
            if (stored) {
                return await Crypto.decryptEnvelope(stored.privateKey, fingerprints[i], envelope);
            }
        }
        throw new Error('In diesem Browser ist kein passender privater Schlüssel hinterlegt. ' +
            'Bitte importieren Sie Ihren privaten Schlüssel unter "Meine Schlüssel".');
    },

    /* ------------------------------------------------ Lock / Unlock */

    edToggleLock: function () {
        if (this.edLocked) {
            this.edUnlock();
        } else {
            this.edLock();
        }
    },

    edUnlock: function () {
        var me = this;
        (async function () {
            try {
                var plain = '';
                if (me.edEnvelope !== null) {
                    plain = await me.edDecrypt();
                }
                me.edLocked = false;
                me.edPlainLoaded = true;
                me.edSilent = true;
                me.setRawValue(plain);
                me.edSilent = false;
                me.setEditable(true);
                me.edUpdateTriggerUi();
            } catch (e) {
                Ext.toast({
                    html: e.message,
                    title: 'Entschlüsselung',
                    align: 't',
                    iconCls: 'fa fa-warning'
                });
            }
        })();
    },

    edLock: function () {
        var me = this;
        (async function () {
            try {
                me.edEncryptTask.cancel();
                await me.edEncryptNow();
                me.edLocked = true;
                me.edPlainLoaded = false;
                me.edSilent = true;
                me.setRawValue(me.edEnvelope === null ? '' : me.lockedText);
                me.edSilent = false;
                me.setEditable(false);
                me.edUpdateTriggerUi();
            } catch (e) {
                Ext.toast({
                    html: e.message,
                    title: 'Verschlüsselung',
                    align: 't',
                    iconCls: 'fa fa-warning'
                });
            }
        })();
    },

    edUpdateTriggerUi: function () {
        var trigger = this.getTrigger ? this.getTrigger('edlock') : null;
        if (!trigger || !trigger.el) return;
        if (this.edLocked) {
            trigger.el.removeCls('fa-unlock');
            trigger.el.addCls('fa-lock');
            trigger.el.set({ 'data-qtip': 'Entschlüsselt anzeigen / bearbeiten' });
        } else {
            trigger.el.removeCls('fa-lock');
            trigger.el.addCls('fa-unlock');
            trigger.el.set({ 'data-qtip': 'Verschlüsseln und verriegeln' });
        }
    }
});
