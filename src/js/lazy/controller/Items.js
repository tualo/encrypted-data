Ext.define('Tualo.EncryptedData.controller.Items', {
    extend: 'Ext.app.ViewController',
    alias: 'controller.encrypteddata_items_controller',

    requires: [
        'Tualo.EncryptedData.Crypto',
        'Tualo.EncryptedData.KeyStore'
    ],

    onReady: function () {
        this.loadItems();
    },

    toast: function (title, html) {
        Ext.toast({ html: html, title: title, align: 't', iconCls: 'fa fa-warning' });
    },

    fetchJSON: async function (url, params) {
        var options = { headers: { 'Accept': 'application/json' } };
        if (params) {
            options.method = 'POST';
            options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
            options.body = (new URLSearchParams(params)).toString();
        }
        var response = await fetch(url, options);
        var o = await response.json();
        if (!o.success) throw new Error(o.msg || 'Anfrage fehlgeschlagen');
        return o;
    },

    loadItems: function () {
        var me = this;
        (async function () {
            try {
                var o = await me.fetchJSON('./encrypted-data/list');
                me.getViewModel().getStore('items').setData(o.data);
            } catch (e) {
                me.toast('Fehler', e.message);
            }
        })();
    },

    selectedItem: function () {
        var selection = this.lookup('itemsgrid').getSelection();
        return selection.length > 0 ? selection[0] : null;
    },

    /**
     * Entschlüsselt den AES-Rohschlüssel eines Datenelements mit einem
     * lokal verfügbaren privaten Schlüssel.
     * @return {Promise<Object>} {rawKey, item, recipients}
     */
    unwrapItem: async function (id) {
        var Crypto = Tualo.EncryptedData.Crypto;
        var KeyStore = Tualo.EncryptedData.KeyStore;
        var o = await this.fetchJSON('./encrypted-data/get/' + id);
        for (var i = 0; i < o.mykeys.length; i++) {
            var stored = await KeyStore.getPrivateKey(o.mykeys[i].fingerprint);
            if (stored) {
                var rawKey = await Crypto.unwrapKey(stored.privateKey, o.mykeys[i].wrapped_key);
                return { rawKey: rawKey, item: o.data, recipients: o.recipients };
            }
        }
        throw new Error('In diesem Browser ist kein passender privater Schlüssel hinterlegt. ' +
            'Bitte importieren Sie Ihren privaten Schlüssel unter "Meine Schlüssel".');
    },

    /* ------------------------------------------------ Neu */

    createItem: function () {
        var me = this;
        (async function () {
            try {
                var keys = await Tualo.EncryptedData.Crypto.loadPublicKeys(true);
                var own = keys.filter(function (k) { return k.own == 1 || k.own === true; });
                if (own.length === 0) {
                    throw new Error('Kein eigener Schlüssel vorhanden. Bitte zuerst unter "Meine Schlüssel" einen Schlüssel erzeugen.');
                }
                var win = Ext.create('Ext.window.Window', {
                    title: 'Neues verschlüsseltes Datenelement',
                    modal: true,
                    width: 600,
                    layout: 'fit',
                    items: [{
                        xtype: 'form',
                        bodyPadding: 15,
                        defaults: { anchor: '100%', labelAlign: 'top' },
                        items: [
                            { xtype: 'textfield', name: 'label', fieldLabel: 'Bezeichnung (unverschlüsselt!)' },
                            { xtype: 'textfield', name: 'context', fieldLabel: 'Kontext (optional, unverschlüsselt)' },
                            {
                                xtype: 'tagfield',
                                name: 'recipients',
                                fieldLabel: 'Empfänger',
                                displayField: 'display',
                                valueField: 'fingerprint',
                                queryMode: 'local',
                                store: {
                                    fields: ['fingerprint', 'display', 'publickey'],
                                    data: keys.map(function (k) {
                                        return {
                                            fingerprint: k.fingerprint,
                                            publickey: k.publickey,
                                            display: k.username + ' / ' + k.keyname
                                        };
                                    })
                                },
                                value: own.map(function (k) { return k.fingerprint; })
                            },
                            { xtype: 'textarea', name: 'plaintext', fieldLabel: 'Inhalt (wird verschlüsselt)', height: 160 }
                        ],
                        buttons: [{
                            text: 'Verschlüsselt speichern',
                            iconCls: 'fa fa-lock',
                            handler: function () {
                                var form = this.up('form');
                                var values = form.getValues();
                                var fps = form.down('tagfield').getValue() || [];
                                (async function () {
                                    try {
                                        if (fps.length === 0) throw new Error('Es muss mindestens ein Empfänger ausgewählt werden');
                                        var recipients = keys.filter(function (k) {
                                            return fps.indexOf(k.fingerprint) !== -1;
                                        });
                                        var Crypto = Tualo.EncryptedData.Crypto;
                                        var envelope = await Crypto.encrypt(values.plaintext || '', recipients);
                                        var wrapped = Object.keys(envelope.keys).map(function (fp) {
                                            return { fingerprint: fp, wrapped_key: envelope.keys[fp] };
                                        });
                                        await me.fetchJSON('./encrypted-data/save', {
                                            label: values.label || '',
                                            context: values.context || '',
                                            datatype: wrapped.length > 1 ? 'shared' : 'single',
                                            iv: envelope.iv,
                                            ciphertext: envelope.ct,
                                            recipients: JSON.stringify(wrapped)
                                        });
                                        win.close();
                                        me.loadItems();
                                    } catch (e) {
                                        me.toast('Fehler', e.message);
                                    }
                                })();
                            }
                        }]
                    }]
                });
                win.show();
            } catch (e) {
                me.toast('Fehler', e.message);
            }
        })();
    },

    /* ------------------------------------------------ Anzeigen */

    viewItem: function () {
        var me = this;
        var rec = this.selectedItem();
        if (!rec) { me.toast('Hinweis', 'Bitte ein Datenelement auswählen.'); return; }
        (async function () {
            try {
                var Crypto = Tualo.EncryptedData.Crypto;
                var unwrapped = await me.unwrapItem(rec.get('id'));
                var plaintext = await Crypto.decryptWithRawKey(unwrapped.rawKey, unwrapped.item.iv, unwrapped.item.ciphertext);
                var recipientsHtml = unwrapped.recipients.map(function (r) {
                    return Ext.String.htmlEncode(r.username + ' / ' + r.keyname);
                }).join('<br>');
                Ext.create('Ext.window.Window', {
                    title: 'Datenelement: ' + Ext.String.htmlEncode(rec.get('label') || rec.get('id')),
                    modal: true,
                    width: 600,
                    layout: 'fit',
                    items: [{
                        xtype: 'form',
                        bodyPadding: 15,
                        defaults: { anchor: '100%', labelAlign: 'top' },
                        items: [
                            { xtype: 'textarea', fieldLabel: 'Entschlüsselter Inhalt', value: plaintext, readOnly: true, height: 160 },
                            { xtype: 'displayfield', fieldLabel: 'Empfänger', value: recipientsHtml }
                        ]
                    }]
                }).show();
            } catch (e) {
                me.toast('Fehler', e.message);
            }
        })();
    },

    /* ------------------------------------------------ Teilen */

    shareItem: function () {
        var me = this;
        var rec = this.selectedItem();
        if (!rec) { me.toast('Hinweis', 'Bitte ein Datenelement auswählen.'); return; }
        (async function () {
            try {
                var Crypto = Tualo.EncryptedData.Crypto;
                var unwrapped = await me.unwrapItem(rec.get('id'));
                var existing = unwrapped.recipients.map(function (r) { return r.fingerprint; });
                var keys = await Crypto.loadPublicKeys(true);
                var candidates = keys.filter(function (k) {
                    return existing.indexOf(k.fingerprint) === -1;
                });
                if (candidates.length === 0) throw new Error('Es gibt keine weiteren registrierten Schlüssel zum Teilen.');
                var win = Ext.create('Ext.window.Window', {
                    title: 'Teilen: ' + Ext.String.htmlEncode(rec.get('label') || rec.get('id')),
                    modal: true,
                    width: 500,
                    layout: 'fit',
                    items: [{
                        xtype: 'form',
                        bodyPadding: 15,
                        defaults: { anchor: '100%', labelAlign: 'top' },
                        items: [{
                            xtype: 'tagfield',
                            fieldLabel: 'Neue Empfänger',
                            displayField: 'display',
                            valueField: 'fingerprint',
                            queryMode: 'local',
                            store: {
                                fields: ['fingerprint', 'display'],
                                data: candidates.map(function (k) {
                                    return {
                                        fingerprint: k.fingerprint,
                                        display: k.username + ' / ' + k.keyname
                                    };
                                })
                            }
                        }],
                        buttons: [{
                            text: 'Teilen',
                            iconCls: 'fa fa-share-alt',
                            handler: function () {
                                var fps = this.up('form').down('tagfield').getValue() || [];
                                (async function () {
                                    try {
                                        if (fps.length === 0) throw new Error('Bitte mindestens einen Empfänger auswählen');
                                        var wrapped = [];
                                        for (var i = 0; i < candidates.length; i++) {
                                            if (fps.indexOf(candidates[i].fingerprint) === -1) continue;
                                            wrapped.push({
                                                fingerprint: candidates[i].fingerprint,
                                                wrapped_key: await Crypto.wrapKeyFor(unwrapped.rawKey, candidates[i].publickey)
                                            });
                                        }
                                        await me.fetchJSON('./encrypted-data/share', {
                                            id: rec.get('id'),
                                            recipients: JSON.stringify(wrapped)
                                        });
                                        win.close();
                                        me.loadItems();
                                    } catch (e) {
                                        me.toast('Fehler', e.message);
                                    }
                                })();
                            }
                        }]
                    }]
                });
                win.show();
            } catch (e) {
                me.toast('Fehler', e.message);
            }
        })();
    },

    /* ------------------------------------------------ Löschen */

    deleteItem: function () {
        var me = this;
        var rec = this.selectedItem();
        if (!rec) { me.toast('Hinweis', 'Bitte ein Datenelement auswählen.'); return; }
        Ext.Msg.confirm(
            'Löschen',
            'Datenelement "' + Ext.String.htmlEncode(rec.get('label') || rec.get('id')) + '" unwiederbringlich löschen?',
            function (btn) {
                if (btn !== 'yes') return;
                (async function () {
                    try {
                        await me.fetchJSON('./encrypted-data/delete', { id: rec.get('id') });
                        me.loadItems();
                    } catch (e) {
                        me.toast('Fehler', e.message);
                    }
                })();
            }
        );
    }
});
