/**
 * Tualo.EncryptedData.KeyStore
 *
 * Ablage privater Schlüssel in der IndexedDB des Browsers.
 *
 * Die Schlüssel werden als nicht-extrahierbare CryptoKey-Objekte gespeichert:
 * Sie können von Skripten der gleichen Origin zum Entschlüsseln VERWENDET,
 * aber nicht exportiert werden. Die Ablage ist an Gerät + Browser(-Profil)
 * gebunden - die heruntergeladene PEM-Datei bleibt das einzige Backup.
 */
Ext.define('Tualo.EncryptedData.KeyStore', {
    singleton: true,

    DB_NAME: 'tualo-encrypted-data',
    DB_VERSION: 1,
    STORE: 'privatekeys',

    _open: function () {
        let me = this;
        return new Promise(function (resolve, reject) {
            let request = window.indexedDB.open(me.DB_NAME, me.DB_VERSION);
            request.onupgradeneeded = function (event) {
                let db = event.target.result;
                if (!db.objectStoreNames.contains(me.STORE)) {
                    db.createObjectStore(me.STORE, { keyPath: 'fingerprint' });
                }
            };
            request.onsuccess = function (event) { resolve(event.target.result); };
            request.onerror = function (event) { reject(event.target.error); };
        });
    },

    _tx: function (mode, fn) {
        let me = this;
        return this._open().then(function (db) {
            return new Promise(function (resolve, reject) {
                let tx = db.transaction(me.STORE, mode);
                let store = tx.objectStore(me.STORE);
                let result = fn(store);
                tx.oncomplete = function () { db.close(); resolve(result.result); };
                tx.onerror = function (event) { db.close(); reject(event.target.error); };
            });
        });
    },

    /**
     * Privaten Schlüssel ablegen.
     * @param {String} fingerprint
     * @param {String} keyname
     * @param {CryptoKey} privateKey nicht-extrahierbarer CryptoKey
     */
    savePrivateKey: function (fingerprint, keyname, privateKey) {
        return this._tx('readwrite', function (store) {
            return store.put({
                fingerprint: fingerprint,
                keyname: keyname,
                privateKey: privateKey,
                created: (new Date()).toISOString()
            });
        });
    },

    /**
     * Privaten Schlüssel lesen.
     * @return {Promise<Object|null>} {fingerprint, keyname, privateKey, created}
     */
    getPrivateKey: function (fingerprint) {
        return this._tx('readonly', function (store) {
            return store.get(fingerprint);
        }).then(function (row) {
            return row || null;
        });
    },

    /** Alle lokal verfügbaren Schlüssel (Metadaten + CryptoKey) */
    listKeys: function () {
        return this._tx('readonly', function (store) {
            return store.getAll();
        }).then(function (rows) {
            return rows || [];
        });
    },

    /** Privaten Schlüssel aus diesem Browser entfernen */
    removeKey: function (fingerprint) {
        return this._tx('readwrite', function (store) {
            return store.delete(fingerprint);
        });
    }
});
