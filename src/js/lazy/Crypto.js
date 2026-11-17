/**
 * Tualo.EncryptedData.Crypto
 *
 * Clientseitige Hybridverschlüsselung auf Basis der WebCrypto-API.
 *
 *  - Pro Datenelement wird ein zufälliger AES-256-GCM-Schlüssel erzeugt,
 *    mit dem der Inhalt verschlüsselt wird.
 *  - Dieser AES-Schlüssel wird pro Empfänger mit dessen RSA-4096-Public-Key
 *    (RSA-OAEP, SHA-256) verschlüsselt ("gewrappt").
 *  - Private Schlüssel verlassen den Browser nie.
 *
 * Envelope-Format (JSON, als String z.B. in beliebigen Feldern speicherbar):
 * {
 *   "tualoEncryptedData": 1,
 *   "v": 1,
 *   "alg": "RSA-OAEP-256+A256GCM",
 *   "iv": "<base64>",
 *   "ct": "<base64>",
 *   "keys": { "<fingerprint>": "<base64 gewrappter AES-Schlüssel>" }
 * }
 */
Ext.define('Tualo.EncryptedData.Crypto', {
    singleton: true,

    RSA_PARAMS: {
        name: 'RSA-OAEP',
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
    },

    /* ------------------------------------------------ Hilfsfunktionen */

    bufToB64: function (buf) {
        let bytes = new Uint8Array(buf), bin = '';
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return window.btoa(bin);
    },

    b64ToBuf: function (b64) {
        let bin = window.atob(b64), bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return bytes.buffer;
    },

    bufToHex: function (buf) {
        return Array.prototype.map.call(new Uint8Array(buf), function (b) {
            return ('00' + b.toString(16)).slice(-2);
        }).join('');
    },

    derToPEM: function (der, label) {
        let body = this.bufToB64(der).match(/.{1,64}/g).join('\n');
        return '-----BEGIN ' + label + '-----\n' + body + '\n-----END ' + label + '-----';
    },

    pemToDer: function (pem) {
        let body = pem.replace(/-----(BEGIN|END)[^-]+-----/g, '').replace(/\s+/g, '');
        return this.b64ToBuf(body);
    },

    /* ------------------------------------------------ Schlüsselerzeugung */

    /**
     * Erzeugt ein RSA-4096-Schlüsselpaar.
     * @return {Promise<CryptoKeyPair>} extrahierbares Schlüsselpaar
     */
    generateKeyPair: async function () {
        return await window.crypto.subtle.generateKey(
            this.RSA_PARAMS, true, ['encrypt', 'decrypt']
        );
    },

    exportPublicKeyPEM: async function (publicKey) {
        let spki = await window.crypto.subtle.exportKey('spki', publicKey);
        return this.derToPEM(spki, 'PUBLIC KEY');
    },

    exportPrivateKeyPEM: async function (privateKey) {
        let pkcs8 = await window.crypto.subtle.exportKey('pkcs8', privateKey);
        return this.derToPEM(pkcs8, 'PRIVATE KEY');
    },

    importPublicKeyPEM: async function (pem) {
        return await window.crypto.subtle.importKey(
            'spki', this.pemToDer(pem),
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            true, ['encrypt']
        );
    },

    /**
     * Importiert einen privaten Schlüssel aus einer PEM-Datei.
     * @param {String} pem PKCS8 PEM
     * @param {Boolean} extractable false (Default) für die Ablage im KeyStore
     */
    importPrivateKeyPEM: async function (pem, extractable) {
        return await window.crypto.subtle.importKey(
            'pkcs8', this.pemToDer(pem),
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            extractable === true, ['decrypt']
        );
    },

    /**
     * Leitet aus einem privaten Schlüssel (PEM) den zugehörigen öffentlichen
     * Schlüssel ab (über JWK n/e).
     * @return {Promise<CryptoKey>} öffentlicher Schlüssel
     */
    publicKeyFromPrivatePEM: async function (pem) {
        let priv = await this.importPrivateKeyPEM(pem, true);
        let jwk = await window.crypto.subtle.exportKey('jwk', priv);
        let pubJwk = { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: jwk.alg, ext: true };
        return await window.crypto.subtle.importKey(
            'jwk', pubJwk,
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            true, ['encrypt']
        );
    },

    /**
     * SHA-256-Fingerprint (hex, lowercase) über den DER-kodierten SPKI
     * Public Key. Serverseitig identisch berechnet (Routes/Keys.php).
     * @param {CryptoKey|String} publicKey CryptoKey oder PEM
     * @return {Promise<String>}
     */
    fingerprint: async function (publicKey) {
        let spki;
        if (Ext.isString(publicKey)) {
            spki = this.pemToDer(publicKey);
        } else {
            spki = await window.crypto.subtle.exportKey('spki', publicKey);
        }
        let hash = await window.crypto.subtle.digest('SHA-256', spki);
        return this.bufToHex(hash);
    },

    /** Darstellung des Fingerprints in Gruppen zum manuellen Abgleich */
    formatFingerprint: function (fp) {
        return (fp || '').toUpperCase().match(/.{1,4}/g).join(' ');
    },

    /* ------------------------------------------------ Ver-/Entschlüsselung */

    /**
     * Verschlüsselt einen Text für eine Liste von Empfängern.
     * @param {String} plaintext
     * @param {Array} recipients [{fingerprint, publickey(PEM)}, ...]
     * @return {Promise<Object>} Envelope-Objekt
     */
    encrypt: async function (plaintext, recipients) {
        if (!recipients || recipients.length === 0) {
            throw new Error('Es muss mindestens ein Empfänger angegeben werden');
        }
        let aesKey = await window.crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 }, true, ['encrypt']
        );
        let iv = window.crypto.getRandomValues(new Uint8Array(12));
        let ct = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            aesKey,
            new TextEncoder().encode(plaintext)
        );
        let rawKey = await window.crypto.subtle.exportKey('raw', aesKey);
        let keys = {};
        for (let i = 0; i < recipients.length; i++) {
            let pub = await this.importPublicKeyPEM(recipients[i].publickey);
            let wrapped = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, rawKey);
            keys[recipients[i].fingerprint] = this.bufToB64(wrapped);
        }
        return {
            tualoEncryptedData: 1,
            v: 1,
            alg: 'RSA-OAEP-256+A256GCM',
            iv: this.bufToB64(iv),
            ct: this.bufToB64(ct),
            keys: keys
        };
    },

    /**
     * Entschlüsselt den AES-Rohschlüssel eines Envelopes/Datenelements.
     * @param {CryptoKey} privateKey
     * @param {String} wrappedKeyB64
     * @return {Promise<ArrayBuffer>} AES-256-Rohschlüssel
     */
    unwrapKey: async function (privateKey, wrappedKeyB64) {
        return await window.crypto.subtle.decrypt(
            { name: 'RSA-OAEP' }, privateKey, this.b64ToBuf(wrappedKeyB64)
        );
    },

    /**
     * Verschlüsselt einen AES-Rohschlüssel für einen weiteren Empfänger
     * (Teilen eines bestehenden Datenelements).
     * @param {ArrayBuffer} rawKey
     * @param {String} publicKeyPEM
     * @return {Promise<String>} base64 gewrappter Schlüssel
     */
    wrapKeyFor: async function (rawKey, publicKeyPEM) {
        let pub = await this.importPublicKeyPEM(publicKeyPEM);
        let wrapped = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, rawKey);
        return this.bufToB64(wrapped);
    },

    /**
     * Entschlüsselt Ciphertext mit einem AES-Rohschlüssel.
     * @param {ArrayBuffer} rawKey
     * @param {String} ivB64
     * @param {String} ctB64
     * @return {Promise<String>} Klartext
     */
    decryptWithRawKey: async function (rawKey, ivB64, ctB64) {
        let aesKey = await window.crypto.subtle.importKey(
            'raw', rawKey, 'AES-GCM', false, ['decrypt']
        );
        let plain = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: this.b64ToBuf(ivB64) },
            aesKey,
            this.b64ToBuf(ctB64)
        );
        return new TextDecoder().decode(plain);
    },

    /**
     * Entschlüsselt ein komplettes Envelope mit einem privaten Schlüssel.
     * @param {CryptoKey} privateKey
     * @param {String} fingerprint Fingerprint des zugehörigen Public Keys
     * @param {Object} envelope
     * @return {Promise<String>} Klartext
     */
    decryptEnvelope: async function (privateKey, fingerprint, envelope) {
        if (!envelope.keys || !envelope.keys[fingerprint]) {
            throw new Error('Für diesen Schlüssel liegt kein Zugang zum Datenelement vor');
        }
        let rawKey = await this.unwrapKey(privateKey, envelope.keys[fingerprint]);
        return await this.decryptWithRawKey(rawKey, envelope.iv, envelope.ct);
    },

    /* ------------------------------------------------ Envelope-Helfer */

    isEnvelope: function (value) {
        if (!Ext.isString(value) || value.indexOf('"tualoEncryptedData"') === -1) return false;
        try {
            let o = JSON.parse(value);
            return o && o.tualoEncryptedData === 1 && Ext.isString(o.iv) && Ext.isString(o.ct) && Ext.isObject(o.keys);
        } catch (e) {
            return false;
        }
    },

    parseEnvelope: function (value) {
        return JSON.parse(value);
    },

    stringifyEnvelope: function (envelope) {
        return JSON.stringify(envelope);
    },

    /* ------------------------------------------------ Server-Schlüssel */

    /**
     * Lädt alle aktiven Public Keys vom Server.
     * @param {Boolean} reload Cache umgehen
     * @return {Promise<Array>} [{fingerprint, username, keyname, publickey, own}]
     */
    loadPublicKeys: async function (reload) {
        if (!reload && this._publicKeys) return this._publicKeys;
        let response = await fetch('./encrypted-data/keys', {
            headers: { 'Accept': 'application/json' }
        });
        let o = await response.json();
        if (!o.success) throw new Error(o.msg || 'Schlüssel konnten nicht geladen werden');
        this._publicKeys = o.data;
        return this._publicKeys;
    },

    /** Eigene aktive Public Keys (Datensätze) vom Server */
    myPublicKeys: async function (reload) {
        let keys = await this.loadPublicKeys(reload);
        return keys.filter(function (k) { return k.own == 1 || k.own === true; });
    },

    /**
     * Sucht einen eigenen Schlüssel, dessen privater Teil im Browser
     * (KeyStore) verfügbar ist.
     * @return {Promise<Object|null>} {fingerprint, keyname, publickey, privateKey}
     */
    availableOwnKey: async function () {
        let own = await this.myPublicKeys();
        for (let i = 0; i < own.length; i++) {
            let priv = await Tualo.EncryptedData.KeyStore.getPrivateKey(own[i].fingerprint);
            if (priv) {
                return Ext.apply({ privateKey: priv.privateKey }, own[i]);
            }
        }
        return null;
    },

    /**
     * Erzeugt ein Schlüsselpaar, registriert den Public Key am Server,
     * legt den privaten Schlüssel im KeyStore ab und liefert das
     * private PEM für den Datei-Download zurück.
     * @param {String} keyname
     * @return {Promise<Object>} {fingerprint, privatePEM, publicPEM}
     */
    generateAndRegister: async function (keyname) {
        let pair = await this.generateKeyPair();
        let publicPEM = await this.exportPublicKeyPEM(pair.publicKey);
        let privatePEM = await this.exportPrivateKeyPEM(pair.privateKey);
        let fp = await this.fingerprint(pair.publicKey);

        let response = await fetch('./encrypted-data/keys/register', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: (new URLSearchParams({
                publickey: publicPEM,
                keyname: keyname
            })).toString()
        });
        let o = await response.json();
        if (!o.success) throw new Error(o.msg || 'Der Schlüssel konnte nicht registriert werden');

        // nicht extrahierbar im Browser ablegen
        let storedPriv = await this.importPrivateKeyPEM(privatePEM, false);
        await Tualo.EncryptedData.KeyStore.savePrivateKey(fp, keyname, storedPriv);

        this._publicKeys = null; // Cache invalidieren
        return { fingerprint: fp, privatePEM: privatePEM, publicPEM: publicPEM };
    },

    /** Startet einen Datei-Download (z.B. für das private PEM). */
    download: function (filename, text) {
        let element = document.createElement('a');
        element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
        element.setAttribute('download', filename);
        element.style.display = 'none';
        document.body.appendChild(element);
        element.click();
        document.body.removeChild(element);
    }
});
