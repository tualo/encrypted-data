#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');

function fail(message) {
    console.error(`decrypt-item: ${message}`);
    process.exitCode = 1;
}

async function main() {
    const privateKeyPath = process.argv[2];
    if (!privateKeyPath || process.argv.length !== 3) {
        throw new Error('Usage: decrypt-response.sh PRIVATE_KEY.asc [RESPONSE.json]');
    }

    const privateKey = crypto.createPrivateKey(fs.readFileSync(privateKeyPath));
    const publicDer = crypto.createPublicKey(privateKey).export({
        type: 'spki',
        format: 'der',
    });
    const fingerprint = crypto.createHash('sha256').update(publicDer).digest('hex');
    const inputChunks = [];
    for await (const chunk of process.stdin) inputChunks.push(chunk);
    const input = Buffer.concat(inputChunks).toString('utf8');

    let response;
    try {
        response = JSON.parse(input);
    } catch {
        throw new Error('Input is not valid JSON.');
    }
    if (!response || response.success !== true) {
        throw new Error(response?.msg || 'The API request did not succeed.');
    }

    const item = response.data;
    if (!item || typeof item.iv !== 'string' || typeof item.ciphertext !== 'string') {
        throw new Error('Response does not contain data.iv and data.ciphertext.');
    }
    if (!Array.isArray(response.mykeys)) {
        throw new Error('Response does not contain the mykeys array.');
    }

    const recipientKey = response.mykeys.find((key) => key.fingerprint === fingerprint);
    if (!recipientKey || typeof recipientKey.wrapped_key !== 'string') {
        throw new Error(`No wrapped key for private-key fingerprint ${fingerprint}.`);
    }

    const aesKey = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
    }, Buffer.from(recipientKey.wrapped_key, 'base64'));
    const iv = Buffer.from(item.iv, 'base64');
    const ciphertextAndTag = Buffer.from(item.ciphertext, 'base64');
    if (aesKey.length !== 32) throw new Error('Unwrapped AES key is not 256 bits.');
    if (iv.length !== 12) throw new Error('AES-GCM IV is not 12 bytes.');
    if (ciphertextAndTag.length < 16) throw new Error('AES-GCM ciphertext is missing its authentication tag.');

    const ciphertext = ciphertextAndTag.subarray(0, -16);
    const authTag = ciphertextAndTag.subarray(-16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    process.stdout.write(plaintext);
}

main().catch((error) => fail(error.message));
