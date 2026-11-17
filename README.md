# tualo/encrypted-data

Clientseitig verschlüsselte Datenelemente für tualo Office.

Informationen werden **im Browser** ver- und entschlüsselt und nur als
Ciphertext in der Datenbank abgelegt. Öffentliche Schlüssel der Nutzer werden
in der Datenbank gespeichert; **private Schlüssel verlassen den Browser nie**
und landen zu keinem Zeitpunkt auf dem Server.

## Inhalt

- [Konzept](#konzept)
- [Kryptografie](#kryptografie)
- [Datenmodell](#datenmodell)
- [Installation](#installation)
- [HTTP-API](#http-api)
- [ExtJS-Steuerelemente](#extjs-steuerelemente)
- [Views](#views)
- [Envelope-Format](#envelope-format)
- [Sicherheitsmodell und Grenzen](#sicherheitsmodell-und-grenzen)

## Konzept

Es gibt zwei Typen von Datenelementen:

- **Einzelnes Datenelement** (`single`): nur für den Besitzer selbst
  verschlüsselt (Empfänger = eigener Schlüssel).
- **Gemeinsames Datenelement** (`shared`): mit anderen Nutzern oder Diensten
  geteilt. Alle Parteien müssen vorab einen öffentlichen Schlüssel im System
  abgelegt haben. Teilt Person A mit Person B, verschlüsselt Person A den
  Inhaltsschlüssel **clientseitig** mit dem öffentlichen Schlüssel von
  Person B.

Die Schlüsselerzeugung erfolgt wie im Package `onlinevote` im Browser
(WebCrypto). Der öffentliche Schlüssel wird in der Datenbank registriert, der
private Schlüssel wird als PEM-Datei heruntergeladen (einziges Backup!) und
zusätzlich als **nicht-extrahierbarer** `CryptoKey` in der IndexedDB des
Browsers abgelegt.

## Kryptografie

Hybridverschlüsselung (analog zur Arbeitsweise von PGP):

1. Pro Datenelement wird ein zufälliger **AES-256-GCM**-Schlüssel erzeugt,
   mit dem der Inhalt verschlüsselt wird (12-Byte-IV, authentifiziert durch
   GCM).
2. Der AES-Schlüssel wird pro Empfänger mit dessen
   **RSA-4096 / RSA-OAEP (SHA-256)**-Public-Key verschlüsselt ("gewrappt").
3. Teilen = der Berechtigte entschlüsselt den AES-Schlüssel mit seinem
   privaten Schlüssel und wrappt ihn für den neuen Empfänger neu — alles
   im Browser.

Dadurch gibt es pro Datenelement genau einen Ciphertext, unabhängig von der
Anzahl der Empfänger, und beliebig große Inhalte sind möglich (reines RSA
könnte nur ~450 Bytes verschlüsseln).

**Hinweis zur Begrifflichkeit:** Verschlüsselt wird immer mit dem
*öffentlichen* Schlüssel (auch für sich selbst), entschlüsselt mit dem
*privaten*. Schlüsselformate (PEM/SPKI, RSA-OAEP) sind kompatibel zu
`tualo/tualopgp` (phpseclib), falls ein Dienst serverseitig als Empfänger
agieren soll.

Fingerprint eines Schlüssels: `SHA-256` (hex, lowercase) über den
DER-kodierten SPKI-Public-Key — client- und serverseitig identisch berechnet
(`Tualo.EncryptedData.Crypto.fingerprint` bzw.
`Tualo\Office\EncryptedData\Routes\Keys::fingerprint`).

## Datenmodell

| Tabelle | Inhalt |
|---|---|
| `encrypted_data_keys` | Öffentliche Schlüssel: `fingerprint` (PK), `username`, `keyname`, `publickey` (PEM), `created`, `revoked` |
| `encrypted_data` | Datenelemente: `id` (UUID), `context`, `label`, `owner`, `datatype` (`single`/`shared`), `iv`, `ciphertext`, `created`, `modified` |
| `encrypted_data_recipients` | Pro Empfänger der gewrappte AES-Schlüssel: `data_id`, `fingerprint`, `wrapped_key`, `added_by`, `created` |

`label` und `context` sind **unverschlüsselte** Metadaten — dort dürfen keine
Geheimnisse abgelegt werden.

## Installation

```bash
./tm install-sql-encrypted-data --client <client>
```

Optional Menüeinträge (SESSIONDB): `src/sql/menu/base.sql`
(Hauptmenü „Verschlüsselte Daten“ mit `#encrypted-data/keys` und
`#encrypted-data/items`, Rolle `administration`).

Der Post-Check `Checks/Tables.php` meldet fehlende Tabellen.

## HTTP-API

Alle Routen erfordern eine eingeloggte Session (Scope `encrypted-data`) und
liefern JSON (`success`, `msg`, ...).

### Schlüssel

| Route | Methode | Beschreibung |
|---|---|---|
| `/encrypted-data/keys/register` | POST | Eigenen Public Key registrieren (`publickey` PEM, `keyname`). Private Keys werden abgewiesen, RSA ≥ 2048 Bit erzwungen, Fingerprint wird serverseitig berechnet. |
| `/encrypted-data/keys` | GET | Alle aktiven Public Keys (für die Empfängerauswahl). |
| `/encrypted-data/keys/my` | GET | Eigene Schlüssel inkl. widerrufener. |
| `/encrypted-data/keys/revoke` | POST | Eigenen Schlüssel widerrufen (`fingerprint`). |

### Datenelemente

| Route | Methode | Beschreibung |
|---|---|---|
| `/encrypted-data/save` | POST | Anlegen/Überschreiben (`id?`, `context?`, `label?`, `datatype`, `iv`, `ciphertext`, `recipients` als JSON `[{fingerprint, wrapped_key}]`). Überschreiben nur durch den Besitzer; dabei müssen alle Empfänger neu gewrappt mitgeliefert werden. |
| `/encrypted-data/list` | GET | Metadaten aller Elemente, bei denen man Besitzer oder Empfänger ist. |
| `/encrypted-data/get/<id>` | GET | Element inkl. `iv`/`ciphertext`; gewrappte Schlüssel (`mykeys`) nur für die eigenen Schlüssel; `recipients` als Anzeige-Liste. |
| `/encrypted-data/share` | POST | Weitere Empfänger hinzufügen (`id`, `recipients` JSON). Erlaubt für Besitzer und Empfänger — nur sie können den AES-Schlüssel clientseitig neu wrappen. |
| `/encrypted-data/unshare` | POST | Empfänger entfernen (`id`, `fingerprint`), nur Besitzer. Rein organisatorisch, s. [Grenzen](#sicherheitsmodell-und-grenzen). |
| `/encrypted-data/delete` | POST | Element löschen (`id`), nur Besitzer. |

## ExtJS-Steuerelemente

Lazy-Klassen werden über `Ext.Loader` (`Tualo.EncryptedData` →
`./jsencrypteddata`) nachgeladen.

### `encrypteddatafield` / `encrypteddataarea`

Verschlüsseltes Textfeld (`Ext.form.field.Text`) bzw. Textarea
(`Ext.form.field.TextArea`) mit Schloss-Trigger zum Umschalten zwischen
ver- und entschlüsselter Ansicht:

```js
{
    xtype: 'encrypteddataarea',
    fieldLabel: 'Geheime Notizen',
    name: 'secret',
    // optional: zusätzliche Empfänger-Fingerprints,
    // eigene aktive Schlüssel werden immer ergänzt
    recipients: ['<fingerprint-von-person-b>']
}
```

Verhalten:

- **Verriegelt** (Standard): zeigt `••••• verschlüsselt •••••`, nicht
  editierbar. Der Feldwert ist der Envelope-JSON-String.
- **Entriegelt** (Klick auf das Schloss): entschlüsselt mit dem privaten
  Schlüssel aus der IndexedDB und zeigt den Klartext editierbar an.
  Änderungen werden gepuffert (400 ms) sowie bei `blur` automatisch neu
  verschlüsselt.
- `getValue()` / `getSubmitValue()` liefern **immer den Envelope, nie den
  Klartext**.
- Vor programmatischem Submit: `await field.ensureEncrypted()` aufrufen,
  damit eine laufende Verschlüsselung abgeschlossen ist.
- Events: `encrypted(field, envelope)`, `encryptionfailed(field, error)`.

### Hilfsklassen

- `Tualo.EncryptedData.Crypto` — WebCrypto-Helfer: Schlüsselerzeugung,
  PEM-Import/-Export, Fingerprints, `encrypt`, `decryptEnvelope`,
  `unwrapKey`/`wrapKeyFor` (Teilen), `generateAndRegister`.
- `Tualo.EncryptedData.KeyStore` — private Schlüssel als nicht-extrahierbare
  `CryptoKey`-Objekte in der IndexedDB (`tualo-encrypted-data`).

## Views

- `#encrypted-data/keys` — Schlüsselverwaltung: erzeugen (mit PEM-Download),
  privaten Schlüssel importieren (nur lokal), widerrufen, aus dem Browser
  entfernen. Zeigt an, ob der private Schlüssel im aktuellen Browser
  verfügbar ist.
- `#encrypted-data/items` — Datenelemente: anlegen, entschlüsselt anzeigen,
  teilen, löschen.

## Envelope-Format

Selbstbeschreibender JSON-String, der auch außerhalb der
`encrypted_data`-Tabellen (z.B. in beliebigen Formularfeldern) gespeichert
werden kann:

```json
{
  "tualoEncryptedData": 1,
  "v": 1,
  "alg": "RSA-OAEP-256+A256GCM",
  "iv": "<base64>",
  "ct": "<base64>",
  "keys": {
    "<fingerprint>": "<base64 gewrappter AES-256-Schlüssel>"
  }
}
```

## Sicherheitsmodell und Grenzen

Was das Package leistet:

- **Server-Betreiber können Inhalte nicht lesen.** Auf dem Server liegen nur
  Ciphertext, IVs und RSA-gewrappte Schlüssel.
- Private Schlüssel existieren nur als Download-Datei beim Nutzer und als
  nicht-extrahierbarer `CryptoKey` in der Browser-IndexedDB.
- AES-GCM authentifiziert den Ciphertext (Manipulation fällt beim
  Entschlüsseln auf).
- Der Server validiert hochgeladene Public Keys (RSA ≥ 2048, keine privaten
  Schlüssel) und berechnet Fingerprints selbst.

Bewusste Entscheidungen / Grenzen — **bitte bei der Nutzung beachten**:

1. **Schlüsselverlust = Datenverlust.** Es gibt bewusst keinen
   Recovery-/Escrow-Schlüssel. Geht die private PEM-Datei verloren und ist
   der Schlüssel in keinem Browser mehr hinterlegt, sind die Daten
   unwiederbringlich verloren. Die PEM-Datei muss sicher verwahrt werden
   (Passwortmanager, Tresor).
2. **Vertrauensmodell Public Keys:** Die Zuordnung Schlüssel ↔ Nutzer trifft
   der Server. Ein kompromittierter Server könnte beim Teilen einen fremden
   Public Key unterschieben und so künftig geteilte Inhalte mitlesen
   (Machine-in-the-Middle). Abschwächung: Die UI zeigt Fingerprints an —
   bei sensiblen Daten Fingerprints über einen zweiten Kanal (Telefon,
   persönlich) abgleichen. Ein Web-of-Trust/Key-Signing ist nicht
   implementiert.
3. **Code-Vertrauen:** Wie bei jeder Web-Anwendung führt der Browser den vom
   Server gelieferten JavaScript-Code aus. Ein kompromittierter Server
   könnte Code ausliefern, der Klartexte exfiltriert. Das Modell schützt
   gegen passive Einsicht (DB-Dumps, Backups, DB-Admins), nicht gegen einen
   aktiv bösartigen Anwendungsserver.
4. **`unshare` ist organisatorisch:** Was ein Empfänger bereits
   entschlüsselt hat (oder dessen gewrappten Schlüssel er kopiert hat), kann
   technisch nicht zurückgeholt werden. Für echten Entzug: Inhalt neu
   verschlüsseln (neuer AES-Schlüssel über `save` durch den Besitzer) und
   nur an die verbleibenden Empfänger wrappen.
5. **Metadaten sind sichtbar:** `label`, `context`, Besitzer, Empfängerliste
   und Zeitstempel sind unverschlüsselt. Keine Geheimnisse in `label`/
   `context` ablegen.
6. **IndexedDB-Ablage:** Nicht-extrahierbare Schlüssel können nicht
   exportiert, aber von Skripten derselben Origin *verwendet* werden
   (XSS-Risiko besteht wie bei jeder Session). Die Ablage ist an
   Gerät + Browser-Profil gebunden; auf neuen Geräten muss die PEM-Datei
   importiert werden.
7. **Widerruf (`revoke`):** verhindert nur neue Verschlüsselungen an diesen
   Schlüssel; bestehende Daten bleiben mit ihm lesbar.
