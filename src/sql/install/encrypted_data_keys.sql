DELIMITER ;
-- Öffentliche Schlüssel der Nutzer / Dienste.
-- Private Schlüssel werden hier NIEMALS gespeichert, sie verlassen den Browser nicht.
CREATE TABLE IF NOT EXISTS `encrypted_data_keys` (
  `fingerprint` varchar(64) NOT NULL COMMENT 'SHA-256 Fingerprint (hex) über den DER-kodierten SPKI Public Key',
  `username` varchar(50) NOT NULL COMMENT 'Besitzer des Schlüssels (Login)',
  `keyname` varchar(100) NOT NULL COMMENT 'Anzeigename des Schlüssels',
  `publickey` text NOT NULL COMMENT 'PEM (SPKI) RSA-4096 Public Key',
  `created` datetime NOT NULL DEFAULT current_timestamp(),
  `revoked` datetime DEFAULT NULL COMMENT 'Zeitpunkt des Widerrufs, NULL = aktiv',
  PRIMARY KEY (`fingerprint`),
  KEY `idx_encrypted_data_keys_username` (`username`)
) ;
