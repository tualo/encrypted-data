DELIMITER ;
-- Verschlüsselte Datenelemente (Hybridverschlüsselung).
-- Der Inhalt ist mit einem zufälligen AES-256-GCM-Schlüssel verschlüsselt,
-- der pro Empfänger RSA-OAEP-verschlüsselt in encrypted_data_recipients liegt.
-- Der Server kann den Inhalt zu keinem Zeitpunkt lesen.
CREATE TABLE IF NOT EXISTS `encrypted_data` (
  `id` varchar(36) NOT NULL COMMENT 'UUID',
  `context` varchar(100) NOT NULL DEFAULT '' COMMENT 'Freie Gruppierung, z.B. Modul-/Tabellenname',
  `label` varchar(255) NOT NULL DEFAULT '' COMMENT 'Unverschlüsselter Anzeigename (keine Geheimnisse hier ablegen!)',
  `owner` varchar(50) NOT NULL COMMENT 'Ersteller (Login)',
  `datatype` varchar(20) NOT NULL DEFAULT 'single' COMMENT 'single = einzelnes Datenelement, shared = gemeinsames Datenelement',
  `iv` varchar(64) NOT NULL COMMENT 'AES-GCM Initialisierungsvektor (base64)',
  `ciphertext` mediumtext NOT NULL COMMENT 'AES-256-GCM Ciphertext (base64)',
  `created` datetime NOT NULL DEFAULT current_timestamp(),
  `modified` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_encrypted_data_owner` (`owner`),
  KEY `idx_encrypted_data_context` (`context`)
) ;
