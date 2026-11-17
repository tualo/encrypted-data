DELIMITER ;
-- Empfänger eines Datenelements: pro Empfänger-Schlüssel der
-- RSA-OAEP-verschlüsselte ("gewrappte") AES-Inhaltsschlüssel.
-- Das Wrapping geschieht ausschließlich clientseitig im Browser.
CREATE TABLE IF NOT EXISTS `encrypted_data_recipients` (
  `data_id` varchar(36) NOT NULL,
  `fingerprint` varchar(64) NOT NULL COMMENT 'Fingerprint des Empfänger-Public-Keys (encrypted_data_keys)',
  `wrapped_key` text NOT NULL COMMENT 'RSA-OAEP-verschlüsselter AES-256-Schlüssel (base64)',
  `added_by` varchar(50) NOT NULL DEFAULT '' COMMENT 'Wer diesen Empfänger hinzugefügt hat (Login)',
  `created` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`data_id`, `fingerprint`),
  KEY `idx_encrypted_data_recipients_fingerprint` (`fingerprint`)
) ;
