DELIMITER ;

INSERT IGNORE INTO SESSIONDB.`macc_menu` VALUES
('1a3f71e8-1114-410b-8e0f-3b9fadefa89d','Verschlüsselte Daten','',NULL,'',0,NULL,'',0,1,'fa fa-user-secret',''),
('76115d39-348e-4824-ad65-dc4f43fd71b4','Meine Schlüssel','',NULL,'',0,NULL,'1a3f71e8-1114-410b-8e0f-3b9fadefa89d',0,1,'fa fa-key','#encrypted-data/keys'),
('9314b082-d09f-43bb-ae6e-afaff0768bdf','Datenelemente','',NULL,'',1,NULL,'1a3f71e8-1114-410b-8e0f-3b9fadefa89d',0,1,'fa fa-lock','#encrypted-data/items');

INSERT IGNORE INTO SESSIONDB.`rolle_menu` VALUES
('1a3f71e8-1114-410b-8e0f-3b9fadefa89d','administration',NULL),
('76115d39-348e-4824-ad65-dc4f43fd71b4','administration',NULL),
('9314b082-d09f-43bb-ae6e-afaff0768bdf','administration',NULL);
