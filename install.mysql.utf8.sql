CREATE TABLE IF NOT EXISTS `#__abuseipdb_entries` (
  `priority` int(11) DEFAULT NULL,
  `message` varchar(512) DEFAULT NULL,
  `date` datetime DEFAULT NULL,
  `category` varchar(255) DEFAULT NULL,
  KEY `idx_category_date_priority` (`category`,`date`,`priority`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;