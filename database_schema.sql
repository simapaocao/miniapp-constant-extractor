-- ============================================================
-- Mini-App Security Scanner - Database Schema
-- Generated automatically. DO NOT EDIT DIRECTLY.
-- ============================================================
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;
-- ============================================================
-- 1. MiniApp Table
-- ============================================================
DROP TABLE IF EXISTS `miniapp_meta`;
CREATE TABLE `miniapp_meta` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `appid` VARCHAR(32) NOT NULL UNIQUE COMMENT 'WeChat AppID',
    `name` VARCHAR(255) COMMENT 'App Name',
    `description` TEXT COMMENT 'App Description',
    `latest_version` VARCHAR(32) COMMENT 'Latest Scanned Version',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
-- ============================================================
-- 2. Data Item Type Table (Single Level, 51 Types)
-- ============================================================
DROP TABLE IF EXISTS `data_item_type`;
CREATE TABLE `data_item_type` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `slug` VARCHAR(50) NOT NULL COMMENT 'Unique Identifier (e.g., url_admin)',
    `category` VARCHAR(32) NOT NULL COMMENT 'Grouping Category (e.g., url, key)',
    `risk_level` TINYINT UNSIGNED DEFAULT 0 COMMENT 'Risk Level 0-5',
    `description` VARCHAR(255) COMMENT 'Data Type Description',
    UNIQUE KEY `ux_type_slug` (`slug`),
    INDEX `idx_category` (`category`),
    INDEX `idx_risk_level` (`risk_level`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
-- {{ INSERT_DATA_ITEM_TYPE }}
-- ============================================================
-- 3. Data Item Table (The Found Secrets)
-- ============================================================
DROP TABLE IF EXISTS `data_item`;
CREATE TABLE `data_item` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `type_id` INT UNSIGNED NOT NULL COMMENT 'Foreign Key to data_item_type',
    `raw_value` TEXT NOT NULL COMMENT 'Original Value',
    `normalized_value` TEXT COMMENT 'Normalized Value',
    `hash_sha256` CHAR(64) NOT NULL COMMENT 'Deduplication Hash',
    `ref_count` INT UNSIGNED NOT NULL DEFAULT 0,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY `ux_data_item_hash` (`hash_sha256`),
    INDEX `idx_type_id` (`type_id`),
    CONSTRAINT `fk_data_item_type` FOREIGN KEY (`type_id`) REFERENCES `data_item_type`(`id`) ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
-- ============================================================
-- 4. MiniApp - Data Item Relation
-- ============================================================
DROP TABLE IF EXISTS `miniapp_to_dataitem`;
CREATE TABLE `miniapp_to_dataitem` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `miniapp_id` BIGINT UNSIGNED NOT NULL COMMENT 'FK to miniapp_meta.id',
    `data_item_id` BIGINT UNSIGNED NOT NULL,
    `source_file` TEXT COMMENT 'File Path',
    `source_line` INT COMMENT 'Line Number',
    `source_snippet` TEXT COMMENT 'Code Snippet',
    `detector_tag` VARCHAR(64),
    `detector_rule_id` VARCHAR(128),
    `detector_source` VARCHAR(128),
    `detector_confidence` DECIMAL(5, 4),
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_miniapp_id` (`miniapp_id`),
    INDEX `idx_data_item_id` (`data_item_id`),
    CONSTRAINT `fk_madi_mini_app` FOREIGN KEY (`miniapp_id`) REFERENCES `miniapp_meta`(`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_madi_data_item` FOREIGN KEY (`data_item_id`) REFERENCES `data_item`(`id`) ON DELETE CASCADE,
    UNIQUE KEY `ux_occurrence` (
        `miniapp_id`,
        `data_item_id`,
        `source_file`(255),
        `source_line`
    )
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
-- ============================================================
-- 5. Attribute Definition Table
-- ============================================================
DROP TABLE IF EXISTS `attribute_def`;
CREATE TABLE `attribute_def` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `key` VARCHAR(64) NOT NULL UNIQUE,
    `description` TEXT COMMENT 'Attribute Information',
    `data_type` ENUM('string', 'integer', 'boolean', 'json') NOT NULL DEFAULT 'string'
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
-- {{ INSERT_ATTRIBUTE_DEF }}
-- ============================================================
-- 6. Data Item Attribute Values
-- ============================================================
DROP TABLE IF EXISTS `data_item_attribute`;
CREATE TABLE `data_item_attribute` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `data_item_id` BIGINT UNSIGNED NOT NULL,
    `attribute_id` BIGINT UNSIGNED NOT NULL,
    `value_string` TEXT,
    `source` VARCHAR(255),
    INDEX `idx_data_item_id` (`data_item_id`),
    INDEX `idx_attribute_id` (`attribute_id`),
    CONSTRAINT `fk_dia_data_item` FOREIGN KEY (`data_item_id`) REFERENCES `data_item`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT `fk_dia_attribute` FOREIGN KEY (`attribute_id`) REFERENCES `attribute_def`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
    UNIQUE KEY `ux_data_item_attr` (`data_item_id`, `attribute_id`)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
SET FOREIGN_KEY_CHECKS = 1;
SELECT 'Database Schema Generated Successfully!' AS status;