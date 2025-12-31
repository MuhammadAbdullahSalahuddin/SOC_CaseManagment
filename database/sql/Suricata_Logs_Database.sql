-- Active: 1765043800316@@127.0.0.1@3306@suricata_db
CREATE DATABASE IF NOT EXISTS suricata_db;
USE suricata_db;

DROP VIEW IF EXISTS Show_Cases;
DROP TABLE IF EXISTS Detail_File_Artifacts;
DROP TABLE IF EXISTS Detail_HTTP_Transactions;
DROP TABLE IF EXISTS Detail_Alert_Context;
DROP TABLE IF EXISTS All_Log_Details;
DROP TABLE IF EXISTS Case_Assignments; 
DROP TABLE IF EXISTS Case_History;
DROP TABLE IF EXISTS Cases;
DROP TABLE IF EXISTS Users;
DROP TABLE IF EXISTS Reference_Rules_Catalog;

CREATE TABLE Users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_of_user VARCHAR(255) NOT NULL,
    is_Admin BOOLEAN NOT NULL DEFAULT FALSE
) ENGINE=InnoDB;

insert into `Users`(username, password_of_user,is_admin) VALUES ("analyst", "secure",0);
insert into `Users`(username, password_of_user,is_admin) VALUES ("admin", "secure",1);
insert into `Users`(username, password_of_user,is_admin) VALUES ("Abdullah", "secure",0);

insert into Users(username, password_of_user, is_admin) values ("Kamran","namuna",1)


CREATE TABLE Reference_Rules_Catalog (
    signature_id INT,
    gid INT,
    signature_name VARCHAR(255),
    category VARCHAR(255),
    severity INT,
    revision INT,
    PRIMARY KEY (signature_id, gid)
) ENGINE=InnoDB;

CREATE TABLE Cases (
    case_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    flow_id BIGINT,

    src_ip VARCHAR(45),
    dest_ip VARCHAR(45),
    src_port INT,
    dest_port INT,
    proto VARCHAR(10),
    flow_start_time DATETIME(6),

    status ENUM('OPEN', 'INVESTIGATING', 'CLOSED', 'FALSE_POSITIVE') DEFAULT 'OPEN',
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'MEDIUM',
    comments TEXT
) ENGINE=InnoDB;

CREATE TABLE Case_Assignments (
    assignment_id INT AUTO_INCREMENT PRIMARY KEY,
    case_id BIGINT,
    user_id INT,
    assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (case_id) REFERENCES Cases(case_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE,
    
    UNIQUE (case_id, user_id) 
) ENGINE=InnoDB;

CREATE TABLE All_Log_Details (
    log_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    case_id BIGINT,              
    timestamp DATETIME(6),
    event_type VARCHAR(50),
    
    interface_in VARCHAR(50),
    traffic_direction VARCHAR(20),
    pkts_toserver INT,
    pkts_toclient INT,
    bytes_toserver INT,
    bytes_toclient INT,
    payload_printable TEXT,
    stream_id INT,
    
    FOREIGN KEY (case_id) REFERENCES Cases(case_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE Detail_Alert_Context (
    log_id BIGINT PRIMARY KEY,
    signature_id INT,
    gid INT,
    action_taken VARCHAR(50),
    
    FOREIGN KEY (log_id) REFERENCES All_Log_Details(log_id) ON DELETE CASCADE,
    FOREIGN KEY (signature_id, gid) REFERENCES Reference_Rules_Catalog(signature_id, gid)
) ENGINE=InnoDB;

CREATE TABLE Detail_HTTP_Transactions (
    log_id BIGINT PRIMARY KEY,
    hostname VARCHAR(255),
    url TEXT,
    http_user_agent TEXT,
    http_content_type VARCHAR(100),
    http_method VARCHAR(10),
    http_protocol VARCHAR(20),
    http_status INT,
    response_length INT,
    http_response_body TEXT,
    
    FOREIGN KEY (log_id) REFERENCES All_Log_Details(log_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE Detail_File_Artifacts (
    artifact_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    log_id BIGINT,
    filename TEXT,
    state VARCHAR(50),
    is_stored BOOLEAN,
    size_bytes INT,
    tx_id INT,
    
    FOREIGN KEY (log_id) REFERENCES All_Log_Details(log_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE Case_History (
    history_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    case_id BIGINT,
    user_id INT,               
    change_type VARCHAR(50),   
    old_value TEXT,            
    new_value TEXT,            
    changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (case_id) REFERENCES Cases(case_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES Users(user_id)
) ENGINE=InnoDB;
CREATE VIEW Show_Cases AS
SELECT 
    c.case_id, 
    c.status, 
    c.severity, 
    c.src_ip, 
    c.dest_ip, 
    GROUP_CONCAT(u.username SEPARATOR ', ') AS assigned_analysts
FROM Cases c
LEFT JOIN Case_Assignments ca ON c.case_id = ca.case_id
LEFT JOIN Users u ON ca.user_id = u.user_id
GROUP BY c.case_id;

SELECT case_id, flow_id, status, severity
FROM Cases
WHERE case_id IN (
    SELECT case_id 
    FROM All_Log_Details 
    WHERE event_type = 'alert'
);

SELECT src_ip AS Suspicious_IP 
FROM Cases 
WHERE severity = 'HIGH'

UNION

SELECT dest_ip AS Suspicious_IP 
FROM Cases 
WHERE severity = 'HIGH';

select * from `Users`;
select * from `Cases`;

select * from `Case_History`