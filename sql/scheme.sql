PRAGMA foreign_keys = ON;

CREATE TABLE users(
    username VARCHAR(20) PRIMARY KEY,
    fullname VARCHAR(40) NOT NULL,
    email VARCHAR(20) NOT NULL,
    filename VARCHAR(64) NOT NULL,
    password VARCHAR(256) NOT NULL,
    created DATETIME
);

