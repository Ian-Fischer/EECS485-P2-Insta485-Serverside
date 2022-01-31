PRAGMA foreign_keys = ON;

CREATE TABLE users(
    username VARCHAR(20) PRIMARY KEY,
    fullname VARCHAR(40) NOT NULL,
    email VARCHAR(20) NOT NULL,
    filename VARCHAR(64) NOT NULL,
    password VARCHAR(256) NOT NULL,
    created DATETIME
);

CREATE TABLE posts(
    postid INTEGER PRIMARY KEY AUTOINCREMENT,
    filename VARCHAR(64) NOT NULL,
    owner VARCHAR(20) NOT NULL,
    created DATETIME,
    FOREIGN KEY (owner) REFERENCES users(username) ON DELETE CASCADE
);

/* check to see if we need to define the following relationship "username1 follows username2" */
CREATE TABLE following(
    username1 VARCHAR(20) NOT NULL,
    username2 VARCHAR(20) NOT NULL,
    created DATETIME,
    PRIMARY KEY (username1, username2),
    FOREIGN KEY (username2) REFERENCES users(username) ON DELETE CASCADE,
    FOREIGN KEY (username1) REFERENCES users(username) ON DELETE CASCADE
);

CREATE TABLE comments(
    commentid INTEGER PRIMARY KEY AUTOINCREMENT,
    owner VARCHAR(20) NOT NULL,
    postid INTEGER NOT NULL,
    text VARCHAR(1024) NOT NULL,
    created DATETIME,
    FOREIGN KEY (owner) REFERENCES users(username),
    FOREIGN KEY (postid) REFERENCES posts(postid) ON DELETE CASCADE
);

CREATE TABLE likes(
    likeid INTEGER PRIMARY KEY,
    owner VARCHAR(20) NOT NULL,
    postid INTEGER NOT NULL,
    created DATETIME,
    FOREIGN KEY (owner) REFERENCES users(username) ON DELETE CASCADE,
    FOREIGN KEY (postid) REFERENCES posts(postid) ON DELETE CASCADE
);
