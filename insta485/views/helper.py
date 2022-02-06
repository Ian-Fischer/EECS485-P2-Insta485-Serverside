"""Includes helper functions."""
import hashlib
import pathlib
import uuid
import sqlite3
import flask
import insta485


def get_file_path(filename):
    """Get uuid file path."""
    stem = uuid.uuid4().hex
    suffix = pathlib.Path(filename).suffix
    uuid_basename = f"{stem}{suffix}"
    # Save to disk
    path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
    return path, uuid_basename


def get_salt(password):
    """Get the salt from the password in the database."""
    idx = password.find('$')
    password = password[idx+1:]
    idx = password.find('$')
    password = password[:idx]
    return password


def hash_password(password, salt):
    """Hash a password given salt."""
    algorithm = 'sha512'
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + password
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join([algorithm, salt, password_hash])
    return password_db_string


def new_password_hash(password):
    """Hash a new password given salt."""
    algorithm = 'sha512'
    salt = uuid.uuid4().hex
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + password
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join([algorithm, salt, password_hash])
    return password_db_string


def get_all_comments(postid, connection):
    """Get all comments commented on post with postid."""
    comments = connection.execute(
        "SELECT C.owner, C.text, C.commentid "
        "FROM comments C "
        "WHERE C.postid = ? ",
        (postid,)
    ).fetchall()
    output = [{'owner': elt['owner'],
               'text': elt['text'],
               'commentid': elt['commentid']} for elt in comments]
    output = sorted(output, key=lambda k: k['commentid'])
    return output


def get_likes(postid, connection):
    """Get all likes on post with postid."""
    likes = connection.execute(
                "SELECT L.owner "
                "FROM likes L "
                "WHERE L.postid = ? ",
                (postid,)).fetchall()
    likes = [elt['owner'] for elt in likes]
    logname_liked = flask.session['logname'] in likes
    return likes, logname_liked


def handle_account_login(target):
    """Handle logging into an account."""
    if target is None:
        target = flask.url_for('show_index')
    # check if any empty information
    if not flask.request.form.get('username'):
        return flask.abort(400)
    if not flask.request.form.get('password'):
        return flask.abort(400)
    logname = flask.request.form.get('username')
    password = flask.request.form.get('password')
    # connect to the db
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    # check if the user exists
    curr_tbl_pass = connection.execute(
        "SELECT U.password "
        "FROM users U "
        "WHERE U.username = ? ",
        (logname,)
    ).fetchall()
    # if the user does not exist, abort 404 NOT FOUND
    if len(curr_tbl_pass) == 0:
        return flask.abort(403)
    # otherwise, get the password
    curr_password = curr_tbl_pass[0]['password']
    # hash the password with the salt it currently has
    hashed_password = hash_password(password, get_salt(curr_password))
    # if it doesn't match, abort 405
    if curr_password != hashed_password:
        return flask.abort(403)
    # otherwise, set session cookie and redirect to target
    flask.session['logname'] = logname
    return flask.redirect(target)


def handle_account_create(target):
    """Handle creating an account."""
    # if target is not specified, default to index
    if target is None:
        target = flask.url_for('show_index')
    # get form data
    username = flask.request.form.get('username')
    fullname = flask.request.form.get('fullname')
    email = flask.request.form.get('email')
    password = flask.request.form.get('password')
    # set up db connect
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    # Unpack flask object
    fileobj = flask.request.files["file"]
    filename = fileobj.filename
    # check for empty fields
    if None in [username, fullname, email, password, filename, fileobj]:
        return flask.abort(400)
    # check to see if the user already exists
    user = connection.execute(
        "SELECT U.username "
        "FROM users U "
        "WHERE U.username = ? ",
        (username,)
    ).fetchall()
    # check to see if the user exists
    if len(user) > 0:
        return flask.abort(409)
    path, uuid_basename = get_file_path(filename)
    fileobj.save(path)
    # now that the file is saved, update user table
    connection.execute(
        "INSERT INTO users(username, fullname, email, filename, password) "
        "VALUES (?,?,?,?,?) ",
        (username, fullname, email, uuid_basename, password,)
    )
    connection.commit()
    # set session cookie to login
    flask.session['logname'] = username
    return flask.redirect(target)


def handle_account_delete(target):
    """Handle deleting account."""
    if target is None:
        target = flask.url_for('show_index')
    # if not logged in, abort(403)
    if 'logname' not in flask.session:
        return flask.abort(403)
    # if target url not specified then redirect to the home page
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    logname = flask.session['logname']
    # check to see if the user exists
    checking = connection.execute(
        'SELECT P.filename '
        'FROM posts P '
        'WHERE P.owner = ? ',
        (logname,)
    ).fetchall()
    for item in checking:
        # Unpack flask object
        # empty file = abort 400
        filename = item["filename"]
        # Delete the file
        path = insta485.app.config["UPLOAD_FOLDER"]/filename
        path.unlink()
    # get to the user
    to_delete = connection.execute(
        "SELECT U.username "
        "FROM users U "
        "WHERE U.username = ? ",
        (logname,)
    ).fetchall()
    # if the user does not exists, abort NOT FOUND
    if len(to_delete) == 0:
        return flask.abort(404)
    connection.execute(
        "DELETE FROM users "
        "WHERE username = ? ",
        (logname,)
    )
    # commit the delete
    connection.commit()
    # clear session and redirect to target
    flask.session.clear()
    return flask.redirect(target)


def handle_account_edit(target):
    """Handle account edits for account endpoint."""
    if target is None:
        target = flask.url_for('show_index')
    # see if logged in
    if 'logname' not in flask.session:
        return flask.abort(403)
    # get information
    fullname = flask.request.form.get('fullname')
    email = flask.request.form.get('email')
    # check for empty fields
    if fullname is None or email is None:
        return flask.abort(400)
    # establish connection
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    # get logname and uploaded file
    logname = flask.session['logname']
    fileobj = flask.request.files["file"]
    # if there is a file, deal with it
    if fileobj:
        # get uploaded file info
        filename = fileobj.filename
        stem = uuid.uuid4().hex
        suffix = pathlib.Path(filename).suffix
        uuid_basename = f"{stem}{suffix}"
        # Save to disk
        path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
        fileobj.save(path)
        # Get the old filename
        delete_file = connection.execute(
            "SELECT U.filename "
            "FROM users U "
            "WHERE username = ? ",
            (logname,)
        ).fetchall()[0]['filename']
        delete_path = insta485.app.config['UPLOAD_FOLDER']/delete_file
        delete_path.unlink()
        # update the filename for the user
        connection.execute(
            "UPDATE users "
            "SET filename = ? "
            "WHERE username = ? ",
            (uuid_basename, logname,)
        )
        # commit the changes
        connection.commit()
    # update the fullname and email
    connection.execute(
        "UPDATE users "
        "SET fullname = ? "
        "WHERE username = ? ",
        (fullname, logname,)
    )
    connection.execute(
        "UPDATE users "
        "SET email = ? "
        "WHERE username = ? ",
        (email, logname,)
    )
    # commit changes and redirect to the target
    connection.commit()
    return flask.redirect(target)


def handle_account_password(target):
    """Handle password changes for account endpoint."""
    # check if logged in
    if 'logname' not in flask.session:
        return flask.abort(403)
    # get form data
    password = flask.request.form.get('password')
    new_password1 = flask.request.form.get('new_password1')
    new_password2 = flask.request.form.get('new_password2')
    # check for empty, if so abort (400)
    if None in [password, new_password1, new_password2]:
        return flask.abort(400)
    # establish connection
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    logname = flask.session['logname']
    # get the old password
    curr_tbl_pass = connection.execute(
        "SELECT U.password "
        "FROM users U "
        "WHERE U.username = ? ",
        (logname, )
    ).fetchall()
    curr_password = curr_tbl_pass[0]['password']
    # get the hashed password inserted (current)
    password_db_string = hash_password(password, get_salt(curr_password))
    # check it got password right
    if curr_password != password_db_string:
        return flask.abort(403)
    # check to see if the new passwords match
    if new_password1 != new_password2:
        return flask.abort(401)
    # hash new password
    password_db_string = new_password_hash(new_password1)
    # store new password
    connection.execute(
        "UPDATE users "
        "SET password = ? "
        "WHERE username = ? ",
        (password_db_string, logname,)
    )
    # commit changes and redirect to the target
    connection.commit()
    return flask.redirect(target)
