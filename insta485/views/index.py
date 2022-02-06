"""
Insta485 index (main) view.

URLs include:
/
/users/<user_url_slug>/
/users/<user_url_slug>/followers/
/users/<user_url_slug>/following/
/posts/<postid_url_slug>/
/explore/
/accounts/?target=URL
/accounts/login/
/accounts/logout/
/accounts/create/
/accounts/delete/
/accounts/edit/
/accounts/password/
/likes/?target=URL
/comments/?target=URL
/posts/?target=URL
/following/?target=URL
"""
import hashlib
import pathlib
import uuid
import sqlite3
import arrow
import flask
import insta485


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


@insta485.app.route('/', methods=['GET'])
def show_index():
    """Display / route."""
    # Connect to database
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    # get all following
    logname = flask.session['logname']
    l_following = connection.execute(
        "SELECT F.username2 "
        "FROM following F "
        "WHERE F.username1 = ? ",
        (logname, )
    ).fetchall()
    l_following = [elt['username2'] for elt in l_following]
    l_following.append(logname)
    posts = []
    # get all following posts
    for user in l_following:
        user_posts = connection.execute(
            "SELECT P.postid, P.filename AS pf, P.owner, P.created "
            "FROM posts P "
            "WHERE P.owner = ? ",
            (user, )
        ).fetchall()
        user_filename = connection.execute(
            "SELECT U.filename "
            "FROM users U "
            "WHERE U.username = ? ",
            (user, )
        ).fetchall()[0]['filename']
        for post in user_posts:
            likes, logname_liked = get_likes(post['postid'], connection)
            comments = get_all_comments(post['postid'], connection)
            timestamp = arrow.get(post['created']).to('US/Eastern').humanize()
            posts.append({
                "postid": post['postid'],
                "owner": post['owner'],
                "owner_img_url": user_filename,
                "img_url": post['pf'],
                "timestamp": timestamp,
                "likes": len(likes),
                "comments": comments,
                "logname_liked": logname_liked
            })
    # build context
    posts = sorted(posts, key=lambda p: p['postid'], reverse=True)
    context = {
        "logname": logname,
        "posts": posts
    }
    return flask.render_template("index.html",  **context)


@insta485.app.route('/users/<user_url_slug>/', methods=['GET'])
def show_user(user_url_slug):
    """Display /users/<user_url_slug>/ route."""
    # check to see if logged in, else red. to login
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    # open database
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    logname = flask.session['logname']
    username = user_url_slug
    usr = connection.execute(
        "SELECT U.username "
        "FROM users U "
        "WHERE U.username = ? ",
        (username, )
    ).fetchall()
    # return 404 if user does not exist in database
    if not usr:
        return flask.abort(404)
    # check if logged in user follows the user
    logname_follows_username_tbl = connection.execute(
        "SELECT F.username1 "
        "FROM following F "
        "WHERE ? = F.username1 AND  ? = F.username2 ",
        (logname, username, )
    ).fetchall()
    checking = [elt['username1'] for elt in logname_follows_username_tbl]
    logname_follows_username = logname in checking
    # get fullname
    fullname = connection.execute(
        "SELECT U.fullname "
        "FROM users U "
        "WHERE U.username = ?",
        (username,)
    ).fetchall()
    fullname = fullname[0]['fullname']
    # get list of following
    l_following = len(connection.execute(
        "SELECT F.username2 "
        "FROM following F "
        "WHERE ? = F.username1 ",
        (username, )
    ).fetchall())
    # get list of followers
    l_followers = len(connection.execute(
        "SELECT F.username1 "
        "FROM following F "
        "WHERE ? = F.username2 ",
        (username, )
    ).fetchall())
    # get posts and corresponding pics
    posts_tbl = connection.execute(
        "SELECT P.postid, P.filename "
        "FROM posts P "
        "WHERE ? = P.owner ",
        (username,)
    )
    posts = [{'postid': elt['postid'],
              'img_url': elt['filename']} for elt in posts_tbl]
    total_posts = len(posts)
    # build context
    context = {
        'logname': logname,
        'username': username,
        'logname_follows_username': logname_follows_username,
        'fullname': fullname,
        'following': l_following,
        'followers': l_followers,
        'total_posts': total_posts,
        'posts': posts
    }
    # render
    return flask.render_template("user.html", **context)


@insta485.app.route('/users/<user_url_slug>/followers/', methods=['GET'])
def followers(user_url_slug):
    """Display /users/<user_url_slug>/followers/ route."""
    # check to see if logged in, else redirect to login
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    # database connection
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    # get logname, username
    logname = flask.session['logname']
    username = user_url_slug
    # get user follows and who logged in follows
    c_followers = connection.execute(
        "SELECT F.username1, U.filename "
        "FROM following F, users U "
        "WHERE ? = F.username2 AND F.username1 = U.username",
        (username,)
    ).fetchall()
    logname_follower = connection.execute(
        "SELECT F.username2 "
        "FROM following F "
        "WHERE ? = F.username1",
        (logname,)
    ).fetchall()
    # build contexzt
    l_follower = [elt['username2'] for elt in logname_follower]
    c_followers = [{
                    'username': elt['username1'],
                    'user_img_url': elt['filename'],
                    'logname_follows_username': elt['username1'] in l_follower
                } for elt in c_followers]
    context = {
        'logname': logname,
        'username': user_url_slug,
        'followers': c_followers
    }
    # render
    return flask.render_template("followers.html", **context)


@insta485.app.route('/users/<user_url_slug>/following/', methods=['GET'])
def following(user_url_slug):
    """Display /users/<user_url_slug>/following/ route."""
    # if not logged in redirect to login
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    # connect to db
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    # get logname and username
    logname = flask.session['logname']
    username = user_url_slug
    # user following and logname following
    u_following = connection.execute(
        "SELECT F.username2, U.filename "
        "FROM following F, users U "
        "WHERE ? = F.username1 AND F.username2 = U.username ",
        (username,)
    ).fetchall()
    l_following = connection.execute(
        "SELECT F.username2 "
        "FROM following F "
        "WHERE ? = F.username1",
        (logname,)
    ).fetchall()
    l_following = [elt['username2'] for elt in l_following]
    c_following = [{
                    'username': elt['username2'],
                    'user_img_url': elt['filename'],
                    'logname_follows_username': elt['username2'] in l_following
                    } for elt in u_following]
    #  build context and render
    context = {
        'logname': logname,
        'username': user_url_slug,
        'following': c_following
    }
    return flask.render_template("following.html", **context)


@insta485.app.route('/posts/<post_url_slug>/', methods=['GET'])
def show_post(post_url_slug):
    """Display /posts/<post_url_slug>/ route."""
    # if not logged in, redirect to login
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    # connect to database
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    logname = flask.session['logname']
    post = connection.execute(
        "SELECT P.owner, P.filename as im, P.created, U.filename "
        "FROM posts P, users U "
        "WHERE P.postid = ? AND U.username = P.owner",
        (post_url_slug, )
    ).fetchall()
    # if there is no post, abort
    if not post:
        return flask.abort(404)
    # get likes and comments
    likes, logname_liked = get_likes(post_url_slug, connection)
    comments = get_all_comments(post_url_slug, connection)
    # build context and render
    context = {
        'logname': logname,
        'postid': post_url_slug,
        "owner": post[0][0],
        "owner_img_url": post[0][3],
        "img_url": post[0][1],
        "timestamp": arrow.get(post[0][2]).to('US/Eastern').humanize(),
        "likes": len(likes),
        "comments": comments,
        "logname_liked": logname_liked
    }
    return flask.render_template("post.html", **context)


@insta485.app.route('/explore/', methods=['GET'])
def show_explore():
    """Display /explore/ route."""
    # if not logged in, redirect to login
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    # get users for explore
    logname = flask.session['logname']
    users = connection.execute(
        "SELECT U.username "
        "FROM users U "
        "EXCEPT "
        "SELECT F.username2 "
        "FROM following F "
        "WHERE F.username1 = ? OR F.username2 = ? ",
        (logname, logname, )
    ).fetchall()
    users = [elt['username'] for elt in users]
    if logname in users:
        users.remove(logname)
    # get not following
    not_following = []
    for user in users:
        profile_pic = connection.execute(
            "SELECT U.filename "
            "FROM users U "
            "WHERE U.username = ? ",
            (user, )
        ).fetchall()
        user_dict = {}
        user_dict['username'] = user
        user_dict['user_img_url'] = profile_pic[0]['filename']
        not_following.append(user_dict)
    # build context and render
    context = {
        'logname': logname,
        'not_following': not_following
    }
    return flask.render_template("explore.html", **context)


@insta485.app.route('/accounts/login/', methods=['GET'])
def login():
    """Display /accounts/login/ route."""
    # if already logged in, redirect to the homepage
    if 'logname' not in flask.session:
        return flask.render_template('login.html')
    return flask.redirect(flask.url_for('show_index'))


@insta485.app.route('/accounts/create/', methods=['GET'])
def show_create():
    """Show the create page."""
    if 'logname' in flask.session:
        return flask.redirect(flask.url_for('show_edit'))
    return flask.render_template('create.html')


@insta485.app.route('/accounts/delete/', methods=['GET'])
def show_delete():
    """Endpoint to show delete account form."""
    # if not in the session, redirect to login
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    # get the logname
    logname = flask.session['logname']
    # get the context dict filled
    context = {
        'logname': logname
    }
    return flask.render_template("delete.html", **context)


@insta485.app.route('/accounts/edit/', methods=['GET'])
def show_edit():
    """Endpoint to show /accounts/edit/."""
    # if not in session, login
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    # establish db connection
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    # get logname
    logname = flask.session['logname']
    # get profile_info from db
    profile_information = connection.execute(
        "SELECT U.fullname, U.email, U.filename "
        "FROM users U "
        "WHERE username = ?",
        (logname,)
    ).fetchall()
    # setup context dict
    context = {
        "logname": logname,
        "logname_profile_pic": profile_information[0]['filename'],
        "logname_fullname": profile_information[0]['fullname'],
        "logname_email": profile_information[0]['email']
    }
    # render
    return flask.render_template("edit.html", **context)


@insta485.app.route('/accounts/password/', methods=['GET'])
def show_password():
    """Endpoint to show change password form."""
    # check to see if logged in
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    # serve password.html
    context = {
        "logname": flask.session['logname']
    }
    return flask.render_template("password.html", **context)


@insta485.app.route('/uploads/<filename>', methods=['GET'])
def send_file(filename):
    """Endpoint handling file requests."""
    # check tos ee if logged in, if not 403
    if 'logname' not in flask.session:
        return flask.abort(403)
    # check to see if the file exists, if not 404
    if not (insta485.app.config['UPLOAD_FOLDER']/filename).exists():
        return flask.abort(404)
    upload_folder = insta485.app.config["UPLOAD_FOLDER"]
    return flask.send_from_directory(upload_folder, filename)


@insta485.app.route('/accounts/logout/', methods=['POST'])
def logout():
    """Endpoint for logging out."""
    # log user out via session clear, redirect to login
    flask.session.clear()
    return flask.redirect(flask.url_for('login'))


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
    # files
    stem = uuid.uuid4().hex
    suffix = pathlib.Path(filename).suffix
    uuid_basename = f"{stem}{suffix}"
    # Save to disk
    path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
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


@insta485.app.route('/accounts/', methods=['POST'])
def handle_account():
    """Handle POST requests for /accounts/?target=URL endpoint."""
    # get the operation and the target
    operation = flask.request.form.get('operation')
    target = flask.request.args.get('target')
    if target is None:
        target = flask.url_for('show_index')
    # LOGIN:
    if operation == 'login':
        handle_account_login(target)
    # CREATE
    elif operation == 'create':
        handle_account_create(target)
    # DELETE
    elif operation == 'delete':
        handle_account_delete(target)
    # EDIT_ACCOUNT
    elif operation == 'edit_account':
        handle_account_edit(target)
    # UPDATE_PASSWORD
    elif operation == 'update_password':
        handle_account_password(target)
    return flask.redirect(target)


@insta485.app.route('/following/', methods=['POST'])
def follow_unfollow():
    """Follow and unfollow functionality."""
    # if not logged in, redirect to login page
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    # else get the logname
    logname = flask.session['logname']
    # establish connection
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    # get form data
    operation = flask.request.form.get('operation')
    username = flask.request.form.get('username')
    target = flask.request.args.get('target')
    # check to see if none
    if target is None:
        target = flask.url_for('show_index')
    # get whether they follow or not
    follows = connection.execute(
            'SELECT F.username2 '
            'FROM following F '
            'WHERE F.username1 = ? AND F.username2 = ? ',
            (logname, username)).fetchall()
    # FOLLOW
    if operation == 'follow':
        # see if already follows
        if len(follows) == 1:
            return flask.abort(409)
        # if not, follow, put in database, commit changes, go to target
        connection.execute(
            "INSERT INTO following(username1, username2) "
            "VALUES (?,?) ",
            (logname, username, )
        )
        connection.commit()
    # UNFOLLOW
    elif operation == 'unfollow':
        # see if they follow
        if len(follows) == 0:
            return flask.abort(409)
        # if they do, commit the deletion and redirect
        connection.execute(
            "DELETE FROM following "
            "WHERE username1 = ? AND username2 = ? ",
            (logname, username, )
        )
        connection.commit()
    # redirect after committing changes
    return flask.redirect(target)


@insta485.app.route('/likes/', methods=['POST'])
def like():
    """Endpoint to handle POST requests for liking and unliking."""
    target = flask.request.args.get('target')
    if not target:
        target = flask.url_for('show_index')
    # establish connection
    connection = insta485.model.get_db()
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))

    logname = flask.session['logname']
    operation = flask.request.form.get('operation')
    postid = flask.request.form.get('postid')
    check = connection.execute(
            "SELECT L.likeid "
            "FROM likes L "
            "WHERE L.postid = ? AND L.owner = ?",
            (postid, logname, )
    ).fetchall()

    if operation == 'like':
        # put the like in the database if it is not there
        if len(check) == 0:
            connection.execute(
                "INSERT INTO likes(owner, postid) "
                "VALUES (?,?) ",
                (logname, postid,))
            connection.commit()
            return flask.redirect(target)
        return flask.abort(409)

    if operation == 'unlike':
        # take the like out if it's there
        if len(check) == 1:
            connection.execute(
                "DELETE FROM likes "
                "WHERE owner = ? AND postid = ?",
                (logname, postid, )
            )
            connection.commit()
            return flask.redirect(target)
        return flask.abort(409)
    return flask.redirect(target)


@insta485.app.route('/comments/', methods=['POST'])
def comment():
    """Endpoint to handle POST requests to comments."""
    # connect to db
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    # get the target
    target = flask.request.args.get('target')
    # if not specified then set to the home page
    if not target:
        target = flask.url_for('show_index')
    # changes only for someone who is logged in
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    logname = flask.session['logname']
    # get form information
    operation = flask.request.form.get('operation')
    postid = flask.request.form.get('postid')
    commentid = flask.request.form.get('commentid')
    text = flask.request.form.get('text')
    # check if the comment exists
    exists = connection.execute(
            "SELECT C.commentid, C.owner "
            "FROM comments C "
            "WHERE C.commentid = ?",
            (commentid,)).fetchall()

    if operation == 'create' and text:
        if len(exists) == 0:
            exists = connection.execute(
                "INSERT INTO comments(owner, postid, text) "
                "VALUES (?,?,?) ",
                (logname, postid, text,))
    elif operation == 'delete':
        if len(exists) == 1:
            # check if the logname is the owner
            if logname == exists[0]['owner']:
                # if so, delete it
                exists = connection.execute(
                    "DELETE FROM comments "
                    "WHERE commentid = ? ",
                    (commentid,))
    elif not text:
        connection.commit()
        return flask.abort(400)
    else:
        # something doesn't add up do nothing!
        connection.commit()
        return flask.redirect(target)
    # send to the target
    connection.commit()
    return flask.redirect(target)


@insta485.app.route('/posts/', methods=['POST'])
def handle_posts():
    """Endpoint to handle post requests for creating and deleting posts."""
    # connect to db
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    # get the target
    target = flask.request.args.get('target')
    # if not specified then set to the home page
    # changes only for someone who is logged in
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    logname = flask.session['logname']
    if not target:
        target = flask.url_for('show_user', user_url_slug=logname)
    # get form information
    operation = flask.request.form.get('operation')
    # create
    if operation == 'create':
        # Unpack flask object
        fileobj = flask.request.files["file"]
        # empty file = abort 400
        if fileobj is None:
            return flask.abort(400)
        # deal with files
        filename = fileobj.filename
        stem = uuid.uuid4().hex
        suffix = pathlib.Path(filename).suffix
        uuid_basename = f"{stem}{suffix}"
        # Save to disk
        path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
        fileobj.save(path)
        # now file is done, make the post
        connection.execute(
            "INSERT INTO posts(filename, owner) "
            "VALUES (?,?) ",
            (uuid_basename, flask.session['logname'],)
        )
        return flask.redirect(target)
    if operation == 'delete':
        # check if the post exists
        postid = flask.request.form.get('postid')
        checking = connection.execute(
            'SELECT P.owner, P.filename '
            'FROM posts P '
            'WHERE P.postid = ? ',
            (postid,)
        ).fetchall()

        if checking[0]['owner'] != flask.session['logname']:
            return flask.abort(403)
        # Unpack flask object
        # empty file = abort 400
        filename = checking[0]["filename"]
        # Save to disk
        path = insta485.app.config["UPLOAD_FOLDER"]/filename
        path.unlink()
        # delete the post
        connection.execute(
            'DELETE FROM posts '
            'WHERE postid = ? ',
            (postid,)
        )
        connection.commit()
        # delete the file
        return flask.redirect(target)
    return flask.redirect(target)
