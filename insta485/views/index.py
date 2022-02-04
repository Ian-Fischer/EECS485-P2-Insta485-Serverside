"""
Insta485 index (main) view.

URLs include:
/
"""
import profile
import re
import os 
from re import L
import arrow
import flask
from pyparsing import empty
import insta485
import sqlite3
import pdb
import uuid 
import hashlib
import pathlib

def get_salt(password):
    idx = password.find('$')
    password = password[idx+1:]
    idx = password.find('$')
    password = password[:idx]
    return password

def hash_password(password, salt):
    algorithm = 'sha512'
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + password
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join([algorithm, salt, password_hash])
    return password_db_string

def get_all_comments(postid, connection):
    comments = connection.execute(
        "SELECT C.owner, C.text, C.commentid "
        "FROM comments C "
        "WHERE C.postid = ? ",
        (postid,)
    ).fetchall()
    return [{'owner' : elt['owner'], 'text': elt['text'], 'commentid': elt['commentid']} for elt in comments]

def get_likes(postid, connection):
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
    else:
        # 1. get all following
        logname = flask.session['logname']
        following = connection.execute(
            "SELECT F.username2 "
            "FROM following F "
            "WHERE F.username1 = ? ",
            (logname, )
        ).fetchall()
        following = [elt['username2'] for elt in following]
        following.append(logname)
        posts = []
        for user in following:
            user_posts = connection.execute(
                "SELECT P.postid AS postid, P.filename as pfilename, P.owner AS owner, P.created AS created, U.filename AS ufilename "
                "FROM posts P, users U "
                "WHERE P.owner = ? AND ? = U.username ",
                (user,user,)
            ).fetchall()
            for post in user_posts:
                likes, logname_liked = get_likes(post['postid'],connection)
                comments = get_all_comments(post['postid'], connection)
                posts.append({
                    "postid" : post['postid'],
                    "owner" : post['owner'],
                    "owner_img_url" : post['ufilename'],
                    "img_url" : post['pfilename'],
                    "timestamp" : arrow.get(post['created']).to('US/Eastern').humanize(),
                    "likes" : len(likes),
                    "comments" : comments,
                    "logname_liked": logname_liked
                })
        # now we have gone through all the following and collected all their posts
        # build context
        context = {
            "logname": logname,
            "posts": posts
        }
        return flask.render_template("index.html",  **context)

@insta485.app.route('/accounts/', methods=['POST'])
def handle_account():
    operation = flask.request.form.get('operation')
    target = flask.request.args.get('target')
    if target is None:
        target = '/'
    if operation == 'login':
        # check if any empty information
        if not flask.request.form.get('username') or not flask.request.form.get('password'):
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
            (logname, )
        ).fetchall()
        if not curr_tbl_pass:
            return flask.abort(403)
        curr_password = curr_tbl_pass[0]['password']
        hashed_password = hash_password(password, get_salt(curr_password))
        if curr_password != hashed_password:
            return flask.abort(403)
        else:
            flask.session['logname'] = logname
            return flask.redirect(target)
            
    elif operation == 'create':
        # get form data
        username, fullname = flask.request.form.get('username'), flask.request.form.get('fullname')
        email, password = flask.request.form.get('email'), flask.request.form.get('password')
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
            return flask.abort(403)
        # SHOULD BE GOOD TO CREATE 
        # Compute base name (filename without directory).  We use a UUID to avoid
        # clashes with existing files, and ensure that the name is compatible with the
        # filesystem.
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
        flask.session['logname'] = username
        # after changes are commited, redirect to the target
        return flask.redirect(target)
        
    # TODO: IAN NICOLE IAN NICOLE this straight up does not work
    elif operation == 'delete':
        # get the target page
        if 'logname' not in flask.session:
            return flask.abort(403)
        # if target url not specified then redirect to the home page
        connection = insta485.model.get_db()
        connection.row_factory = sqlite3.Row
        logname = flask.session['logname']
        # check to see if the user exists
        to_delete = connection.execute(
            "SELECT U.username "
            "FROM users U "
            "WHERE U.username = ? ",
            (logname,)
        ).fetchall()
        if len(to_delete) == 0:
            return flask.abort(404)
        connection.execute(
            "DELETE FROM users "
            "WHERE username = ? ",
            (logname,)
        )
        connection.commit()
        flask.session.clear()
        return flask.redirect(target)
        
    elif operation == 'edit_account':
        # see if logged in
        if 'logname' not in flask.session:
            return flask.abort(403)
        # get information
        fullname, email = flask.request.form.get('fullname'), flask.request.form.get('email')
        # check for empty fields
        if fullname == None or email == None:
            return flask.abort(400)
        # establish connection
        connection = insta485.model.get_db()
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        logname = flask.session['logname']
        # deal with uploaded file (whatever it is)
        fileobj = flask.request.files["file"]
        if fileobj != None:
            filename = fileobj.filename
            stem = uuid.uuid4().hex
            suffix = pathlib.Path(filename).suffix
            uuid_basename = f"{stem}{suffix}"
            # Save to disk
            path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
            fileobj.save(path)
            connection.execute(
                "UPDATE users "
                "SET filename = ? "
                "WHERE username = ? ",
                (uuid_basename, logname,)
            )
            connection.commit()
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
        connection.commit()
        return flask.redirect(target)

    elif operation == 'update_password':
        # check if logged in
        if 'logname' not in flask.session:
            return flask.abort(403)
        # get info
        password, new_password1 = flask.request.form.get('password'), flask.request.form.get('new_password1')
        new_password2 = flask.request.form.get('new_password2')
        # check for empty
        if not password or not new_password1 or not new_password2:
            return flask.abort(400)
        # establish connection
        connection = insta485.model.get_db()
        connection.row_factory = sqlite3.Row
        logname = flask.session['logname']
        curr_tbl_pass = connection.execute(
            "SELECT U.password "
            "FROM users U "
            "WHERE U.username = ? ",
            (logname, )
        ).fetchall()
        curr_password = curr_tbl_pass[0]['password']
        # get the hashed password
        password_db_string = hash_password(password, get_salt(curr_password))
        # check it got password right
        if curr_password != password_db_string:
            return flask.abort(403)
        if new_password1 != new_password2:
            return flask.abort(401)
        # TODO: new hash, don't use old salt won't work, do complete password alg. from spec
        password_db_string = hash_password(new_password1, get_salt(new_password1))
        connection.execute(
            "UPDATE users "
            "SET password = ? "
            "WHERE username = ? ",
            (password_db_string, logname, )
        )
        connection.commit()
        return flask.redirect(target)
        

@insta485.app.route('/explore/', methods=['GET'])
def show_explore():
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row

    logname = flask.session['logname']
    users = connection.execute(
        "SELECT U.username "
        "FROM users U "
        "EXCEPT "
        "SELECT F.username2 "
        "FROM following F "
        "WHERE F.username1 = ? OR F.username2 = ?",
        (logname,logname,)
    ).fetchall()

    users = [elt['username'] for elt in users]

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

    context = {
        'logname': logname,
        'not_following': not_following
    }
    connection.commit()
    return flask.render_template("explore.html", **context)

@insta485.app.route('/accounts/logout/', methods=['POST'])
def logout():
    flask.session.clear()
    return flask.redirect(flask.url_for('login'))

@insta485.app.route('/accounts/login/', methods=['GET'])
def login():
    # if already logged in, redirect to the homepage
    if 'logname' not in flask.session:
        return flask.render_template('login.html')
    else:
        return flask.redirect(flask.url_for('show_index'))

@insta485.app.route('/users/<user_url_slug>/', methods=['GET'])
def show_user(user_url_slug):
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    # open database
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    # build the context
    # logname, username, logname_follows_username, fullname, following, followers
    # total_posts, posts = [{'postid', 'img_url'}]

    logname = flask.session['logname']
    username = user_url_slug
    # check if the user exists
    usr = connection.execute(
        "SELECT U.username "
        "FROM users U "
        "WHERE U.username = ? ",
        (username, )
    ).fetchall()
    if not usr:
        return flask.abort(403)
    logname_follows_username_tbl = connection.execute(
        "SELECT F.username1 "
        "FROM following F "
        "WHERE ? = F.username1 AND  ? = F.username2 ",
        (logname, username)
    ).fetchall()

    logname_follows_username_tbl = [elt['username1'] for elt in logname_follows_username_tbl]

    logname_follows_username = logname in logname_follows_username_tbl
    fullname = connection.execute(
        "SELECT U.fullname "
        "FROM users U "
        "WHERE U.username = ?",
        (username,)
    ).fetchall()
    fullname = fullname[0]['fullname']

    following = len(connection.execute(
        "SELECT F.username2 "
        "FROM following F "
        "WHERE ? = F.username1 ",
        (username, )
    ).fetchall())

    followers = len(connection.execute(
        "SELECT F.username1 "
        "FROM following F "
        "WHERE ? = F.username2 ",
        (username, )
    ).fetchall())

    posts_tbl = connection.execute(
        "SELECT P.postid, P.filename "
        "FROM posts P "
        "WHERE ? = P.owner ",
        (username,)
    )
    posts = [{'postid': elt['postid'], 'img_url': elt['filename']} for elt in posts_tbl]
    total_posts = len(posts)
    context = {
        'logname': logname,
        'username': username,
        'logname_follows_username': logname_follows_username,
        'fullname': fullname,
        'following': following,
        'followers': followers,
        'total_posts': total_posts,
        'posts': posts
    }
    connection.commit()
    return flask.render_template("user.html", **context)


@insta485.app.route('/posts/<post_url_slug>/', methods=['GET'])
def show_post(post_url_slug):
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    logname = flask.session['logname']
    post = connection.execute(
        "SELECT P.owner, P.filename as image, P.created, U.filename as profile_picture "
        "FROM posts P, users U "
        "WHERE P.postid = ? AND U.username = P.owner",
        (post_url_slug, )
    ).fetchall()

    likes, logname_liked = get_likes(post_url_slug, connection)
    comments = get_all_comments(post_url_slug, connection)

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
    connection.commit()
    return flask.render_template("post.html", **context)


@insta485.app.route('/users/<user_url_slug>/followers/', methods=['GET'])
def show_followers(user_url_slug):
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row

    logname = flask.session['logname']
    username = user_url_slug
    followers = connection.execute(
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

    logname_follower = [elt['username2'] for elt in logname_follower]

    followers = [{
                    'username': elt['username1'], 
                    'user_img_url': elt['filename'], 
                    'logname_follows_username': elt['username1'] in logname_follower
                } for elt in followers]
    context = {
        'logname': logname,
        'username': user_url_slug,
        'followers': followers
    }
    connection.commit()
    return flask.render_template("followers.html", **context)
    

@insta485.app.route('/users/<user_url_slug>/following/', methods=['GET'])
def show_following(user_url_slug):
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    # open database
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row


    logname = flask.session['logname']
    username = user_url_slug
    following = connection.execute(
        "SELECT F.username2, U.filename "
        "FROM following F, users U "
        "WHERE ? = F.username1 AND F.username2 = U.username ",
        (username,)
    ).fetchall()

    logname_following = connection.execute(
        "SELECT F.username2 "
        "FROM following F "
        "WHERE ? = F.username1",
        (logname,)
    ).fetchall()

    logname_following = [elt['username2'] for elt in logname_following]

    following = [{
                    'username': elt['username2'], 
                    'user_img_url': elt['filename'], 
                    'logname_follows_username': elt['username2'] in logname_following
                } for elt in following]
    context = {
        'logname': logname,
        'username': user_url_slug,
        'following': following
    }
    return flask.render_template("following.html", **context)

@insta485.app.route('/following/', methods=['POST'])
def follow_unfollow():
    """Follow and unfollow functionality."""
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    logname = flask.session['logname']
    # establish connection
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    operation, username = flask.request.form.get('operation'), flask.request.form.get('username')
    target = flask.request.args.get('target')
    # get whether they follow or not
    follows = connection.execute(
            'SELECT F.username2 '
            'FROM following F '
            'WHERE F.username1 = ? AND F.username2 = ?',
            (logname, username)).fetchall()
    if operation == 'follow':
        # see if already follows
        if len(follows) == 1:
            return flask.abort(409)
        else:
            connection.execute(
                "INSERT INTO following(username1, username2) "
                "VALUES (?,?) ",
                (logname, username,)
            )
            connection.commit()
    if operation == 'unfollow':
        # see if they follow
        if len(follows) == 0:
            return flask.abort(409)
        else:
            connection.execute(
                "DELETE FROM following "
                "WHERE username1 = ? AND username2 = ?",
                (logname, username,)
            )
            connection.commit()
    return flask.redirect(target)


@insta485.app.route('/uploads/<filename>')
def send_file(filename):
    if 'logname' not in flask.session:
        return flask.abort(403)
    return flask.send_from_directory(insta485.app.config["UPLOAD_FOLDER"], filename)

@insta485.app.route('/accounts/edit/', methods=['GET'])
def show_edit():
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    # build context for edit page
    # serve edit.html
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row

    logname = flask.session['logname']
    
    profile_information = connection.execute(
        "SELECT U.fullname, U.email, U.filename "
        "FROM users U "
        "WHERE username = ?",
        (logname,)
    ).fetchall()
    context = {
        "logname": logname,
        "logname_profile_pic": profile_information[0]['filename'],
        "logname_fullname" : profile_information[0]['fullname'],
        "logname_email": profile_information[0]['email']
    }
    connection.commit()
    return flask.render_template("edit.html", **context)

@insta485.app.route('/accounts/password/', methods=['GET'])
def show_password():
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    # build context for edit password page
    # serve password.html
    return flask.render_template("password.html")

@insta485.app.route('/accounts/delete/', methods=['GET'])
def show_delete():
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row

    logname = flask.session['logname']

    context = {
        'logname': logname
    }
    connection.commit()
    return flask.render_template("delete.html", **context)


@insta485.app.route('/likes/', methods=['POST'])
def like():
    target = flask.request.args.get('target')
    connection = insta485.model.get_db()
    if 'logname' not in flask.session:
        return flask.redirect('login')
    logname = flask.session['logname']
    if not target:
        target = '/'
    operation = flask.request.form.get('operation')
    postid = flask.request.form.get('postid')
    check = connection.execute(
            "SELECT L.likeid "
            "FROM likes L "
            "WHERE L.postid = ? AND L.owner = ?",
            (postid,logname,)
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
        else:
            return flask.abort(409)

    elif operation == 'unlike':
        # take the like out if it's there
        if len(check) == 1:
            connection.execute(
                "DELETE FROM likes "
                "WHERE owner = ? AND postid = ?",
                (logname, postid, )
            )
            connection.commit()
            return flask.redirect(target)
        else:
            return flask.abort(409)


@insta485.app.route('/comments/', methods=['POST'])
def comment():
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
    operation, postid = flask.request.form.get('operation'), flask.request.form.get('postid')
    commentid, text = flask.request.form.get('commentid'), flask.request.form.get('text')
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
    # check to see if logged in
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    # snag that target
    target = flask.request.args.get('target')
    # db4eva
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    # if it fits it sits
    if target is None:
        target = flask.url_for('show_user', user_url_slug=flask.session['logname'])
    # opopopopopopopopopopopop
    operation = flask.request.form.get('operation')
    #c
    if operation == 'create':
        # Unpack flask object
        fileobj = flask.request.files["file"]
        # empty file = abort 400 
        if fileobj is None:
            return flask.abort(400)
        filename = fileobj.filename
        # Compute base name (filename without directory).  We use a UUID to avoid
        # clashes with existing files, and ensure that the name is compatible with the
        # filesystem.
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
    elif operation == 'delete':
        # check if the post exists
        postid = flask.request.form.get('postid')
        checking = connection.execute(
            'SELECT P.owner, P.filename '
            'FROM posts P '
            'WHERE P.postid = ? ',
            (postid,)
        ).fetchall()
        if len(checking) != 0:
            return flask.abort(404)
        if checking[0]['owner'] != flask.sesion['logname']:
            return flask.abort(403)
        # delete the post
        connection.execute(
            'DELETE FROM posts '
            'WHERE postid = ? ',
            (postid,)
        )
        connection.commit()
        # delete the file
        # TODO: IAN NICOLE IAN NICOLE IAN NICOLE DELETE THE FILE FROM THE SYSTEM
        return flask.redirect(target)

@insta485.app.route('/accounts/create/', methods=['GET'])
def show_create():
    if 'logname' in flask.session:
        return flask.redirect(flask.url_for('show_edit'))
    else:
        return flask.render_template('create.html')