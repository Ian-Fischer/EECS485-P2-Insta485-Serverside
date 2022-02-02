"""
Insta485 index (main) view.

URLs include:
/
"""
import re
from re import L
import arrow
import flask
from pyparsing import empty
import insta485
import sqlite3
import pdb
import uuid 
import hashlib

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
        "SELECT C.owner, C.text "
        "FROM comments C "
        "WHERE C.postid = ? ",
        (postid,)
    ).fetchall()
    return [{'owner' : elt['owner'], 'text': elt['text']} for elt in comments]

def get_likes(postid, connection):
    return len(connection.execute(
                "SELECT L.likeid "
                "FROM likes L "
                "WHERE L.postid = ? ",
                (postid, )
            ).fetchall())

@insta485.app.route('/')
def show_index():
    """Display / route."""
    # Connect to database
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row

    if 'logname' not in flask.session:
        return flask.render_template("login.html")
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
                likes = get_likes(post['postid'],connection)
                len(connection.execute(
                    "SELECT L.postid "
                    "FROM likes L "
                    "WHERE L.postid = ? ",
                    (post['postid'],)).fetchall())
                comments = get_all_comments(post['postid'], connection)
                posts.append({
                    "postid" : post['postid'],
                    "owner" : post['owner'],
                    "owner_img_url" : insta485.app.config['UPLOAD_FOLDER']/post['ufilename'],
                    "img_url" : insta485.app.config['UPLOAD_FOLDER']/post['pfilename'],
                    "timestamp" : arrow.get(post['created']).to('US/Eastern').humanize(),
                    "likes" : likes,
                    "comments" : comments
                })
        # now we have gone through all the following and collected all their posts
        # build context
        context = {
            "logname": logname,
            "posts": posts
        }
        return flask.render_template("index.html",  **context)

@insta485.app.route('/explore/', methods=['GET'])
def show_explore():
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
        (logname,logname, )
    ).fetchall()

    not_following = []
    for user in users:
        profile_pic = connection.execute(
            "SELECT U.filename "
            "FROM users U "
            "WHERE U.username = ? ",
            (user[0], )
        ).fetchall()
        user_dict = {}
        user_dict['username'] = user[0]
        user_dict['user_img_url'] = insta485.app.config['UPLOAD_FOLDER']/profile_pic[0][0]
        not_following.append(user_dict)

    context = {
        'logname': logname,
        'not_following': not_following
    }

    return flask.render_template("explore.html", **context)

@insta485.app.route('/accounts/logout/', methods=['POST'])
def logout():
    flask.session.clear()
    return flask.redirect(flask.url_for('show_index'))

@insta485.app.route('/accounts/login/', methods=['POST'])
def login():
    # if already logged in, redirect to the homepage
    if 'logname' in flask.session:
        return flask.redirect(flask.url_for('show_index'))
    # POST-only route for handling login requests
    flask.session['logname'] = flask.request.form['username']
    password = flask.request.form.get('password')

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
    hashed_password = hash_password(password, get_salt(curr_password))
    if curr_password != hashed_password:
        flask.session.clear()
        return flask.redirect(flask.url_for('show_index'))
    else:
        return flask.redirect(flask.url_for('show_index'))

@insta485.app.route('/users/<user_url_slug>/', methods=['GET'])
def show_user(user_url_slug):
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
        flask.abort(404)
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
    posts = [{'postid': elt['postid'], 'img_url': insta485.app.config['UPLOAD_FOLDER']/elt['filename']} for elt in posts_tbl]
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
    return flask.render_template("user.html", **context)


@insta485.app.route('/posts/<post_url_slug>/', methods=['GET'])
def show_post(post_url_slug):
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row

    logname = flask.session['logname']
    post = connection.execute(
        "SELECT P.owner, P.filename as image, P.created, U.filename as profile_picture "
        "FROM posts P, users U "
        "WHERE P.postid = ? AND U.username = P.owner",
        (post_url_slug, )
    ).fetchall()
    likes = get_likes(post_url_slug, connection)
    comments = get_all_comments(post_url_slug, connection)

    context = {
        'logname': logname,
        'postid': post_url_slug,
        "owner": post[0][0],
        "owner_img_url": insta485.app.config['UPLOAD_FOLDER']/post[0][3],
        "img_url": insta485.app.config['UPLOAD_FOLDER']/post[0][1],
        "timestamp": arrow.get(post[0][2]).to('US/Eastern').humanize(),
        "likes": likes,
        "comments": comments
    }

    return flask.render_template("post.html", **context)


@insta485.app.route('/users/<user_url_slug>/followers/', methods=['GET'])
def show_followers(user_url_slug):
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
                    'user_img_url': insta485.app.config['UPLOAD_FOLDER']/elt['filename'], 
                    'logname_follows_username': elt['username1'] in logname_follower
                } for elt in followers]
    context = {
        'logname': logname,
        'followers': followers
    }
    return flask.render_template("followers.html", **context)
    

@insta485.app.route('/users/<user_url_slug>/following/', methods=['GET'])
def show_following(user_url_slug):
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
                    'user_img_url': insta485.app.config['UPLOAD_FOLDER']/elt['filename'], 
                    'logname_follows_username': elt['username2'] in logname_following
                } for elt in following]
    context = {
        'logname': logname,
        'following': following
    }
    return flask.render_template("following.html", **context)

@insta485.app.route('/following/', methods=['POST'])
def follow_unfollow():
    target = flask.request.args.get('target')

@insta485.app.route(str(insta485.app.config['UPLOAD_FOLDER']/'<path:filename>'))
def send_file(filename):
    return flask.send_from_directory(insta485.app.config["UPLOAD_FOLDER"], filename)

@insta485.app.route('/accounts/edit/', methods=['GET'])
def show_edit():
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
        "logname_profile_pic": insta485.app.config["UPLOAD_FOLDER"]/profile_information[0]['filename'],
        "logname_fullname" : profile_information[0]['fullname'],
        "logname_email": profile_information[0]['email']
    }
    return flask.render_template("edit.html", **context)


@insta485.app.route('/accounts/editing/', methods=['POST'])
def edit_profile():

    target = flask.request.args.get('target')

    fullname, email = flask.request.form.get('fullname'), flask.request.form.get('email')
    file = flask.request.form.get('file')
    
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    logname = flask.session['logname']
    if file:
        cursor.execute(
            "UPDATE users "
            "SET filename = ? "
            "WHERE username = ? ",
            (file, logname,)
        )
    if fullname:
        cursor.execute(
                "UPDATE users "
                "SET fullname = ? "
                "WHERE username = ? ",
                (fullname, logname,)
            )
    if email:
        cursor.execute(
            "UPDATE users "
            "SET email = ? "
            "WHERE username = ? ",
            (email, logname,)
        )
    connection.commit()
    return flask.redirect(target)


@insta485.app.route('/accounts/password/', methods=['GET', 'POST'])
def show_password():
    # build context for edit password page
    # serve password.html
    return flask.render_template("password.html")
    
    

@insta485.app.route('/accounts/changepass/', methods=['POST'])
def edit_password():
    # get the passwords from the form
    # encrypt the passwords
    # check old passcode == password in db
    # update if it matches
    # if not, just redirect to show_password

    password, new_password1 = flask.request.form.get('password'), flask.request.form.get('new_password1')
    new_password2 = flask.request.form.get('new_password2')


    target = flask.request.args.get('target')

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
    
    password_db_string = hash_password(password, get_salt(curr_password))

    if curr_password != password_db_string or new_password1 != new_password2:
        return flask.redirect(flask.url_for('show_password'))

    password_db_string = hash_password(new_password1, get_salt(new_password1))

    connection.execute(
        "UPDATE users "
        "SET password = ? "
        "WHERE username = ? ",
        (password_db_string, logname, )
    )
    return flask.redirect(target)


@insta485.app.route('/accounts/delete/', methods=['GET', 'POST'])
def show_delete():
    
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row

    logname = flask.session['logname']

    context = {
        'logname': logname
    }

    return flask.render_template("delete.html", **context)

@insta485.app.route('/accounts/deleting/', methods=['POST'])
def delete_account():
    
    target = flask.request.args.get('target')

    connection = insta485.model.get_db()

    connection.row_factory = sqlite3.Row

    logname = flask.session['logname']

    connection.execute(
        "DELETE FROM users "
        "WHERE username = ? ",
        (logname, )
    )
    flask.session.clear()
    
    return flask.redirect(target)


@insta485.app.route('/likes/', methods=['POST'])
def like():

    target = flask.request.args.get('target')
    connection = insta485.model.get_db()
    logname = flask.session['logname']
    if not target:
        target = '/'
    operation = flask.request.form.get('operation')
    postid = flask.request.form.get('postid')
    post_info = connection.execute(
        "SELECT P.owner, P.created "
        "FROM posts P "
        "WHERE P.postid = ?",
        (postid,)
    )
    check = connection.execute(
            "SELECT L.likeid "
            "FROM likes L "
            "WHERE L.postid = ? AND L.owner = ?",
            (postid,logname,)
    ).fetchall()       
    
    if operation == 'like':
        # put the like in the database if it is not there
        if len(check) != 1:
            connection.execute(
                "INSERT INTO likes(owner, postid) "
                "VALUEs (?,?) ",
                (logname, postid,))
        return flask.redirect(target)
    
    elif operation == 'unlike':
        # take the like out if it's there
        if check:
            connection.execute(
                "DELETE FROM likes "
                "WHERE owner = ? AND postid = ?",
                (logname, postid, )
            )
        return flask.redirect(target)
    else:
        return flask.redirect(target)


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
    # get form information
    operation, postid = flask.request.form.get('operation'), flask.request.form.get('postid')
    commentid, text = flask.request.form.get('commentid'), flask.request.form.get('text')
    if operation is 'create':
        # do something 
        print('beanboy')
    elif operation is 'delete':
        # do something
        print('beanboy')
    elif not text:
        flask.abort(400)
    else:
        # something doesn't add up do nothing!
        return flask.redirect(target)


    # send to the target
    return flask.redirect(target)