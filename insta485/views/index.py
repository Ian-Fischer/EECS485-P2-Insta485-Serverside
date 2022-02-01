"""
Insta485 index (main) view.

URLs include:
/
"""
from re import L
import arrow
import flask
import insta485
import sqlite3
import pdb

def get_all_comments(postid, connection):
    comments = connection.execute(
        "SELECT C.owner, C.text "
        "FROM comments C "
        "WHERE C.postid = ? ",
        (postid,)
    ).fetchall()
    return [{'owner' : elt['owner'], 'text': elt['text']} for elt in comments]

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
                likes = len(connection.execute(
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

@insta485.app.route('/accounts/logout/', methods=['POST'])
def logout():
    flask.session.clear()
    return flask.redirect(flask.url_for('show_index'))

@insta485.app.route('/accounts/login/', methods=['POST'])
def login():
    # POST-only route for handling login requests
    flask.session['logname'] = flask.request.form['username']
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
    )

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


@insta485.app.route('/users/<user_url_slug>/followers/', methods=['GET'])
def show_followers(user_url_slug):
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    # FIX ME FIX ME FIX ME
    logname = flask.session['logname']
    username = user_url_slug
    followers = connection.execute(
        "SELECT F.username1, U.filename"
        "FROM following F, users U"
        "WHERE ? = F.username2 AND ? = U.user",
        (username, username,)
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
    # build the context
    # logname, username, logname_follows_username, fullname, following, followers
    # total_posts, posts = [{'postid', 'img_url'}]

    logname = flask.session['logname']
    username = user_url_slug
    following = connection.execute(
        "SELECT F.username2, U.filename"
        "FROM following F, users U"
        "WHERE ? = F.username1 AND ? = U.user",
        (username, username, )
    ).fetchall()

    following = connection.execute(
        "SELECT F.username2 "
        "FROM following F "
        "WHERE ? = F.username1",
        (logname,)
    ).fetchall()

    following = [{
                    'username': elt['username1'], 
                    'user_img_url': insta485.app.config['UPLOAD_FOLDER']/elt['filename'], 
                    'logname_follows_username': elt['username1'] in following
                } for elt in following]
    context = {
        'logname': logname,
        'following': following
    }
    return flask.render_template("followers.html", **context)

@insta485.app.route('/following/', methods=['POST'])
def follow_unfollow():
    target = flask.request.args.get('target')

@insta485.app.route(str(insta485.app.config['UPLOAD_FOLDER']/'<path:filename>'))
def send_file(filename):
    return flask.send_from_directory(insta485.app.config["UPLOAD_FOLDER"], filename)