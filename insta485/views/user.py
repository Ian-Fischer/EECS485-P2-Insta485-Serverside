"""
Includes user related endpoints.

URLs include:
/users/<user_url_slug>/
/users/<user_url_slug>/following/
/users/<user_url_slug>/followers/
"""
import sqlite3
import flask
import insta485


@insta485.app.route('/users/<user_url_slug>/', methods=['GET'])
def show_user(user_url_slug):
    """Display /users/<user_url_slug>/ route."""
    # check to see if logged in, else red. to login
    # if not in session, login, True if O.K.
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    # open database
    logname = flask.session['logname']
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
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


@insta485.app.route('/users/<user_url_slug>/following/', methods=['GET'])
def following(user_url_slug):
    """Display /users/<user_url_slug>/following/ route."""
    # if not in session, login, True if O.K.
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


@insta485.app.route('/users/<user_url_slug>/followers/', methods=['GET'])
def followers(user_url_slug):
    """Display /users/<user_url_slug>/followers/ route."""
    # check to see if logged in, else redirect to login
    # if not in session, login, True if O.K.
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
