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
                    "owner_img_url" : post['ufilename'],
                    "img_url" : post['pfilename'],
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


@insta485.app.route('/accounts/login/', methods=['POST'])
def login():
    # POST-only route for handling login requests
    # TODO: Implement this route
    print('DEBUG Login:', flask.request.form['username'])
    flask.session['logname'] = flask.request.form['username']
    return flask.redirect(flask.url_for('show_index'))

@insta485.app.route('/var/uploads/<path:filename>')
def send_file(filename):
    return flask.send_from_directory("/", filename)

@insta485.app.route('/accounts/create/', methods=['POST'])
def create():
