"""
Insta485 index (main) view.

URLs include:
/
"""
from re import L
import flask
import insta485
import sqlite3
import pathlib

@insta485.app.route('/')
def show_index():
    """Display / route."""
    # Connect to database
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row

    if 'logname' not in flask.session:
        return flask.render_template("login.html")
    else:
        context = {}
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
        # for user in following:
        #     user_posts = connection.execute(
        #         "SELECT P.postid AS postid, P.filename as pfilename, P.owner AS owner, P.created AS created, U.filename AS ufilename "
        #         "FROM posts P, users U, likes L "
        #         "WHERE P.owner = ? AND ? = U.users AND L.postid = P.postid",
        #         (user,)
        #     ).fetchall()
        #     for post in user_posts:
        #         likes = 
        #         posts.append({
        #             "postid" : post['postid']
        #             "owner" : post['owner']
        #             "owner_img_url" : post['ufilename']
        #             "img_url" : post['pfilename']
        #             "timestamp" : post['created']
        #             "likes" : 
        #             "comments" : [
        #                 {
        #                     "owner" :
        #                     "text" :
        #                 } 
        #             ]
        #         })
        return flask.render_template("index.html",  **context)



@insta485.app.route('/accounts/login/', methods=['POST'])
def login():
    # POST-only route for handling login requests
    # TODO: Implement this route
    print('DEBUG Login:', flask.request.form['username'])
    flask.session['logname'] = flask.request.form['username']
    return flask.redirect(flask.url_for('show_index'))

# @insta485.app.route('/accounts/create/', methods=['POST'])
# def create():
