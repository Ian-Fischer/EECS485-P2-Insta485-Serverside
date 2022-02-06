"""
Includes post related endpoints.

URLs include:
/posts/<post_url_slug>/
/posts/
"""
import sqlite3
import arrow
import flask
import insta485
from insta485.views.helper import get_all_comments, get_likes, get_file_path


@insta485.app.route('/posts/<post_url_slug>/', methods=['GET'])
def show_post(post_url_slug):
    """Display /posts/<post_url_slug>/ route."""
    # if not in session, login, True if O.K.
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    # connect to database
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
    # get likes and comments
    likes, logname_liked = get_likes(post_url_slug, connection)
    comments = get_all_comments(post_url_slug, connection)
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
        path, uuid_basename = get_file_path(filename)
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
