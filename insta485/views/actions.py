"""
Includes POST action related endpoints.

URLs include:
/following
/likes/
/comments/
"""
import sqlite3
import flask
import insta485


@insta485.app.route('/following/', methods=['POST'])
def follow_unfollow():
    """Follow and unfollow functionality."""
    # if not in session, login, True if O.K.
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    # else get the logname
    logname = flask.session['logname']
    # get form data
    operation = flask.request.form.get('operation')
    username = flask.request.form.get('username')
    target = flask.request.args.get('target')
    # check to see if none
    # establish connection
    connection = insta485.model.get_db()
    connection.row_factory = sqlite3.Row
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
