"""
Includes accounts related endpoints.

URLs include:
/accounts/login/
/accounts/logout/
/accoutns/create/
/accounts/delete/
/accounts/edit/
/accounts/password/
/accounts/
"""
import sqlite3
import flask
import insta485
from insta485.views.helper import handle_account_create, handle_account_delete
from insta485.views.helper import handle_account_edit, handle_account_login
from insta485.views.helper import handle_account_password


@insta485.app.route('/accounts/login/', methods=['GET'])
def login():
    """Display /accounts/login/ route."""
    # if already logged in, redirect to the homepage
    if 'logname' not in flask.session:
        return flask.render_template('login.html')
    return flask.redirect(flask.url_for('show_index'))


@insta485.app.route('/accounts/logout/', methods=['POST'])
def logout():
    """Endpoint for logging out."""
    # log user out via session clear, redirect to login
    flask.session.clear()
    return flask.redirect(flask.url_for('login'))


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
    # establish db connection
    connection = insta485.model.get_db()
    # if not in session, login, True if O.K.
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
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
