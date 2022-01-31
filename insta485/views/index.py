"""
Insta485 index (main) view.

URLs include:
/
"""
import flask
import insta485


@insta485.app.route('/')
def show_index():
    """Display / route."""

    # Connect to database
    connection = insta485.model.get_db()

    # Query database
    logname = "awdeorio"
    cur = connection.execute(
        "SELECT username, fullname "
        "FROM users "
        "WHERE username != ?",
        (logname, )
    )
    users = cur.fetchall()

    # Add database info to context
    context = {"users": users}
    return flask.render_template("index.html", **context)