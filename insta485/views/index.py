"""
Insta485 index (main) view.

URLs include:
/
"""
from re import L
import flask
import insta485


@insta485.app.route('/')
def show_index():
    """Display / route."""

    # Connect to database
    connection = insta485.model.get_db()

    if 'logname' not in flask.session:
        return flask.render_template("login.html")
    else:
        context = {}
        # 1. get all following
        logname = flask.session['logname']
        following = list(connection.execute(
            "SELECT F.username2"
            "FROM following F"
            "WHERE F.username1 = ?"
            (logname,)
        ))
        posts = []
        for user in following:
            
            posts.append({
                "postid" : 
                "owner" :
                "owner_img_url" :
                "img_url" : 
                "timestamp" :
                "likes" : 
                "comments" : [
                    {
                        "owner" :
                        "text" :
                    } 
                ]
            })
        return flask.render_template("login.html",  **context)


    # Query database
    logname = "awdeorio"
    cur = connection.execute(
        "SELECT username, fullname "
        "FROM users "
        "WHERE username != ?",
        (logname, )
    
    users = cur.fetchall()

    # Add database info to context
    context = {"users": users}
    return flask.render_template("index.html", **context)






@app.route('/accounts/login/', methods=['POST'])
def login():
    # POST-only route for handling login requests
    # TODO: Implement this route
    print('DEBUG Login:', flask.request.form['username'])
    flask.session['logname'] = flask.request.form['username']
    return flask.redirect(flask.url_for('show_index'))

@app.route('/accounts/create/', methods=['POST'])
def create():
