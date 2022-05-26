from flask import Flask, render_template, request, session, redirect
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)
DATABASE = "identifier.sqlite"
app.secret_key = "s34de5f7r6g77hu78"
bcrypt = Bcrypt(app)


def create_connection(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)
    return None


def categories():
    query = "SELECT id, category_name FROM categories"
    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    con.close()
    return category_list


def vocab():
    query = "SELECT * FROM vocab"
    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute(query)
    vocab_list = cur.fetchall()
    con.close()
    return vocab_list


@app.route('/')
def hello_world():
    print(categories())
    print(vocab())
    return render_template('home.html', categories=categories(), logged_in=is_logged_in())


@app.route('/login', methods=['GET', 'POST'])
def render_login():
    if is_logged_in():
        return redirect('/')

    if request.method == "POST":
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        print(request.form)
        query = """SELECT id, fname, password FROM customer WHERE email = ?"""
        con = create_connection(DATABASE)
        cur = con.cursor()
        cur.execute(query, (email,))
        user_data = cur.fetchall()
        con.close()

        try:
            userid = user_data[0][0]
            firstname = user_data[0][1]
            db_password = user_data[0][2]
        except IndexError:
            return redirect("/login?")

        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + "?error=Email+invalid+or+password+incorrect")

        session['email'] = email
        session['userid'] = userid
        session['firstname'] = firstname
        print(session)
        return redirect('/')
    return render_template('login.html', logged_in=is_logged_in())


@app.route('/signup', methods=['GET', 'POST'])
def render_signup():
    if is_logged_in():
        return redirect('/')

    if request.method == 'POST':
        print(request.form)
        fname = request.form.get('fname').strip().title()
        lname = request.form.get('lname').strip().title()
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        password2 = request.form.get('password2')

        if password != password2:
            return redirect('/signup?error=Passwords+dont+match')

        if len(password)<8:
            return redirect('/signup?error=Passowrd+must+be+8+characters+or+more')

        hashed_password = bcrypt.generate_password_hash(password)

        con = create_connection(DATABASE)

        query = "INSERT INTO customer (id, fname, lname, email, password) VALUES(NULL,?,?,?,?)"

        cur = con.cursor()
        try:
            cur.execute(query, (fname, lname, email, hashed_password))
        except sqlite3.IntegrityError:
            return redirect('/signup?error=Email+is+already+used')

        con.commit()
        con.close()
        return redirect('/login')

    return render_template('signup.html', logged_in=is_logged_in())


@app.route('/logout')
def logout():
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    return redirect('/?message=See+you+next+time!')


def is_logged_in():
    if session.get("email") is None:
        print("not logged in")
        return False
    else:
        print("logged in")
        return True


@app.route('/category/<cat_id>')
def render_list(cat_id):
    return render_template('category.html', categories=categories(), vocab_list=vocab(), cat_id=int(cat_id)
                           , logged_in=is_logged_in())

@app.route('/word/<word_id>')
def render_word(word_id):
    return render_template('word.html', categories=categories(), vocab_list=vocab(), word_id=int(word_id),
                           logged_in=is_logged_in())

if __name__ == '__main__':
    app.run()
