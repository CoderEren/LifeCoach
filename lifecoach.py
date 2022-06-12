from flask import Flask, render_template, request, redirect, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import psycopg2

app = Flask(__name__)
connection_url = os.environ["DATABASE_URI"]
app.config['SQLALCHEMY_DATABASE_URI'] = connection_url
app.secret_key = 'LifeCoach'

db = SQLAlchemy(app)

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    email = db.Column(db.String(200))
    password = db.Column(db.String(200))

class Coach(db.Model):
    coach_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    email = db.Column(db.String(200))
    password = db.Column(db.String(200))

class Message(db.Model):
    message_id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer)
    receiver_id = db.Column(db.Integer)
    message = db.Column(db.String(500))

class Request(db.Model):
    request_id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer)
    sender_name = db.Column(db.String(200))
    sender_email = db.Column(db.String(200))
    receiver_id = db.Column(db.Integer)

def exec_statement(conn, stmt):
    try:
        with conn.cursor() as cur:
            cur.execute(stmt)
            res = cur.fetchall()
            conn.commit()
            print(cur.statusmessage)
            return res
    except psycopg2.Error as e:
        print("Error: ", e.diag.message_primary)

user_counter = 1

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/signup', methods=["POST", "GET"])
def signup():
    global user_counter
    if request.method == "POST":
        name = request.form['full-name']
        email = request.form['email']
        password = request.form['password']
        if email == "" or password == "":
            flash("Email/password cannot be blank.", category="error")
            return redirect('/')
        
        coach = False
        if request.form.get("coach"):
            coach = True

        connection = psycopg2.connect(connection_url)

        if coach:
            coach_user = exec_statement(connection, f"SELECT * FROM coaches WHERE email='{email}'")
            if coach_user:
                flash("An account with that email address already exists.", category="error")
                return redirect('/signup')
            else:
                new_password = generate_password_hash(password, method='sha256')
                exec_statement(connection, f"INSERT INTO coaches (coach_id, name, email, password) VALUES ({user_counter}, '{name}', '{email}', '{new_password}')")
                user_counter += 1
                connection.close()
                session['coach-email'] = request.form['email']
                return redirect("/home")
        else:
            user = exec_statement(connection, f"SELECT * FROM users WHERE email='{email}'")
            if user:
                flash("An account with that email address already exists.", category="error")
                return redirect('/signup')
            else:
                new_password = generate_password_hash(password, method='sha256')
                exec_statement(connection, f"INSERT INTO users (user_id, name,email,password) VALUES ({user_counter}, '{name}', '{email}', '{new_password}')")
                user_counter += 1
                connection.close()
                session['email'] = request.form['email']
                return redirect("/home")
    elif request.method == "GET":
        return render_template("signup.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        if email == "" or password == "":
            flash("Email/password cannot be blank.", category="error")

        coach = False
        if request.form.get("coach"):
            coach = True

        connection = psycopg2.connect(connection_url)

        if coach:
            coach_user = exec_statement(connection, f"SELECT * FROM coaches WHERE email='{email}'")
            if coach_user:
                if check_password_hash(coach_user.password, password):
                    session['coach-email'] = email
                    return redirect("/home")
                else:
                    flash("Wrong password, please try again.", category="error")
                    return redirect("/login")
            else:
                flash("Email does not exist.", category="error")
                return redirect("/login")
        else:
            user = exec_statement(connection, f"SELECT * FROM users WHERE email='{email}'")
            if user:
                if check_password_hash(user.password, password):
                    session['email'] = email
                    return redirect("/home")
                else:
                    flash("Wrong password, please try again.", category="error")
                    return redirect("/login")
            else:
                flash("Email does not exist.", category="error")
                return redirect("/login")
    else:
        if 'email' in session:
            return redirect("/home")
        elif 'coach-email' in session:
            return redirect("/home")
        else:
            return render_template("login.html")
        
@app.route('/home')
def home():
    connection = psycopg2.connect(connection_url)
    if 'email' in session:
        coaches = exec_statement(connection, "SELECT * FROM coaches LIMIT 10")
        connection.close()
        return render_template("home.html", user_email=session['email'], coaches=coaches)
    elif 'coach-email' in session:
        coach_email = session['coach-email']
        coach_id = exec_statement(connection, f"SELECT * FROM coaches WHERE email='{coach_email}'")
        requests = exec_statement(connection, f"SELECT * FROM requests WHERE receiver_id='{coach_id[0][0]}'")
        connection.close()
        return render_template("home.html", coach_email=session['coach-email'], requests=requests, coach_id=coach_id[0][0])
    else:
        return redirect('/')

@app.route('/request', methods=["POST"])
def requests():
    coach_id = request.form["coach_id"]
    user_email = request.form['user_email']

    connection = psycopg2.connect(connection_url)

    sender = exec_statement(connection, f"SELECT * FROM users WHERE email='{user_email}'")
    existing_request = exec_statement(connection, f"SELECT * FROM requests WHERE sender_id={sender[0][0]} AND receiver_id={coach_id}")
    
    if existing_request:
        return redirect(url_for("message", sender=sender[0][0], receiver=coach_id))
    else:
        exec_statement(connection, f"INSERT INTO requests (sender_id, sender_name, sender_email, receiver_id) VALUES ({sender[0][0]}, '{sender[0][1]}', '{sender[0][2]}', {coach_id})")
        return redirect(url_for("message", sender=sender[0][0], receiver=coach_id))

@app.route('/message', methods=["GET", "POST"])
def message():
    if request.method == "POST":
        message = request.form["message"]
        sender_id = request.form["sender_id"]
        receiver_id = request.form["receiver_id"]

        connection = psycopg2.connect(connection_url)
        
        exec_statement(connection, f"INSERT INTO messages (sender_id, receiver_id, message) VALUES ({sender_id}, {receiver_id}, '{message}')")
        if 'email' in session:
            return redirect(url_for("message", sender=sender_id, receiver=receiver_id))
        else:
            return redirect(url_for("message", sender=receiver_id, receiver=sender_id))
    else:
        sender = request.args.get('sender')
        receiver = request.args.get('receiver')

        connection = psycopg2.connect(connection_url)

        sender_email = exec_statement(connection, f"SELECT * FROM users WHERE user_id={sender}")
        receiver_email = exec_statement(connection, f"SELECT * FROM coaches WHERE coach_id={receiver}")
        
        if 'email' in session:
            if session["email"] == sender_email[0][2]:
                user_messages = exec_statement(connection, f"SELECT * FROM messages WHERE sender_id={sender_email[0][0]} AND receiver_id={receiver_email[0][0]}")
                coach_messages = exec_statement(connection, f"SELECT * FROM messages WHERE sender_id={receiver_email[0][0]} AND receiver_id={sender_email[0][0]}")
                
                messages = user_messages + coach_messages
                ids = []
                for message in messages:
                    ids.append({"id":message[0], "sender":int(message[1]), "receiver":message[2], "message":message[3]})
                newlist = sorted(ids, key=lambda d: d['id']) 
                return render_template("message.html", messages=newlist, user_email=session["email"], user_name=receiver_email[0][1])
        elif 'coach-email' in session:
            if session['coach-email'] == receiver_email[0][2]:
                user_messages = exec_statement(connection, f"SELECT * FROM messages WHERE sender_id={sender_email[0][0]} AND receiver_id={receiver_email[0][0]}")
                coach_messages = exec_statement(connection, f"SELECT * FROM messages WHERE sender_id={receiver_email[0][0]} AND receiver_id={sender_email[0][0]}")
                             
                messages = user_messages + coach_messages
                ids = []
                for message in messages:
                    ids.append({"id":message[0], "sender":int(message[1]), "receiver":message[2], "message":message[3]})
                newlist = sorted(ids, key=lambda d: d['id']) 
                return render_template("message.html", messages=newlist, coach_email=session["coach-email"], user_name=sender_email[0][1])

@app.route('/logout', methods=["POST"])
def logout():
    session.pop("email", None)
    session.pop("coach-email", None)
    return redirect('/')



if __name__ == "__main__":
    app.run(port=8000, debug=False)
