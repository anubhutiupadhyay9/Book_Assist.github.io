from flask import Flask,render_template,request,url_for,redirect,session , flash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
import mysql.connector
import pickle
import numpy as np
from datetime import timedelta
import os
import re
from passlib.hash import sha256_crypt


app = Flask(__name__,template_folder='templates',static_folder='staticFiles')
app.secret_key=os.urandom(24)

conn=mysql.connector.connect(host="127.0.0.1",user="root",password="",database="database")
cursor=conn.cursor()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return login.query.get(int(user_id))

popular_df = pickle.load(open('popular.pkl','rb'))
pt = pickle.load(open('pt.pkl','rb'))
books = pickle.load(open('books.pkl','rb'))
similarity_scores = pickle.load(open('similarity_scores.pkl','rb'))


@app.route('/')
def firstpage():
    return render_template('firstpage.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/login_validation',methods=['POST','GET'])
def login_validation():
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form :
        email=request.form.get('email') 
        password=request.form.get('password')

        cursor.execute("""SELECT * FROM `login` WHERE `email` LIKE '{}' """.format(email))
        users=cursor.fetchone()

        if users and sha256_crypt.verify(request.form.get('password'), users[3]):
            session['loggedin'] =True
            return redirect('/index')
        else:
            flash("Invalid Credentials","danger")
            return redirect('/login')
        #here if the login info is not correct then show an error popup message and redirect to login
    return redirect('/login')


@app.route('/add_user',methods=['POST','GET'])
def add_user():

    if request.method == 'POST' and 'uname' in request.form and 'uemail' in request.form and 'upassword' in request.form :
        name=request.form.get('uname')
        email=request.form.get('uemail') 
        password=request.form.get('upassword')
        hashed_password= sha256_crypt.hash(request.form.get('upassword'))


        cursor.execute("""SELECT * FROM `login` WHERE `email` LIKE '{}'""".format(email))
        myuser=cursor.fetchone()

        if myuser:
            flash("Account already exists !")
            return redirect('/register')
        
        elif not len(password) >= 8:
            flash("Password : Minimum 8 characters" , "info")
            return redirect('/register')
        
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash("Invalid email address!","info")
            return redirect('/register')

        elif not name or not password or not email:
            flash("Please fill out the form!","info")
            return redirect('/register')
        
        else:
            cursor.execute("""INSERT INTO `login`(`user_id`,`Name`,`email`,`password`) VALUES(NULL,'{}','{}','{}')""".format(name,email,hashed_password))
            conn.commit()
            flash("Account created successfully")
            return redirect('/login')

    return redirect('/register')
    

@app.route('/index')
def index():

    if 'loggedin' in session:
        return render_template('index.html',
             book_name = list(popular_df['Book-Title'].values),
             author=list(popular_df['Book-Author'].values),
             image=list(popular_df['Image-URL-M'].values),
             votes=list(popular_df['num_ratings'].values),
             rating=list(popular_df['avg_rating'].values)
              )
    return redirect(url_for('login'))


@app.route('/AboutUs')
def AboutUs():
    return render_template('AboutUs.html')

@app.route('/Help')
def Help():
    return render_template('Help.html')


@app.route('/AboutUsBefore')
def AboutUsBefore():
    return render_template('AboutUsBefore.html')

@app.route('/HelpBefore')
def HelpBefore():
    return render_template('HelpBefore.html')

@app.route('/rec')
def recommend_ui():
    if 'loggedin' in session:
         return render_template('rec.html')
    return redirect(url_for('login'))

@app.route('/recommend_books',methods=['POST','GET'])
def recommend():

    if 'loggedin' in session:
        try:
            user_input = request.form.get('user_input')
            index = np.where(pt.index == user_input)[0][0]
            similar_items = sorted(list(enumerate(similarity_scores[index])), key=lambda x: x[1], reverse=True)[1:5]

            data = []
            for i in similar_items:
                item = []
                temp_df = books[books['Book-Title'] == pt.index[i[0]]]
                item.extend(list(temp_df.drop_duplicates('Book-Title')['Book-Title'].values))
                item.extend(list(temp_df.drop_duplicates('Book-Title')['Book-Author'].values))
                item.extend(list(temp_df.drop_duplicates('Book-Title')['Image-URL-M'].values))

                data.append(item)              
            print(data)
            return render_template('rec.html',data=data)
        
        except IndexError:
            pass
            flash("Book not found.Try Again!","info")
            
        return render_template('rec.html')
    
    return redirect(url_for('login'))
   

@app.route('/logout')
def logout():
    session.pop('loggedin' , None)
    flash("LogOut Successfully","info")
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)