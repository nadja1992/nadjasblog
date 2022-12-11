from flask import Flask, render_template, redirect, url_for, request, flash, g, abort
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, PasswordField
from wtforms.validators import DataRequired, URL, Email, Length
from flask_ckeditor import CKEditor, CKEditorField
from datetime import datetime
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_gravatar import Gravatar
import gunicorn

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['CKEDITOR_PKG_TYPE'] = 'standard'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

#Configure table for Users
class User(db.Model, UserMixin):
    __tablename__='user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), unique=True, nullable=False)
    posts = db.relationship('BlogPost', backref = 'user')
    comments = db.relationship('Comment', backref ='user')

##CONFIGURE TABLE FOR POSTS
class BlogPost(db.Model):
    __tablename__ = 'blog_post'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.String(250), nullable=False)
    author = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, ForeignKey('user.id'))
    comments = db.relationship('Comment', backref='blog_post')

#CONFIGURE TABLE FOR COMMENTS
class Comment (db.Model):
    __tablename__='comment'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, ForeignKey('user.id'))
    post_id = db.Column(db.Integer, ForeignKey('blog_post.id'))

with app.app_context():
    db.create_all()

##Post Submission Form
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    author = StringField("Your Name", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField('Content')
    submit = SubmitField("Submit Post")

#User Registration Form
class RegisterForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField ('Password', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired(), Length(min=4, max=12)])
    submit = SubmitField("SING ME UP!")

#User Login Form
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField("LET ME IN!")

#Comments Form
class CommentForm(FlaskForm):
    comment = CKEditorField('')
    submit = SubmitField("SUBMIT COMMENT")

#Decorator that will be added to /delete, /edit-post and /new-post routes to make sure they can't be accessed unless user is admin (with id =1)
def admin_only(f):
    @wraps(f)
    def wrapper_function(**kwargs):
        if current_user is not None:
            if current_user.get_id()=="1":
                return f(**kwargs)
            else:
                return abort(403)
    wrapper_function.__name__ = f.__name__
    return wrapper_function

#Gravatar - slika za usere
gravatar = Gravatar(app, size=35, rating='g', default='retro', force_default=False,force_lower=False,use_ssl=False,base_url=None)


#home-page
@app.route('/')
def get_all_posts():
    posts = db.session.query(BlogPost).all()
    return render_template("index.html", all_posts=posts)

#show a post
@app.route("/post/<int:index>", methods = ['GET', 'POST'])
def show_post(index):
    form = CommentForm()
    posts = db.session.query(BlogPost).all()
    requested_post = None
    for blog_post in posts:
        if blog_post.id == index:
            requested_post = blog_post

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login in order to comment")
            return redirect(url_for('login'))
        else:
            comment = Comment(text=form.comment.data, user_id = int(current_user.get_id()), post_id = requested_post.id)
            db.session.add(comment)
            db.session.commit()
    #Uzimamo sve komentare koji su ostavljeni za taj post
    all_comments = db.session.query(Comment).filter_by(post_id = requested_post.id)
    #Izvlacimo usere koji su ostavili komentare
    users = [User.query.get(comment.user_id)  for comment in all_comments]
    return render_template("post.html", post=requested_post, form = form, all_comments=all_comments, users = users)

#about
@app.route("/about")
def about():
    return render_template("about.html")

#contact
@app.route("/contact")
def contact():
    return render_template("contact.html")

#editing a post
@app.route("/edit-post/<int:post_id>", methods=['GET', "POST"])
@admin_only
def edit_post(post_id):
    post_to_edit = BlogPost.query.get(post_id)
    form=CreatePostForm()
    if request.method =='GET':
        form.title.data = post_to_edit.title
        form.subtitle.data = post_to_edit.subtitle
        form.author.data = post_to_edit.author
        form.img_url.data = post_to_edit.img_url
        form.body.data = post_to_edit.body
        return render_template("make-post.html", form = form, page_title = "Edit Post")
    else:
        post_to_edit.title= form.title.data
        post_to_edit.subtitle= form.subtitle.data
        post_to_edit.author= form.author.data
        post_to_edit.img_url= form.img_url.data
        post_to_edit.body = form.body.data
        db.session.commit()
        return redirect(url_for('show_post', index = post_to_edit.id))

#adding a post
@app.route("/new-post", methods=['GET', "POST"])
@admin_only
def new_post():
    form = CreatePostForm()
    today = datetime.today().strftime("%B %d,%Y")
    if form.validate_on_submit():
        post_to_add = BlogPost(title = form.title.data, date = today, body = form.body.data, author = form.author.data, img_url = form.img_url.data, subtitle = form.subtitle.data, user_id=int(current_user.get_id()))
        db.session.add(post_to_add)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    else:
        return render_template("make-post.html", form = form, page_title = "New Post")

#deleting a post
@app.route("/delete/<int:post_id>", methods = ['DELETE', 'GET'])
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

#registering new user
@app.route('/register', methods = ["POST", "GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email = form.email.data).first()==None and User.query.filter_by(name = form.name.data).first()==None:
            hashed_pass = generate_password_hash(password=form.password.data, method='pbkdf2:sha256', salt_length=4 )
            new_user = User(email = form.email.data, password = hashed_pass, name = form.name.data)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        elif User.query.filter_by(email = form.email.data).first()!=None:
            flash("You've already registered with that email. Try loging in instead.")
            return redirect(url_for('login'))

        else:
            flash ("That name's already taken. Please choose another name")
    return render_template('register.html', form = form)

#loging in
@app.route('/login', methods = ["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user_to_login = User.query.filter_by(email=email).first()
        if user_to_login==None:
            flash("This user doesn't exist.")
        else:
            if not check_password_hash(pwhash=user_to_login.password, password=password):
                flash('Password is incorrect')
            else:
                login_user(user_to_login)
                return redirect(url_for('get_all_posts'))
    return render_template('login.html', form = form)

#logging out
@app.route('/logout', methods = ['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

if __name__ == "__main__":
    app.run(debug=True)