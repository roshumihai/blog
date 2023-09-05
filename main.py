from flask import Flask, render_template, url_for, redirect, request, jsonify, flash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField
from wtforms.validators import InputRequired, Length, ValidationError, Regexp
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from flask_socketio import SocketIO, emit
import uuid as uuid
import pytz
import os
import logging
import re

logging.basicConfig(level=logging.DEBUG, filename="app_LOG.log", filemode="a",
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

basedir = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(basedir, 'static/uploads')

db = SQLAlchemy()
app = Flask(__name__)
bcrypt = Bcrypt(app)
socketio = SocketIO(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///"+ os.path.join(basedir, "database.db")
app.config["SECRET_KEY"] = "Abecedar1234"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['TIMEZONE'] = 'Europe/Bucharest'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Strict'


db.init_app(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Database Models Admin, User, Register, Login
class Admin(db.Model):
    admin_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('admin', uselist=False))

    def __init__(self, user=None, *args, **kwargs):
        super(Admin, self).__init__(*args, **kwargs)
        if user:
            self.user = user
            self.username = user.username

    def __repr__(self):
        return f"<Admin id:{self.admin_id}, user_id: {self.user_id}, user_username:{self.username}>"


class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime(), default=datetime.now())

    def __init__(self, username, password):
        self.username = username.lower()
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def __repr__(self):
        return f"<User id:{self.user_id}, username: {self.username}, member since: {self.created_at}"

    def is_active(self):
        return True

    def get_id(self):
        return str(self.user_id)

    def is_authenticated(self):
        return True
    

class Post(db.Model):
    post_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    comment = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('posts', lazy='joined'))
    image_ref = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<Post id:{self.post_id}, title: {self.title}, user: {self.user_id}, created_at: {self.created_at}"
    

class Comment(db.Model):
    comment_id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.post_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('comments', lazy=True))
    image_ref = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<Comment id:{self.comment_id}, post_id: {self.post_id}, user: {self.user_id}, created_at: {self.created_at}"


class Message(db.Model):
    message_id = db.Column(db.Integer, primary_key=True)
    sender_username = db.Column(db.String(20), nullable=False)
    recipient_username = db.Column(db.String(20), nullable=False)
    message_text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def __init__(self, sender_username, recipient_username, message_text):
        self.sender_username = sender_username
        self.recipient_username = recipient_username
        self.message_text = message_text


# Classes for FlaskForm
class AddAdmin(FlaskForm):
    admin_user = TextAreaField(render_kw={"placeholder": "Enter username"})
    submit = SubmitField("Add")

class AddCommentForm(FlaskForm):
    comment = TextAreaField(render_kw={"placeholder": "Add your comment"})
    image = FileField('Upload Photo', render_kw={"class": "upload-image-comment"})
    submit = SubmitField("Comment")
    post_id = IntegerField('Post ID')


class CreatePostForm(FlaskForm):
    title = StringField(validators=[InputRequired(), Length(max=100)], render_kw={"placeholder": "Title"})
    comment = TextAreaField(render_kw={"placeholder": "Comment"})
    image = FileField('Upload Photo', render_kw={"class": "upload-image-post"})
    submit = SubmitField("POST")


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")



    def validate_username(self, username):
        logger = logging.getLogger('validate_username_func')
        existing_user_username = User.query.filter_by(username=username.data).first()

        if existing_user_username:
            logger.warning("Username already exist!")
            raise ValidationError("Username already exists. Please choose a different username.")

        return True
    
    def validate_password(self, password):
        logger = logging.getLogger('validate_username_password')
        
        if not re.search(r'[A-Z]', password.data):
            logger.info("Password entered without any uppercase letter.")
            raise ValidationError("Pasword must contain at least one uppercase letter.")
        
        if not re.search(r'\d', password.data):
            logger.info("Password entered without any digit.")
            raise ValidationError("Password must contain at least one digit.")
        
        if len(password.data) < 8:
            logging.info("Password lenght < 8 characters.")
            raise ValidationError("Password must be at least 8 characters long.")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")




# Define Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return redirect('dashboard')

@app.route('/dashboard')
def dashboard():
    latest_posts = Post.query.order_by(Post.created_at.desc()).limit(5).all()

    for post in latest_posts:
        utc_created_at = post.created_at.replace(tzinfo=pytz.utc)
        local_created_at = utc_created_at.astimezone(pytz.timezone('Europe/Bucharest'))
        post.created_at = local_created_at

    return render_template('dashboard.html', latest_posts=latest_posts)


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    add_admin_form = AddAdmin()

    if add_admin_form.validate_on_submit():
        username = add_admin_form.admin_user.data
        user = User.query.filter_by(username=username).first()

        if user:
            new_admin = Admin(user=user)
            db.session.add(new_admin)
            db.session.commit()
            flash(f"{user.username.title()} has been added as an Admin")
            return jsonify({'username': user.username})
        else:
            flash(f"User with username '{username}' not found.")
            print(f"User with username '{username}' not found.")

    if current_user.admin or current_user.username.lower() == "roshu":
        return render_template('admin.html', add_admin_form=add_admin_form)
    else:
        return "Unauthorized", 401

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    logger = logging.getLogger('Home Path')

    create_post_form = CreatePostForm()

    add_comment_form = AddCommentForm()

    recent_posts = Post.query.order_by(Post.created_at.desc()).all()
    for post in recent_posts:
        post.comments = Comment.query.filter_by(post_id=post.post_id).order_by(Comment.created_at.desc()).all()
        post.is_owner = post.user_id == current_user.user_id

    # Convert Post timestamps
    for post in recent_posts:
        utc_created_at = post.created_at.replace(tzinfo=pytz.utc)
        local_created_at = utc_created_at.astimezone(pytz.timezone('Europe/Bucharest'))
        post.created_at = local_created_at

    # Convert Comment timestamps
    for comment in Comment.query.all():
        utc_comment_created_at = comment.created_at.replace(tzinfo=pytz.utc)
        local_comment_created_at = utc_comment_created_at.astimezone(pytz.timezone('Europe/Bucharest'))
        comment.created_at = local_comment_created_at


    return render_template('home.html', create_post_form=create_post_form, posts=recent_posts, add_comment_form=add_comment_form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    logger = logging.getLogger('register_route')
    form = RegisterForm()

    if form.validate_on_submit():
        form.validate_password(form.password)

        new_user = User(username=form.username.data, password=form.password.data)

        logger.info(f"u.{new_user.username}, p.{form.password.data}")

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        logger = logging.getLogger('login_route')
        logger.info("Form validation")

        username = form.username.data.lower()
        user = User.query.filter_by(username=username).first()

        if user:
            logger.info("User found.")

            if bcrypt.check_password_hash(user.password, form.password.data):
                logger.info("Password matched. Logging in...")
                login_user(user)

                return redirect(url_for('home'))
            else:
                logger.warning("Password incorrect.")
                form.password.errors.append("Incorrect password. Please try again.")
        else:
            logger.warning("User not found")
            form.username.errors.append("User does not exist.")

    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('dashboard'))


@app.route('/reset-database/<target>', methods=['POST'])
def reset_database(target):
    logger = logging.getLogger('resetdb_route')

    if target == 'users':
        db.session.query(User).delete()
    elif target == 'posts':
        db.session.query(Post).delete()
    db.session.commit()

    logger.info('Database was deleted..')

    return redirect(url_for('admin'))

@app.route('/create_post', methods=['POST'])
@login_required
def create_post():
    create_post_form = CreatePostForm()

    if create_post_form.validate_on_submit():
        title = create_post_form.title.data
        comment = create_post_form.comment.data
        image = request.files['image']

        if title:
            if image:
                # Generate a secure filename for the uploaded file
                filename = secure_filename(image.filename)
                # Create a unique filename with UUID and save the uploaded file
                unique_filename = str(uuid.uuid4()) + '_' + filename
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                new_post = Post(title=title, comment=comment, user_id=current_user.user_id, image_ref=unique_filename)
            else:
                new_post = Post(title=title, comment=comment, user_id=current_user.user_id)

            db.session.add(new_post)
            db.session.commit()

            create_post_form.title.data = ""
            create_post_form.comment.data = ""
            create_post_form.image.data = None

    return redirect(url_for('home'))

@app.route('/add_comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    add_comment_form = AddCommentForm()

    if add_comment_form.validate_on_submit():
        comment_text = add_comment_form.comment.data
        image = request.files['image']

        if comment_text:
            if image:
                filename = secure_filename(image.filename)
                # Create a unique filename with UUID and save the uploaded file
                unique_filename = str(uuid.uuid4()) + '_' + filename
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                new_comment = Comment(text=comment_text, post_id=post_id, user_id=current_user.user_id, image_ref=unique_filename)
            else:
                new_comment = Comment(text=comment_text, post_id=post_id, user_id=current_user.user_id)
            db.session.add(new_comment)
            db.session.commit()

            add_comment_form.comment.data = ""
            add_comment_form.image.data = None

    return redirect(url_for('home'))


@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.user_id == current_user.user_id:
        db.session.delete(comment)
        db.session.commit()

    return redirect(url_for('home'))


@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id == current_user.user_id or current_user.admin or current_user.username.lower() == "roshu":
        Post.query.filter_by(post_id=post_id).delete()
        db.session.delete(post)
        db.session.commit()

    return redirect(url_for('home'))


@app.route('/delete_admin', methods=['POST'])
@login_required
def delete_admin():
    if current_user.username.lower() != 'roshu':
        return "Unauthorized", 401

    username = request.form.get('admin_user')
    admin_name = Admin.query.join(User).filter(User.username == username).first()

    if admin:
        db.session.delete(admin_name)
        db.session.commit()
        flash(f"'{username.title()}' has been removed from Admins")
    return redirect(url_for('admin'))


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['POST', 'GET'])
def contact():
    if request.method == 'POST':
        message_text = request.form.get('message')
        sender_username = current_user.username if current_user.is_authenticated else 'Anonymous'

        # Check if the recipient user 'roshu' exists
        recipient_user = User.query.filter_by(username='roshu').first()

        if recipient_user:
            # Create a new message and save it to the database
            new_message = Message(sender_username=sender_username, recipient_username='roshu', message_text=message_text)
            db.session.add(new_message)
            db.session.commit()
            flash("Your message has been sent to roshu.")
        else:
            flash("The owner couldn't receive messages at the moment.")
    return render_template('contact.html')


@app.route('/messages')
@login_required
def messages():
    if current_user.username.lower() != 'roshu':
        return "Unauthorized", 401

    for message in Message.query.all():
        utc_message_created_at = message.timestamp.replace(tzinfo=pytz.utc)
        local_message_created_at = utc_message_created_at.astimezone(pytz.timezone('Europe/Bucharest'))
        message.timestamp = local_message_created_at

    # Retrieve messages sent to 'roshu'
    messages_to_roshu = Message.query.filter_by(recipient_username='roshu').order_by(Message.timestamp.desc()).all()

    return render_template('messages.html', messages=messages_to_roshu)

with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)


