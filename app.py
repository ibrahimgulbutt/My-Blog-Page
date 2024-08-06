from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, URL
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from faker import Faker
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date

# Initialize Flask app and configure settings
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
Bootstrap5(app)
db = SQLAlchemy(app)
ckeditor = CKEditor(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Define User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    
    author = db.relationship('User', backref=db.backref('posts', lazy=True))
    comments = db.relationship('Comment', backref='blog_post', lazy=True)  # 'blog_post' as backref name

    def __repr__(self):
        return f'<BlogPost {self.title}>'




class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'), nullable=False)

    author = db.relationship('User', backref=db.backref('comments', lazy=True))
    post = db.relationship('BlogPost', backref=db.backref('post_comments', lazy=True))  # 'post_comments' as backref name

    def __repr__(self):
        return f'<Comment {self.text[:20]}>'




# Define BlogPost form
class BlogPostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    subtitle = StringField('Subtitle', validators=[DataRequired()])
    date = StringField('Date', validators=[DataRequired()])
    body = CKEditorField('Body', validators=[DataRequired()])
    img_url = StringField('Image URL', validators=[DataRequired(), URL()])
    submit = SubmitField('Submit')

# Define Comment form
class CommentForm(FlaskForm):
    text = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Add Comment')

# Define Register form
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=20)])
    submit = SubmitField('Register')

# Define Login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=20)])
    submit = SubmitField('Login')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define routes
@app.route('/')
def home():
    posts = BlogPost.query.all()
    return render_template('index.html', posts=posts, button_text='View Posts', page_info='Home Page')

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        new_comment = Comment(
            text=form.text.data,
            date=date.today().strftime("%B %d, %Y"),
            author=current_user,
            post=post
        )
        db.session.add(new_comment)
        db.session.commit()
        flash('Comment added successfully!', 'success')
        return redirect(url_for('post', post_id=post.id))
    return render_template('post.html', post=post, form=form, button_text='Read Full Blog', page_info='Blog Page')

@app.route('/add_post', methods=['GET', 'POST'])
@login_required
def add_post():
    form = BlogPostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            date=form.date.data,
            body=form.body.data,
            author_id=current_user.id,
            img_url=form.img_url.data
        )
        db.session.add(new_post)
        db.session.commit()
        flash('Blog post created successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('make_post.html', form=form, button_text='Create New Post', page_info='Make a new post Page')

@app.route('/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    if post.author != current_user:
        flash('You are not authorized to edit this post.', 'danger')
        return redirect(url_for('home'))
    form = BlogPostForm(obj=post)
    if form.validate_on_submit():
        post.title = form.title.data
        post.subtitle = form.subtitle.data
        post.img_url = form.img_url.data
        post.date = form.date.data
        post.body = form.body.data
        db.session.commit()
        flash('Blog post updated successfully!', 'success')
        return redirect(url_for('post', post_id=post.id))
    return render_template('edit.html', form=form, post=post, button_text='Update Post', page_info='Edit a blog Page')


@app.route('/my_blogs')
@login_required
def my_blogs():
    posts = BlogPost.query.filter_by(author=current_user).all()
    return render_template('my_blog.html', posts=posts,button_text='Blog Posts', page_info='All Blog Posts By You')

@app.route('/my_comments')
@login_required
def my_comments():
    comments = Comment.query.filter_by(author=current_user).all()  # Use 'author' instead of 'user'
    return render_template('my_comments.html', comments=comments,button_text='All Comments Posts', page_info='All Comments By You')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Check if username already exists
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form,button_text='Registration', page_info='Registration Page')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        flash('Login failed. Check your username and/or password.', 'danger')
    return render_template('login.html', form=form,button_text='Login', page_info='Login Page')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/about')
def about():
    return render_template('about.html', button_text='Learn More', page_info='About Page')

def create_db():
    with app.app_context():
        #db.drop_all()  # Remove the old tables if they exist
        #db.create_all()  # Create new tables
        print("Database tables created.")

def generate_sample_data():
    with app.app_context():
        fake = Faker()
        # Ensure at least one user exists to associate posts with
        if User.query.count() == 0:
            user = User(username=fake.user_name(), password_hash=generate_password_hash('password', method='pbkdf2:sha256'))
            db.session.add(user)
            db.session.commit()
        author = User.query.first()
        for _ in range(10):
            post = BlogPost(
                title=fake.sentence(nb_words=6),
                subtitle=fake.sentence(nb_words=8),
                date=fake.date(),
                body=fake.paragraph(nb_sentences=5),
                author_id=author.id,
                img_url=fake.image_url()
            )
            db.session.add(post)
        db.session.commit()
        print("Sample data added.")

if __name__ == '__main__':
    app.run(debug=True)
