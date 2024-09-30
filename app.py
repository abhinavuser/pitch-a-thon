from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import Length, EqualTo, DataRequired
from flask_wtf import FlaskForm
from sqlalchemy.sql import func

# Initialize the app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///restaurant.db'  # Your SQLite database
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Secret key for session management and CSRF protection

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login_page'

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    fullname = db.Column(db.String(30), nullable=False)
    address = db.Column(db.String(50), nullable=False)
    phone_number = db.Column(db.Integer, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)

    def check_password_correction(self, attempted_password):
        return bcrypt.check_password_hash(self.password_hash, attempted_password)

    @property
    def password(self):
        raise AttributeError('password: write-only field')

    @password.setter
    def password(self, plain_text_password):
        self.password_hash = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

# Item model
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), nullable=False)
    description = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    source = db.Column(db.String(30), nullable=False)

    def __repr__(self):
        return f'Item({self.name}, {self.price})'

# Flask Forms
class RegisterForm(FlaskForm):
    username = StringField(label='Username', validators=[Length(min=2, max=30), DataRequired()])
    fullname = StringField(label='Fullname', validators=[Length(min=3, max=30), DataRequired()])
    address = StringField(label='Address', validators=[Length(min=7, max=50), DataRequired()])
    phone_number = IntegerField(label='Phone Number', validators=[DataRequired()])
    password1 = PasswordField(label='Password', validators=[Length(min=6), DataRequired()])
    password2 = PasswordField(label='Confirm Password', validators=[EqualTo('password1'), DataRequired()])
    submit = SubmitField(label='Sign Up')

class LoginForm(FlaskForm):
    username = StringField(label='Username', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label='Sign In')

class AddForm(FlaskForm):
    submit = SubmitField(label='Add')

# User loader for flask-login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@app.route('/home')
def home_page():
    return render_template('index.html')

@app.route('/menu', methods=['GET', 'POST'])
@login_required
def menu_page():
    add_form = AddForm()
    
    if request.method == 'POST':
        # Handling new item form submission
        item_name = request.form.get('item_name')
        item_description = request.form.get('item_description')
        item_price = request.form.get('item_price')
        item_image = request.files['item_image']

        if item_name and item_description and item_price and item_image:
            image_filename = item_image.filename
            item_image.save(f"static/styles/img/{image_filename}")

            new_item = Item(
                name=item_name,
                description=item_description,
                price=int(item_price),
                source=image_filename
            )
            db.session.add(new_item)
            db.session.commit()
            flash(f'{item_name} has been added successfully!', category='success')
            return redirect(url_for('menu_page'))

    # Display existing items
    items = Item.query.all()
    return render_template('menu.html', items=items, add_form=add_form)


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    forml = LoginForm()  # Login form
    form = RegisterForm()  # Registration form
    if forml.validate_on_submit():
        attempted_user = User.query.filter_by(username=forml.username.data).first()
        if attempted_user and attempted_user.check_password_correction(attempted_password=forml.password.data):
            login_user(attempted_user)
            return redirect(url_for('home_page'))
        else:
            flash('Username or password is incorrect! Please try again.', category='danger')
    return render_template('login.html', forml=forml, form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out!', category='info')
    return redirect(url_for('home_page'))

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        user_to_create = User(username=form.username.data,
                              fullname=form.fullname.data,
                              address=form.address.data,
                              phone_number=form.phone_number.data,
                              password=form.password1.data)
        db.session.add(user_to_create)
        db.session.commit()
        login_user(user_to_create)
        return redirect(url_for('home_page'))

    if form.errors != {}:  # if there are errors from the validators
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a user: {err_msg}', category='danger')
    return render_template('login.html', form=form)

# Initialize database if not already created
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
