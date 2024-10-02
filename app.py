from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectField
from wtforms.validators import Length, EqualTo, DataRequired
from flask_wtf import FlaskForm
from sqlalchemy.sql import func
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy



import json

db = SQLAlchemy()
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
    storename = db.Column(db.String(30), nullable=False, unique=True)
    store_type = db.Column(db.String(50), nullable=False)  # New field for store type
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


# Flask Forms
from wtforms import SelectField

class RegisterForm(FlaskForm):
    storename = StringField(label='Username', validators=[Length(min=2, max=30), DataRequired()])
    store_type = SelectField(label='Store Type', 
                             choices=[('Restaurant', 'Restaurant'), 
                                      ('Cafe', 'Cafe'), 
                                      ('Buffet restaurant', 'Buffet restaurant'),
                                      ('Hotel', 'Hotel'),
                                      ('Bakery', 'Bakery'),
                                      ('Supermarket', 'Supermarket'),
                                      ('Fruit & vegetable store', 'Fruit & vegetable store'),
                                      ('Sweets and Savouries', 'Sweets and Savouries')],
                             validators=[DataRequired()])
    address = StringField(label='Address', validators=[Length(min=7, max=50), DataRequired()])
    phone_number = IntegerField(label='Phone Number', validators=[DataRequired()])
    password1 = PasswordField(label='Password', validators=[Length(min=6), DataRequired()])
    password2 = PasswordField(label='Confirm Password', validators=[EqualTo('password1'), DataRequired()])
    submit = SubmitField(label='Sign Up')


class LoginForm(FlaskForm):
    storename = StringField(label='Username', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label='Sign In')

class SurpriseBox(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    store_name = db.Column(db.String(80), nullable=False)
    store_type = db.Column(db.String(80), nullable=False)
    store_location = db.Column(db.String(120), nullable=False)
    items = db.Column(db.JSON, nullable=False)  # This should store the items as JSON
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<SurpriseBox {self.store_name}, Items: {self.items}>'




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
    return render_template('menu.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    forml = LoginForm()  # Login form
    form = RegisterForm()  # Registration form
    if forml.validate_on_submit():
        attempted_user = User.query.filter_by(storename=forml.storename.data).first()
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

@app.route('/profile')
@login_required
def profile_page():
    return render_template('profile.html')

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # For demo purposes, we'll log the data to the console. You can save this data to your database.
    print(f"Checkout data: {data}")

    # Save the order information into the database
    new_order = SurpriseBox(
        user_id=current_user.id,
        store_name=current_user.storename,
        store_type=current_user.store_type,
        store_location=current_user.address,
        items=json.dumps(data['items'])  # JSON format for items
    )
    db.session.add(new_order)
    db.session.commit()

    return jsonify({'message': 'Order placed successfully!'}), 201




@app.route('/api/surprise_boxes/current_store', methods=['GET'])
@login_required
def get_surprise_boxes_for_current_store():
    boxes = SurpriseBox.query.filter_by(user_id=current_user.id).all()
    box_list = [
        {
            "store_name": box.store_name,
            "store_type": box.store_type,
            "store_location": box.store_location,
            "items": json.loads(box.items),  # Convert JSON back to a list
            "total_price": sum(item['price'] for item in json.loads(box.items))  # Calculate total price
        }
        for box in boxes
    ]
    return jsonify(box_list)




@app.route('/register', methods=['GET', 'POST'])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        user_to_create = User(
            storename=form.storename.data,
            store_type=form.store_type.data,  # Capturing the selected store type
            address=form.address.data,
            phone_number=form.phone_number.data,
            password=form.password1.data
        )
        db.session.add(user_to_create)
        db.session.commit()
        login_user(user_to_create)
        return redirect(url_for('profile_page'))

    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a user: {err_msg}', category='danger')
    return render_template('login.html', form=form)


# Initialize database if not already created
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
