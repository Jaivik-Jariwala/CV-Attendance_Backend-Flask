
# imorting necessary modules
from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, BooleanField
from wtforms.validators import DataRequired, EqualTo, Length

app = Flask(__name__)
app.config["SECRET_KEY"] = "#1*6j!a&a3i8$d##p!!"  # replaced with our Best secret key
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "sqlite:///your_database.db"  # used SQlite for database
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

#  Creating user model for asic authentication 
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(
        db.String(20), nullable=False, default="user"
    )  # Default role is 'user'

# Creating registration modules 

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('user', 'User'), ('developer', 'Developer'), ('teacher', 'Teacher')])
    submit = SubmitField('Register')

# Creating Login modules 

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

# Creating routes for login and registration
# Here we will only accept login to system of Professors and We developers

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # checking for role as developer or teacher
        if form.role.data in ('developer', 'teacher'):
            user = User(username=form.username.data, password=form.password.data, role=form.role.data)
            db.session.add(user)
            db.session.commit() # MYSQLALCHEMY DOCS FOR MORE INFO, you can goto quickinfo for more info
            flash('Sucessfully registered', 'PERFECT!')
            return redirect(url_for('login'))
        else:
            flash('OOPS! sorry you are not authorized for this role.', 'sorry')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.password == form.password.data:
            login_user(user, remember=form.remember.data)
            flash('Sucessfully Logged in!', 'Welcome')
            return redirect(url_for('home'))
        else:
            flash('Login Failed, Do check your credentials!!', 'Sorry')
    return render_template('login.html', form=form)


# Now implementing user session and logouts

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'Thankx for visiting!')
    return redirect(url_for('login'))

#  Protecting routes based on roles

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role in ('developer', 'teacher'):
        return 'This dashboard is specifically for users and developers !!'
    else:
        return 'You are not authorized to access this page.'

if __name__ == "__main__":
    app.run(debug=True) # For developer to view error, we will change this as False after deployment