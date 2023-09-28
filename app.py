
# imorting necessary modules
from flask import Flask, render_template, redirect, url_for, flash,request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, BooleanField
from wtforms.validators import DataRequired, EqualTo, Length

app = Flask(__name__)
app.config["SECRET_KEY"] = "#1*6j!a&a3i8$d##p!!"  # replaced with our Best secret key
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "sqlite:///dblogs.db"  # used SQlite for database and our db name is dbLogs, Use three slashes for SQLite
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

# Create the database tables
with app.app_context():
    db.create_all()

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
            flash('Sucessfully registered', 'sucess')
            return redirect(url_for('login'))
        else:
            flash('OOPS! sorry you are not authorized for this role.', 'danger')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.password == form.password.data:
            login_user(user, remember=form.remember.data)
            flash('Sucessfully loged in!', 'success')
            
            # Redirecting to the dashboard page after successful login
            return redirect(url_for('dashboard')) 
        else:
            flash('Please check your credentials.', 'danger')
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
        return render_template('dashboard.html')  # Render the dashboard template
    else:
        return 'You are not authorized to access this page.'

# capturing image routing
@app.route('/dashboard/capture_image', methods=['POST'])
@login_required
def capture_image():
    if current_user.role in ('developer', 'teacher'):
     # put your code of capturing image here
        return 'Image captured successfully!'  # Return a success message
    else:
        return 'You are not authorized to capture an image.'

# Mapping face using AI ML
@app.route('/dashboard/map_face', methods=['POST'])
@login_required
def map_face():
    if current_user.role in ('developer', 'teacher'):
        # put AI Ml code here
        return 'Face mapped successfully!'  # Return a success message
    else:
        return 'You are not authorized to map a face.'

# Student data routing
@app.route('/dashboard/student_data', methods=['GET'])
@login_required
def student_data():
    if current_user.role in ('developer', 'teacher'):
        # drop your AI Ml code for fetching data form data set
        students = [
            {'id': 1, 'name': 'Student 1', 'roll_number': '001'},
            {'id': 2, 'name': 'Student 2', 'roll_number': '002'},
            # Add more student data dictionaries as needed
        ]
        # Render the student_data.html template with the student data
        return render_template('student_data.html', students=students)
    else:
        return 'You are not authorized to access student data.'

# Routing to capture image and determine present/absent status
@app.route('/dashboard/present_absent_data', methods=['GET', 'POST'])
@login_required
def present_absent_data():
    if current_user.role in ('developer', 'teacher'):
        if request.method == 'POST':
            # Here, dropt  your code to capture an image and send it to your AI-ML model
            # and the model will determine the present/absent status and return the result
            # I took for example result=Present
            result = 'Present'

            # It will render data to present_Absent table
            return render_template('present_absent_data.html', result=result)
        else:
            # you can display the formto capture image
            return render_template('capture_image.html')
    else:
        return 'You are not authorized to access present/absent data.'

if __name__ == "__main__":
    app.run(debug=True) # For developer to view error, we will change this as False after deployment