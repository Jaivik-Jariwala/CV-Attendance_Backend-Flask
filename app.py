# imorting necessary modules
from flask import Flask, jsonify, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, BooleanField
from wtforms.validators import DataRequired, EqualTo, Length
from PIL import Image, ImageDraw, ImageFont
import cv2
import numpy as np
import base64
import os
from datetime import datetime


app = Flask(__name__)
app.config["SECRET_KEY"] = "#1*6j!a&a3i8$d##p!!"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///dblogs.db"
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


# Creating user model for basic authentication
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")


# Create the database tables
with app.app_context():
    db.create_all()


@app.route("/")
def home():
    return "Welcome to the Home Page"


# Creating registration modules


class RegistrationForm(FlaskForm):
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=4, max=20)]
    )
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )
    role = SelectField(
        "Role",
        choices=[("user", "User"), ("developer", "Developer"), ("teacher", "Teacher")],
    )
    submit = SubmitField("Register")


# Creating Login modules


class LoginForm(FlaskForm):
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=4, max=20)]
    )
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")


# Creating routes for login and registration
# Here we will only accept login to system of Professors and We developers


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if the username is already taken
        user_exists = User.query.filter_by(username=form.username.data).first()
        if user_exists:
            flash("Username already taken.", "danger")
            return render_template("register.html", form=form)

        # Check if the role is valid
        valid_roles = ("user", "developer", "teacher")
        if form.role.data in valid_roles:
            user = User(
                username=form.username.data,
                password=form.password.data,
                role=form.role.data,
            )
            db.session.add(user)
            db.session.commit()
            flash("Successfully registered", "success")
            return redirect(url_for("login"))  # Redirect to the login page
        else:
            flash("Invalid role selected.", "danger")
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.password == form.password.data:
            if user.role in ("developer", "teacher"):
                login_user(user, remember=form.remember.data)
                flash("Sucessfully logged in!", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("You are not authorized to access the dashboard.", "danger")
        else:
            flash("Please check your credentials.", "danger")
    return render_template("login.html", form=form)


# Now implementing user session and logouts


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "Thankx for visiting!")
    return redirect(url_for("login"))


#  Protecting routes based on roles


@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role in ("developer", "teacher"):
        return render_template("dashboard.html")  # Render the dashboard template
    else:
        return "You are not authorized to access this page."


# Serve the capture_image.html page
@app.route('/dashboard/capture_image_page')
@login_required
def capture_image_page():
    return render_template('capture.html')

# New route for capturing and processing images
@app.route('/dashboard/capture_image', methods=['POST'])
@login_required
def capture_image():
    faces = []
    try:
        # Capture image from the request data
        data = request.get_json()
        photo_data = data.get('photoData')

        # Decode base64 image data and save it as a file with the current date and time
        current_date_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{current_date_time}.png"

        image_data = base64.b64decode(photo_data.split(',')[1])
        image = cv2.imdecode(np.frombuffer(image_data, np.uint8), cv2.IMREAD_COLOR)
        cv2.imwrite(filename, image)

        # Perform face detection on the captured photo
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.3, minNeighbors=5, minSize=(30, 30))

        if len(faces) == 0:
            return jsonify({"error": "No faces found in the image"})

        # Convert the captured image to base64 for displaying it on the page
        _, buffer = cv2.imencode('.jpg', image)
        captured_photo_base64 = base64.b64encode(buffer).decode('utf-8')

        return jsonify({"message": f"Image processed successfully: Number of detected faces: {len(faces)}",
                        "capturedPhoto": captured_photo_base64})
    
    except Exception as e:
        detected_faces_count = len(faces)
        print(f"Number of faces detected: {detected_faces_count}")
        print("Error: ", e)
        return jsonify({"error": f"Error processing the image. Detected {detected_faces_count} faces."})
    

# Mapping face using AI ML
@app.route("/dashboard/map_face", methods=["POST"])
@login_required
def map_face():
    if current_user.role in ("developer", "teacher"):
        # put AI Ml code here
        return "Face mapped successfully!"  # Return a success message
    else:
        return "You are not authorized to map a face."

# Student data routing
@app.route("/dashboard/student_data", methods=["GET"])
@login_required
def student_data():
    if current_user.role in ("developer", "teacher"):
        # drop your AI Ml code for fetching data form data set
        students = [
            {"id": 1, "name": "Student 1", "roll_number": "001"},
            {"id": 2, "name": "Student 2", "roll_number": "002"},
            # Add more student data dictionaries as needed
        ]
        # Render the student_data.html template with the student data
        return render_template("student_data.html", students=students)
    else:
        return "You are not authorized to access student data."


# Routing to capture image and determine present/absent status
@app.route("/dashboard/present_absent_data", methods=["GET", "POST"])
@login_required
def present_absent_data():
    if current_user.role in ("developer", "teacher"):
        if request.method == "POST":
            # Here, dropt  your code to capture an image and send it to your AI-ML model
            # and the model will determine the present/absent status and return the result
            # I took for example result=Present
            result = "Present"

            # It will render data to present_Absent table
            return render_template("present_absent_data.html", result=result)
        else:
            # you can display the formto capture image
            return render_template("capture_image.html")
    else:
        return "You are not authorized to access present/absent data."


if __name__ == "__main__":
    app.run(
        debug=True
    )  # For developer to view error, we will change this as False after deployment
