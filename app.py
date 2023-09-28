from flask import Flask

# Create a Flask application
app = Flask(__name__)

# Define a route and a view function
@app.route('/')
def hello_world():
    return 'Hello, World!'

if __name__ == '__main__':
    app.run(debug=True)
