from flask import Flask, render_template, request

app = Flask(__name__)   

@app.route('/')
def hello():
    return "Hello, World!"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['username']
        return f"Hello {name}, POST request received"
    return render_template('name.html')

if __name__ == '__main__':
    app.run(debug=True)