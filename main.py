import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from core.memory.db import view_all_items, insert_item, search_items, delete_item, delete_all_items, update_item_details, get_item
from core.memory import extract
from threading import Thread
import time
from pyngrok import ngrok
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from core.assist import generate

template_dir = os.path.abspath('core/ui/chat')
target_path = os.path.abspath('C:/Users/ur file/core/databases/users.db')

app = Flask(__name__, template_folder=template_dir)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{target_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')

role_hierarchy = {
    'user': 1,
    'admin': 2
}

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session or 'role' not in session or role_hierarchy[session['role']] < role_hierarchy[role]:
                flash('You do not have access to this page.', 'danger')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('User registered successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Login successful!', 'success')
            return redirect(url_for('chat'))
        else:
            flash('Login failed. Check your credentials.', 'danger')
    return render_template('login.html')

@app.route('/')
@role_required('admin')
def index():
    items = view_all_items()
    return render_template('index.html', items=items)

@app.route('/insert', methods=['POST'])
@role_required('admin')
def insert():
    name = request.form['name']
    description = request.form['description']
    importance = int(request.form['importance'])
    keywords = request.form['keywords']
    ai_response = extract.extract_memories(name + ' ' + description + ' ' + keywords)
    if ai_response != "The generation failed.":
        pass
    
    insert_item(name, description, importance, keywords)
    return redirect(url_for('index'))

@app.route('/search', methods=['GET'])
@role_required('admin')
def search():
    keywords = request.args.get('keywords', '').split(',')
    results = search_items(keywords)
    return render_template('search_results.html', items=results)

@app.route('/delete/<int:item_id>', methods=['POST'])
@role_required('admin')
def delete(item_id):
    delete_item(item_id)
    return redirect(url_for('index'))

@app.route('/delete_all', methods=['POST'])
@role_required('admin')
def delete_all():
    delete_all_items()
    return redirect(url_for('index'))

@app.route('/item_details/<int:item_id>')
@role_required('admin')
def item_details(item_id):
    item = get_item(item_id)
    if item:
        return render_template('item_details.html', item=item)
    return redirect(url_for('index'))

@app.route('/update_item/<int:item_id>', methods=['POST'])
@role_required('admin')
def update_item(item_id):
    name = request.form['name']
    description = request.form['description']
    importance = int(request.form['importance'])
    keywords = request.form['keywords']
    update_item_details(item_id, name, description, importance, keywords)
    return redirect(url_for('item_details', item_id=item_id))

@app.route('/add_item')
@role_required('admin')
def add_item():
    return render_template('add_item.html')

@app.route('/ai_add_item', methods=['GET', 'POST'])
@role_required('admin')
def ai_add_item():
    if request.method == 'POST':
        text = request.form['text']
        extract.memory_set(text)
        return redirect(url_for('index'))
    return render_template('ai_add_item.html')

@app.route('/chat', methods=['GET', 'POST'])
@role_required('user')
def chat():
    if request.method == 'POST':
        message = request.form.get('message')
        if message:
            print("User message:", message)
            gen = generate(message, 'no memory')
            print('Nova: ' + gen)
            return jsonify({'gen': gen})
    return render_template('chat.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/user/<int:id>')
@role_required('admin')
def user_profile(id):
    user = User.query.get_or_404(id)
    return render_template('user_profile.html', user=user)

def run_ngrok():
    http_tunnel = ngrok.connect(5000)
    print(f"Public URL: {http_tunnel.public_url}")
    time.sleep(3 * 60 * 60)
    ngrok.disconnect(http_tunnel.public_url)
    ngrok.kill()
    run_ngrok()

def create_app():
    with app.app_context():
        db.create_all()
    
    flask_thread = Thread(target=app.run, kwargs={'host': '0.0.0.0', 'port': 5000, 'debug': False, 'threaded': True})
    flask_thread.start()
    
    ngrok_thread = Thread(target=run_ngrok)
    ngrok_thread.start()

# if __name__ == '__main__':
#     create_app()
