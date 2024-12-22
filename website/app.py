from flask import Flask, render_template, jsonify, redirect, url_for, request, flash, session
import sqlite3
import os
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from findmatch import find_matches_logic
from post import create_post_logic, get_posts_logic, get_categories
from werkzeug.security import generate_password_hash, check_password_hash
from time import sleep
from data import send_message, get_messages, add_message, get_user_conversations  # Import the new functions
from flask_socketio import SocketIO, emit, join_room

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
socketio = SocketIO(app)  # Initialize SocketIO

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Path
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")

# Database helper function
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# User class
class User(UserMixin):
    def __init__(self, id, first_name, email, password, is_admin):
        self.id = id
        self.first_name = first_name
        self.email = email
        self.password = password
        self.is_admin = bool(is_admin)  # Ensure is_admin is treated as a boolean

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user_data:
        return User(user_data['id'], user_data['first_name'], user_data['email'], user_data['password'], user_data['is_admin'])
    return None

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not email or not password:
            flash('Please fill out both email and password.', 'danger')
            return redirect(url_for('login'))

        # Validate user credentials
        conn = get_db_connection()
        user_data = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data['id'], user_data['first_name'], user_data['email'], user_data['password'], user_data['is_admin'])
            login_user(user)
            session['user_id'] = user.id  # Set user_id in session
            session['is_admin'] = user.is_admin  # Store is_admin in session
            flash('Login successful!', 'success')

            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('profile'))
        else:
            flash('Login unsuccessful. Please check your email and password.', 'danger')

    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        # Logic for handling the password recovery (e.g., sending an email, etc.)
        pass
    return render_template('forgot_password.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        first_name = request.form['first_name']
        email = request.form['email']
        password = request.form['password']

        try:
            conn = get_db_connection()
            existing_user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

            if existing_user:
                flash('Email already exists!', 'danger')
                return redirect(url_for('signup'))

            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            conn.execute('INSERT INTO users (first_name, email, password) VALUES (?, ?, ?)',
                         (first_name, email, hashed_password))
            conn.commit()
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))

        except sqlite3.Error as e:
            flash(f"Database error: {str(e)}. Please try again later.", 'danger')
            return redirect(url_for('signup'))

        finally:
            conn.close()

    return render_template('signup.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Try to connect to the database with retries in case it's locked
    conn = None
    for _ in range(3):  # Retry 3 times
        try:
            conn = get_db_connection()
            break  # Break the loop if successful
        except sqlite3.OperationalError:
            sleep(1)  # Wait for 1 second before retrying
    if conn is None:
        flash("Could not connect to the database. Please try again later.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Fetch form data
        name = request.form.get('name')
        student_id = request.form.get('student_id')
        phone_number = request.form.get('phone_number')

        # Update user details in the database
        try:
            conn.execute(
                "UPDATE users SET first_name = ?, student_id = ?, phone_number = ? WHERE id = ?",
                (name, student_id, phone_number, user_id)
            )
            conn.commit()
            flash("Profile updated successfully!")
        except sqlite3.OperationalError as e:
            flash(f"Database error: {str(e)}. Please try again later.")
            conn.rollback()  # Rollback in case of error

    # Fetch the updated user data to display
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    return render_template('profile.html', user=user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user_id', None)  # Clear user_id from session
    session.pop('is_admin', None)  # Clear is_admin from session
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/post')
def post():
    return render_template('post.html')

@app.route('/createPost', methods=['GET', 'POST'])
def create_post():
    if request.method == 'POST':
        req_data = request.json
        response, status_code = create_post_logic(req_data)
        return jsonify(response), status_code

    return render_template('create_post.html')

@app.route('/getPosts', methods=['GET'])
def get_posts():
    response = get_posts_logic()
    return jsonify(response), 200

@app.route('/categories', methods=['GET'])
def categories():
    return get_categories()

@app.route('/findmatch')
def findmatch_page():
    return render_template('findmatch.html')

@app.route('/findMatches', methods=['POST'])
def find_matches():
    req_data = request.json
    results = find_matches_logic(req_data)
    return jsonify(results)

# New route for listing conversations
@app.route('/messages', methods=['GET'])
@login_required
def messages_list():
    user_id = session['user_id']
    conversations = get_user_conversations(user_id)  # Fetch all conversations
    return render_template('messages_list.html', conversations=conversations)

# Messaging Interface
@app.route('/messages/<int:recipient_id>', methods=['GET', 'POST'])
@login_required
def messages(recipient_id):
    user_id = session['user_id']

    if request.method == 'POST':
        # Handle sending a new message
        content = request.form.get('content')
        add_message(user_id, recipient_id, content)
        return redirect(url_for('messages', recipient_id=recipient_id))

    # Fetch user conversations
    conversations = get_user_conversations(user_id)
    return render_template('messages.html', conversations=conversations, recipient_id=recipient_id)

# SocketIO event handlers
@socketio.on('send_message')
def handle_send_message(data):
    """Handle incoming messages and broadcast them to the room."""
    room = data['room']
    message = data['message']
    emit('receive_message', {'message': message, 'user': current_user.first_name}, room=room)

@socketio.on('join')
def on_join(data):
    """Handle user joining a chat room."""
    room = data['room']
    join_room(room)
    emit('receive_message', {'message': f'{current_user.first_name} has entered the room.'}, room=room)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message_route():
    data = request.json
    sender_id = session['user_id']
    receiver_id = data['receiver_id']
    message = data['message']
    
    # Create a unique room name based on user IDs
    room = f'room_{sender_id}_{receiver_id}'
    
    # Send the message using SocketIO
    socketio.emit('send_message', {'room': room, 'message': message})
    
    send_message(sender_id, receiver_id, message)  # Save the message to the database
    return jsonify({'status': 'Message sent successfully'}), 200

@app.route('/get_messages', methods=['GET'])
@login_required
def get_messages_route():
    user_id = session['user_id']
    messages = get_messages(user_id)
    return jsonify([dict(message) for message in messages]), 200

# Admin Dashboard
@app.route('/admin', methods=['GET'])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied: Admins only!', 'danger')
        return redirect(url_for('profile'))  # Redirect non-admins to their profile

    return render_template('admin_dashboard.html')  # Simplified, no data needed here

@app.route('/admin/manage_users', methods=['GET'])
@login_required
def manage_users():
    if not current_user.is_admin:
        flash('Access denied: Admins only!', 'danger')
        return redirect(url_for('profile'))

    conn = get_db_connection()
    users = conn.execute('SELECT id, first_name, email, is_admin FROM users').fetchall()
    conn.close()
    return render_template('manage_users.html', users=users)

@app.route('/admin/manage_items', methods=['GET'])
@login_required
def manage_items():
    if not current_user.is_admin:
        flash('Access denied: Admins only!', 'danger')
        return redirect(url_for('profile'))

    conn = get_db_connection()
    items = conn.execute('SELECT * FROM items').fetchall()  # Adjust this query based on your items table
    conn.close()
    return render_template('manage_items.html', items=items)

@app.route('/admin/manage_content', methods=['GET'])
@login_required
def manage_content():
    if not current_user.is_admin:
        flash('Access denied: Admins only!', 'danger')
        return redirect(url_for('profile'))

    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts').fetchall()
    conn.close()
    return render_template('manage_content.html', posts=posts)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('home'))

    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('User deleted successfully!', 'success')
    return redirect(url_for('manage_users'))  # Redirect to manage users page

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('home'))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if request.method == 'POST':
        first_name = request.form['first_name']
        email = request.form['email']
        is_admin = request.form.get('is_admin', '0')

        conn.execute('UPDATE users SET first_name = ?, email = ?, is_admin = ? WHERE id = ?',
                     (first_name, email, int(is_admin), user_id))
        conn.commit()
        conn.close()

        flash('User updated successfully!', 'success')
        return redirect(url_for('manage_users'))  # Redirect to manage users page

    conn.close()
    return render_template('edit_user.html', user=user)

# Updated delete_post route to accept a string for post_id
@app.route('/admin/delete_post/<post_id>', methods=['POST'])  # Changed <int:post_id> to <post_id>
@login_required
def delete_post(post_id):
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('home'))

    conn = get_db_connection()
    conn.execute('DELETE FROM posts WHERE id = ?', (post_id,))  # No change needed here if post_id is a string
    conn.commit()
    conn.close()

    flash('Post deleted successfully!', 'success')
    return redirect(url_for('manage_content'))  # Redirect to manage content page

if __name__ == '__main__':
    app.run(debug=True)  # Keep this line for standard Flask run