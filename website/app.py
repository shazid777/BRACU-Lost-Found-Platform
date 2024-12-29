from flask import Flask, render_template, jsonify, redirect, url_for, request, flash, session
from flask_socketio import SocketIO, emit, join_room
from cryptography.fernet import Fernet
import sqlite3
import os
import uuid
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from time import sleep
from data import send_message, get_messages, add_message, get_user_conversations, claim_item  # Import the new functions
from data import create_post, get_unclaimed_items, get_posts_logic, insert_found_post, fetch_found_posts
from data import insert_claim, get_claims_for_admin, get_claims_for_item_and_user  # Import the new function

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
socketio = SocketIO(app, async_mode='threading')  # Use threading mode for compatibility

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Encryption key for secure messaging
key = Fernet.generate_key()
cipher_suite = Fernet(key)

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

            return redirect(url_for('home'))

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

    conn = None
    for _ in range(3):  # Retry 3 times
        try:
            conn = get_db_connection()
            break
        except sqlite3.OperationalError:
            sleep(1)
    if conn is None:
        flash("Could not connect to the database. Please try again later.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form.get('name')
        student_id = request.form.get('student_id')
        phone_number = request.form.get('phone_number')

        try:
            conn.execute(
                "UPDATE users SET first_name = ?, student_id = ?, phone_number = ? WHERE id = ?",
                (name, student_id, phone_number, user_id)
            )
            conn.commit()
            flash("Profile updated successfully!")
        except sqlite3.OperationalError as e:
            flash(f"Database error: {str(e)}. Please try again later.")
            conn.rollback()

    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    return render_template('profile.html', user=user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user_id', None)
    session.pop('is_admin', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/post', methods=['GET', 'POST'])
@login_required
def post():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        last_seen_location = request.form['last_seen_location']
        date = request.form['date']
        photos = request.form.get('photos', '')

        post_id = uuid.uuid4().hex

        create_post(post_id, title, description, category, last_seen_location, date, photos, post_type='lost')

        flash('Lost item posted successfully!', 'success')
        return redirect(url_for('unclaimed_items_list'))

    return render_template('post.html')

@app.route('/createPost', methods=['POST'])
def create_post_route():
    req_data = request.json
    if not req_data:
        return jsonify({"error": "No data provided"}), 400

    response, status_code = create_post_logic(req_data, post_type='lost')
    return jsonify(response), status_code

def create_post_logic(req_data, post_type):
    post_id = uuid.uuid4().hex
    title = req_data.get('title')
    description = req_data.get('description')
    category = req_data.get('category')
    last_seen_location = req_data.get('last_seen_location')
    date = req_data.get('date')
    photos = req_data.get('photos', '')

    if not all([title, description, category, last_seen_location, date]):
        return {"error": "All fields are required"}, 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM categories WHERE name = ?", (category,))
    if not cursor.fetchone():
        conn.close()
        return {"error": f"Category '{category}' does not exist"}, 400

    cursor.execute("""
    INSERT INTO posts (id, title, description, category, last_seen_location, date, photos, post_type)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (post_id, title, description, category, last_seen_location, date, photos, post_type))
    conn.commit()
    conn.close()

    return {
        "message": "Post created successfully",
        "id": post_id,
        "title": title,
        "description": description,
        "category": category,
        "last_seen_location": last_seen_location,
        "date": date,
        "photos": photos
    }, 201

@app.route('/getPosts', methods=['GET'])
def get_posts():
    response = get_posts_logic()
    return jsonify(response), 200

def get_posts_logic():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, title, description, category, last_seen_location, date, photos FROM posts")
    posts = [
        {
            "id": row[0],
            "title": row[1],
            "description": row[2],
            "category": row[3],
            "last_seen_location": row[4],
            "date": row[5],
            "photos": row[6]
        }
        for row in cursor.fetchall()
    ]
    conn.close()

    return {"posts": posts}

@app.route('/found_post', methods=['GET', 'POST'])
@login_required
def found_post():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        last_seen_location = request.form['last_seen_location']
        date = request.form['date']
        category = request.form['category']
        photo = request.form['photo']

        post_id = insert_found_post(title, description, last_seen_location, date, photo)

        if post_id:
            flash('Found item posted successfully!')
            return redirect(url_for('unclaimed_items_list'))
        else:
            flash('Failed to post found item.', 'danger')

    return render_template('found_post.html')

@app.route('/unclaimed_items', methods=['GET'])
@login_required
def unclaimed_items_list():
    item_id = request.args.get('item_id', type=int)
    conn = get_db_connection()

    if item_id:
        item = conn.execute('SELECT * FROM items WHERE id = ?', (item_id,)).fetchone()
        conn.close()
        if item:
            return render_template('items_list.html', item=item)
        else:
            flash('Item not found!', 'danger')
            return redirect(url_for('unclaimed_items_list'))
    else:
        items = conn.execute('SELECT * FROM items WHERE status = "unclaimed"').fetchall()
        conn.close()
        print("Unclaimed items fetched:", items)
        return render_template('items_list.html', items=items)

@app.route('/claim/<int:item_id>', methods=['GET', 'POST'])
@login_required
def claim_item_route(item_id):
    if request.method == 'POST':
        user_id = current_user.id
        data = request.get_json()
        question_1 = data.get('question_1')
        question_2 = data.get('question_2')
        question_3 = data.get('question_3')

        if not question_1 or not question_2 or not question_3:
            return jsonify({"error": "All questions must be answered."}), 400

        existing_claims = get_claims_for_item_and_user(item_id, user_id)
        if existing_claims:
            if existing_claims[0]['status'] == 'pending':
                return jsonify({"error": "You have already submitted a claim for this item. Status: pending."}), 400

        try:
            claim_id = insert_claim(item_id, user_id, question_1, question_2, question_3, '', 'pending')

            if claim_id:
                return jsonify({"message": "Claim request submitted. Wait for admin response.", "status": "pending"}), 200
            else:
                return jsonify({"error": "Failed to submit claim. Please try again."}), 500

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return render_template('claim_form.html', item_id=item_id)

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied: Admins only!', 'danger')
        return redirect(url_for('profile'))

    claims = get_claims_for_admin()
    print("Claims fetched for admin dashboard:", claims)
    return render_template('admin_dashboard.html', claims=claims)

@app.route('/admin/manage_claims', methods=['GET', 'POST'])
@login_required
def manage_claims():
    if not current_user.is_admin:
        flash('Access denied: Admins only!', 'danger')
        return redirect(url_for('profile'))

    conn = get_db_connection()
    if request.method == 'POST':
        claim_id = request.form['claim_id']
        action = request.form['action']
        rejection_reason = request.form.get('rejection_reason', '')

        if action == 'approve':
            conn.execute('UPDATE claims SET status = "Approved" WHERE id = ?', (claim_id,))
            conn.execute('UPDATE items SET status = "claimed" WHERE id = (SELECT item_id FROM claims WHERE id = ?)', (claim_id,))
            flash('Claim approved successfully!', 'success')
        elif action == 'reject':
            conn.execute('UPDATE claims SET status = "Rejected", rejection_reason = ? WHERE id = ?', (rejection_reason, claim_id))
            flash('Claim rejected successfully!', 'danger')

        conn.commit()
        conn.close()
        return redirect(url_for('admin_dashboard'))

    return redirect(url_for('admin_dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM found_items WHERE status = 'unclaimed'")
    items = cursor.fetchall()
    conn.close()
    return render_template('dashboard.html', items=items)

@app.route('/messages', methods=['GET'])
@login_required
def messages_list():
    user_id = session['user_id']
    conn = get_db_connection()

    users = conn.execute('SELECT id, first_name FROM users WHERE id != ?', (user_id,)).fetchall()
    conn.close()

    return render_template('messages_list.html', users=users)

@app.route('/messages/<int:recipient_id>', methods=['GET', 'POST'])
@login_required
def messages(recipient_id):
    user_id = session['user_id']
    conn = get_db_connection()

    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            conn.execute(
                'INSERT INTO messages (sender_id, recipient_id, content) VALUES (?, ?, ?)',
                (user_id, recipient_id, content)
            )
            conn.commit()

    messages = conn.execute('''
        SELECT * FROM messages
        WHERE (sender_id = ? AND recipient_id = ?)
           OR (sender_id = ? AND recipient_id = ?)
        ORDER BY timestamp ASC
    ''', (user_id, recipient_id, recipient_id, user_id)).fetchall()

    recipient = conn.execute('SELECT first_name FROM users WHERE id = ?', (recipient_id,)).fetchone()
    conn.close()

    return render_template('messages.html', messages=messages, recipient=recipient, recipient_id=recipient_id)

@app.route('/get_messages', methods=['GET'])
@login_required
def get_messages_route():
    user_id = session['user_id']
    messages = get_messages(user_id)
    return jsonify([dict(message) for message in messages]), 200

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
    return redirect(url_for('manage_users'))

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
        return redirect(url_for('manage_users'))

    conn.close()
    return render_template('edit_user.html', user=user)

@app.route('/admin/delete_post/<post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    if not session.get('is_admin'):
        flash('Access denied!', 'danger')
        return redirect(url_for('home'))

    conn = get_db_connection()
    conn.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    conn.commit()
    conn.close()

    flash('Post deleted successfully!', 'success')
    return redirect(url_for('manage_content'))

@app.route('/getFoundPosts', methods=['GET'])
@login_required
def get_found_posts_route():
    found_posts = fetch_found_posts()
    return jsonify(found_posts), 200

@app.route('/createFoundPost', methods=['POST'])
@login_required
def create_found_post_route():
    req_data = request.json
    if not req_data:
        return jsonify({"error": "No data provided"}), 400

    title = req_data.get('title')
    description = req_data.get('description')
    last_seen_location = req_data.get('last_seen_location')
    date = req_data.get('date')
    category = req_data.get('category')
    photo = req_data.get('photos', '')

    post_id = insert_found_post(title, description, last_seen_location, date, photo)

    if post_id:
        return jsonify({"message": "Found post created successfully!", "id": post_id}), 201
    else:
        return jsonify({"error": "Failed to create found post."}), 500

# SocketIO Messaging Functions
@socketio.on('send_message')
def handle_send_message(data):
    sender_id = session['user_id']
    receiver_id = data['receiver_id']
    message = cipher_suite.encrypt(data['message'].encode())  # Encrypt the message

    # Save the message to the database
    conn = get_db_connection()
    conn.execute('INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)',
                 (sender_id, receiver_id, message))
    conn.commit()
    conn.close()

    # Emit the message to the receiver
    emit('receive_message', {
        'message': data['message'],  # Send the plain text message
        'sender_id': sender_id
    }, room=str(receiver_id))

# Handle joining a room
@socketio.on('join')
def on_join(data):
    room = str(data['room'])
    join_room(room)

if __name__ == '__main__':
    app.run(debug=True)  # standard Flask run