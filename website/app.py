from flask import Flask, render_template, jsonify, redirect, url_for, request, flash, session
import sqlite3
import os
import uuid
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from time import sleep
from data import send_message, get_messages, add_message, get_user_conversations, claim_item  # Import the new functions
from data import create_post, get_unclaimed_items, get_posts_logic, insert_found_post, fetch_found_posts
from data import insert_claim
from data import search_posts, get_categories

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

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

@app.route('/post', methods=['GET', 'POST'])
@login_required
def post():
    if request.method == 'POST':
        # Get form data
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        last_seen_location = request.form['last_seen_location']
        date = request.form['date']
        photos = request.form.get('photos', '')

        # Create a unique post ID
        post_id = uuid.uuid4().hex

        # Save the post to the database
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

    # Check if the category exists
    cursor.execute("SELECT name FROM categories WHERE name = ?", (category,))
    if not cursor.fetchone():
        conn.close()
        return {"error": f"Category '{category}' does not exist"}, 400

    # Insert the post into the database
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
    """Logic for fetching posts"""
    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch posts from the database
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
        photo = request.form['photo']  # Assume photo is a URL or file path

        # Insert found item and create corresponding unclaimed item
        post_id = insert_found_post(title, description, last_seen_location, date, photo)

        if post_id:  # Check if the post was created successfully
            flash('Found item posted successfully!')
            return redirect(url_for('unclaimed_items_list'))
        else:
            flash('Failed to post found item.', 'danger')

    return render_template('found_post.html')

@app.route('/unclaimed_items', methods=['GET'])
@login_required
def unclaimed_items_list():
    """Display all unclaimed items or item details if an item_id is provided."""
    item_id = request.args.get('item_id', type=int)
    conn = get_db_connection()

    if item_id:
        # Fetch details for a specific item
        item = conn.execute('SELECT * FROM items WHERE id = ?', (item_id,)).fetchone()  # Updated to query items table
        conn.close()
        if item:
            return render_template('items_list.html', item=item)
        else:
            flash('Item not found!', 'danger')
            return redirect(url_for('unclaimed_items_list'))
    else:
        # Fetch all unclaimed items
        items = conn.execute('SELECT * FROM items WHERE status = "unclaimed"').fetchall()  # Updated to query items table
        conn.close()
        print("Unclaimed items fetched:", items)  # Debugging line
        return render_template('items_list.html', items=items)

@app.route('/claim/<int:item_id>', methods=['GET', 'POST'])
@login_required
def claim_item_route(item_id):
    if request.method == 'POST':
        user_id = current_user.id  # Ensure user is logged in
        data = request.get_json()  # Get JSON data from the request
        question_1 = data.get('question_1')
        question_2 = data.get('question_2')
        question_3 = data.get('question_3')

        print(f"Received data: {data}")  # Log the received data

        if not question_1 or not question_2 or not question_3:
            return jsonify({"error": "All questions must be answered."}), 400

        # Insert claim into the database
        success = insert_claim(item_id, user_id, question_1, question_2, question_3, '')

        if success:
            return jsonify({"message": "Claim Request Submitted. Wait for Admin Response"}), 200
        else:
            return jsonify({"error": "Failed to submit claim."}), 500

    # Render the claim form for GET requests
    return render_template('claim_form.html', item_id=item_id)

# Admin dashboard
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied: Admins only!', 'danger')
        return redirect(url_for('profile'))

    # Fetch claims and claimed items in one query
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT claims.id AS claim_id, found_items.title, claims.question_1, claims.question_2, claims.question_3, 
               claims.status AS claim_status, found_items.status AS item_status 
        FROM claims 
        JOIN found_items ON claims.item_id = found_items.id
    """)
    claims_combined = cursor.fetchall()
    conn.close()
    
    print("Claims fetched for admin dashboard:", claims_combined)  # Debugging line
    return render_template('admin_dashboard.html', claims=claims_combined)

# Admin manage claims
@app.route('/admin/manage_claims', methods=['GET', 'POST'])
@login_required
def manage_claims():
    """Admin can view and resolve claims."""
    if not current_user.is_admin:
        flash('Access denied: Admins only!', 'danger')
        return redirect(url_for('profile'))

    conn = get_db_connection()
    if request.method == 'POST':
        claim_id = request.form['claim_id']
        action = request.form['action']

        if action == 'approve':
            conn.execute('UPDATE claims SET status = "approved" WHERE id = ?', (claim_id,))
            conn.execute('UPDATE found_items SET status = "claimed" WHERE id = (SELECT item_id FROM claims WHERE id = ?)', (claim_id,))
            flash('Claim approved successfully!', 'success')
        elif action == 'reject':
            conn.execute('UPDATE claims SET status = "rejected" WHERE id = ?', (claim_id,))
            flash('Claim rejected successfully!', 'danger')

        conn.commit()

    claims = conn.execute("""
        SELECT claims.id AS claim_id, found_items.title, claims.question_1, claims.question_2, claims.question_3, 
               claims.status AS claim_status, found_items.status AS item_status 
        FROM claims 
        JOIN found_items ON claims.item_id = found_items.id
    """).fetchall()
    conn.close()
    
    print("Claims fetched for manage claims:", claims)  # Debugging line
    return render_template('manage_claims.html', claims=claims)

# New route for user dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM found_items WHERE status = 'unclaimed'")
    items = cursor.fetchall()
    conn.close()
    return render_template('dashboard.html', items=items)

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

@app.route('/get_messages', methods=['GET'])
@login_required
def get_messages_route():
    user_id = session['user_id']
    messages = get_messages(user_id)
    return jsonify([dict(message) for message in messages]), 200

# Admin Dashboard
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
    items = conn.execute('SELECT * FROM found_items').fetchall()  # Adjust this query based on your items table
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

# New route to fetch found posts
@app.route('/getFoundPosts', methods=['GET'])
@login_required
def get_found_posts_route():
    """Fetch all found posts."""
    found_posts = fetch_found_posts()  # Call the function to get found posts
    return jsonify(found_posts), 200

# New route to create a found post
@app.route('/createFoundPost', methods=['POST'])
@login_required
def create_found_post_route():
    req_data = request.json
    if not req_data:
        return jsonify({"error": "No data provided"}), 400

    # Extract data from the request
    title = req_data.get('title')
    description = req_data.get('description')
    last_seen_location = req_data.get('last_seen_location')
    date = req_data.get('date')
    category = req_data.get('category')
    photo = req_data.get('photos', '')  # Assuming photos is a comma-separated string

    # Call the function to insert the found post
    post_id = insert_found_post(title, description, last_seen_location, date, photo)

    if post_id:
        return jsonify({"message": "Found post created successfully!", "id": post_id}), 201
    else:
        return jsonify({"error": "Failed to create found post."}), 500

@app.route('/search', methods=['GET'])
def search():
    # Get category and keyword from the form
    category = request.args.get('category')
    keyword = request.args.get('keyword')

    # Fetch categories for the dropdown (always available)
    categories = get_categories()

    # Initialize posts as an empty list
    posts = []

    # If a search is made (category or keyword provided), perform the search
    if category or keyword:
        posts = search_posts(category=category, keyword=keyword)

    return render_template('search.html', categories=categories, posts=posts)









if __name__ == '__main__':
    app.run(debug=True)  # standard Flask run