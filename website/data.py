import sqlite3
import os
import uuid

# Define the database path
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")

def get_db_connection():
    """Create a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Enables dictionary-like access
    return conn

def initialize_db():
    """Initialize the database and create necessary tables."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Drop posts table if it exists
    cursor.execute("DROP TABLE IF EXISTS posts")

    # Create users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        student_id TEXT,
        phone_number TEXT
    )
    """)

    # Create posts table with post_type column
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS posts (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        last_seen_location TEXT NOT NULL,
        date TEXT NOT NULL,
        photos TEXT,
        post_type TEXT NOT NULL  -- New column to identify post type
    )
    """)

    # Create items table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL,
        FOREIGN KEY (post_id) REFERENCES posts (id)
    )
    """)

    # Create found_items table (add a status field)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS found_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        last_seen_location TEXT NOT NULL,
        date TEXT NOT NULL,
        category TEXT NOT NULL,
        photo_path TEXT,
        user_id INTEGER,
        status TEXT DEFAULT 'unclaimed',  -- Default status for found items
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """)

    # Create categories table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )
    """)

    # Create claims table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS claims (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        item_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        question_1 TEXT,
        question_2 TEXT,
        question_3 TEXT,
        answers TEXT,  -- Added answers column
        status TEXT DEFAULT 'pending',
        rejection_reason TEXT,  -- Added rejection_reason column
        FOREIGN KEY (item_id) REFERENCES items (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """)

    # Create messages table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        recipient_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users(id),
        FOREIGN KEY (recipient_id) REFERENCES users(id)
    )
    """)

    # Insert admin user if it doesn't already exist
    cursor.execute('''
    INSERT OR IGNORE INTO users (first_name, email, password, is_admin)
    VALUES ('Admin', 'admin1@gmail.com', 'admin123', 1)
    ''')

    # Insert default categories
    default_categories = ["Electronics", "Clothing", "Documents", "Accessories", "Others", "Personal", "Clothes", "Books"]
    cursor.executemany("INSERT OR IGNORE INTO categories (name) VALUES (?)", [(c,) for c in default_categories])

    conn.commit()
    conn.close()
    print("Database initialized successfully!")


def initialize_reports_table():
    """Create a table to store post reports."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id TEXT NOT NULL,
            report_reason TEXT NOT NULL,

            description TEXT,
            FOREIGN KEY (post_id) REFERENCES posts (id)
        )
    """)
    conn.commit()
    conn.close()

initialize_reports_table()

def add_report_category_column():
    """Add the report_category column to the reports table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if the column already exists to avoid error
    cursor.execute("PRAGMA table_info(reports)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'report_category' not in columns:
        cursor.execute("""
            ALTER TABLE reports
            ADD COLUMN report_category TEXT NOT NULL DEFAULT 'Regular'
        """)
        conn.commit()
    
    conn.close()

add_report_category_column()


def add_report_category_column():
    """Add the report_category column to the reports table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    

    cursor.execute("PRAGMA table_info(reports)")
    columns = [column[1] for column in cursor.fetchall()]
    

    if 'report_category' not in columns:
        cursor.execute("""
            ALTER TABLE reports
            ADD COLUMN report_category TEXT
        """)
        conn.commit()


    cursor.execute("""
        UPDATE reports
        SET report_category = 'Regular'
        WHERE report_category IS NULL
    """)
    conn.commit()
    conn.close()

add_report_category_column()




def initialize_chatbot_table():
    """Create a table to store chatbot messages."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chatbot_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            response TEXT,
            is_custom BOOLEAN DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    conn.commit()
    conn.close()

initialize_chatbot_table()




def update_claims_table():
    """Update the claims table to ensure all required columns exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the columns exist
    cursor.execute("PRAGMA table_info(claims);")
    columns = [column[1] for column in cursor.fetchall()]

    # Add columns if they do not exist
    if 'question_1' not in columns:
        cursor.execute("ALTER TABLE claims ADD COLUMN question_1 TEXT;")
    if 'question_2' not in columns:
        cursor.execute("ALTER TABLE claims ADD COLUMN question_2 TEXT;")
    if 'question_3' not in columns:
        cursor.execute("ALTER TABLE claims ADD COLUMN question_3 TEXT;")
    if 'answers' not in columns:  # Ensure answers column exists
        cursor.execute("ALTER TABLE claims ADD COLUMN answers TEXT;")
    if 'rejection_reason' not in columns:  # Ensure rejection_reason column exists
        cursor.execute("ALTER TABLE claims ADD COLUMN rejection_reason TEXT;")

    conn.commit()
    conn.close()

def update_database():
    """Update the database schema to ensure the status column exists in found_items."""
    conn = get_db_connection()
    c = conn.cursor()

    # Check if the 'status' column exists in the 'found_items' table
    c.execute("PRAGMA table_info(found_items)")
    columns = [column[1] for column in c.fetchall()]

    # If 'status' column does not exist, add it
    if 'status' not in columns:
        c.execute('ALTER TABLE found_items ADD COLUMN status TEXT DEFAULT "unclaimed"')
        print("Added 'status' column to 'found_items' table.")

    conn.commit()
    conn.close()

# Database query functions

def create_post(post_id, title, description, category, last_seen_location, date, photos, post_type):
    """Save a new post to the database and mark it as unclaimed in the items table."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Insert into posts table
    cursor.execute("""
        INSERT INTO posts (id, title, description, category, last_seen_location, date, photos, post_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (post_id, title, description, category, last_seen_location, date, photos, post_type))

    # Insert into items table as unclaimed
    cursor.execute("""
        INSERT INTO items (post_id, title, description, status)
        VALUES (?, ?, ?, 'unclaimed')
    """, (post_id, title, description))

    conn.commit()
    conn.close()

# Function to insert a found item
def insert_found_post(title, description, last_seen_location, date, photo):
    post_id = uuid.uuid4().hex
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Insert into posts table
        cursor.execute("""
        INSERT INTO posts (id, title, description, category, last_seen_location, date, photos, post_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (post_id, title, description, 'Found', last_seen_location, date, photo, 'found'))  # Default category
        
        # Insert into items table as unclaimed
        cursor.execute("""
            INSERT INTO items (post_id, title, description, status)
            VALUES (?, ?, ?, 'unclaimed')
        """, (post_id, title, description))

        conn.commit()  # Commit both insertions
        print(f"Inserted found post: {title}, ID: {post_id}")  # Debugging line
        return post_id
    except Exception as e:
        print(f"Error inserting found post: {e}")  # Log the error
        conn.rollback()  # Rollback in case of error
    finally:
        conn.close()

# Function to fetch all found posts
def fetch_found_posts():
    """Fetch all found posts from the posts table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM posts WHERE post_type = 'found'")  # Adjusted to use post_type
    posts = cursor.fetchall()
    
    conn.close()
    return [dict(post) for post in posts]  # Convert rows to dictionaries

def get_unclaimed_items():
    """Fetch all unclaimed items from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE status = 'unclaimed'")
    items = cursor.fetchall()
    print("Unclaimed items fetched:", items)  # Debugging line
    conn.close()
    return items

def get_all_items():
    """Fetch all items from the items table."""
    conn = get_db_connection()
    items = conn.execute('SELECT * FROM items').fetchall()
    conn.close()
    return items

def get_all_posts():
    """Fetch all posts from the posts table."""
    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts').fetchall()
    conn.close()
    return posts

def add_item(title, description, last_seen_location, date, photo, category):
    """Add a new item to the items table."""
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO items (title, description, last_seen_location, date, photo, category) VALUES (?, ?, ?, ?, ?, ?)',
        (title, description, last_seen_location, date, photo, category)
    )
    conn.commit()
    conn.close()

def add_post(id, title, description, category, last_seen_location, date, photos, post_type):
    """Add a new post to the posts table."""
    conn = get_db_connection()
    conn.execute(
        '''
        INSERT INTO posts (id, title, description, category, last_seen_location, date, photos, post_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (id, title, description, category, last_seen_location, date, photos, post_type)
    )
    conn.commit()
    conn.close()

def create_item_from_post(post_id, title, description, last_seen_location, date, photos, category):
    """Create an item from a post."""
    add_item(title, description, last_seen_location, date, photos, category)

def get_categories():
    """Fetch all categories from the categories table."""
    conn = get_db_connection()
    categories = conn.execute('SELECT * FROM categories').fetchall()
    conn.close()
    return categories

# Claim functions

def claim_item(item_id, user_id, question_1, question_2, question_3, answers):
    """Claim an item by a user."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the item exists
    cursor.execute("SELECT * FROM items WHERE id = ?", (item_id,))
    if not cursor.fetchone():
        print(f"Item with ID {item_id} does not exist.")
        return False

    # Check if the user exists
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    if not cursor.fetchone():
        print(f"User with ID {user_id} does not exist.")
        return False

    # Check if answers is None or empty, and set a default value if needed
    if answers is None or answers.strip() == "":
        answers = ""  # Set to an empty string or any default value you prefer

    try:
        cursor.execute(
            'INSERT INTO claims (item_id, user_id, question_1, question_2, question_3, answers) VALUES (?, ?, ?, ?, ?, ?)',
            (item_id, user_id, question_1, question_2, question_3, answers)
        )
        # Update item status to claimed
        cursor.execute('UPDATE items SET status = ? WHERE id = ?', ('claimed', item_id))
        conn.commit()
    except sqlite3.IntegrityError as e:
        print(f"Error occurred: {e}")  # Log the error
        return False  # Indicate failure
    finally:
        conn.close()

    return True  # Indicate success

def get_claims():
    """Fetch all claims from the claims table."""
    conn = get_db_connection()
    claims = conn.execute('SELECT * FROM claims').fetchall()
    conn.close()
    return claims

def get_claims_for_item(item_id):
    """Fetch all claims for a specific item."""
    conn = get_db_connection()
    claims = conn.execute('SELECT * FROM claims WHERE item_id = ?', (item_id,)).fetchall()
    conn.close()
    return claims

def insert_claim(item_id, user_id, question_1, question_2, question_3, answers):
    """Insert a new claim into the claims table and return the claim ID."""
    conn = get_db_connection()
    cursor = conn.cursor()

    print(f"Inserting claim: item_id={item_id}, user_id={user_id}, question_1={question_1}, question_2={question_2}, question_3={question_3}, answers={answers}")  # Debugging line

    try:
        cursor.execute(
            'INSERT INTO claims (item_id, user_id, question_1, question_2, question_3, answers) VALUES (?, ?, ?, ?, ?, ?)',
            (item_id, user_id, question_1, question_2, question_3, answers)
        )
        conn.commit()
        return cursor.lastrowid  # Return the ID of the inserted claim
    except sqlite3.IntegrityError as e:
        print(f"IntegrityError occurred: {e}")  # Log the error
        return False
    except Exception as e:
        print(f"Error occurred: {e}")  # Log any other errors
        return False
    finally:
        conn.close()

# New function to fetch claims for the admin dashboard
def get_claims_for_admin():
    """Fetch all claims for the admin dashboard."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM claims')
    claims = cursor.fetchall()
    
    print("Claims fetched for admin dashboard:", claims)  # Debugging line
    conn.close()
    return claims

# Messaging functions

def send_message(sender_id, recipient_id, content):
    """Send a message from one user to another."""
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO messages (sender_id, recipient_id, content) VALUES (?, ?, ?)',
        (sender_id, recipient_id, content)
    )
    conn.commit()
    conn.close()

def get_messages(user_id):
    """Fetch messages for a user (both sent and received)."""
    conn = get_db_connection()
    messages = conn.execute(
        'SELECT * FROM messages WHERE recipient_id = ? OR sender_id = ? ORDER BY timestamp DESC',
        (user_id, user_id)
    ).fetchall()
    conn.close()
    return messages

# Fetch user conversations
def get_user_conversations(user_id):
    """Fetch all conversations for a user."""
    conn = get_db_connection()
    conversations = conn.execute(
        'SELECT * FROM messages WHERE sender_id = ? OR recipient_id = ? ORDER BY timestamp DESC',
        (user_id, user_id)
    ).fetchall()
    conn.close()
    return conversations

# New function to add a message (if needed)
def add_message(sender_id, recipient_id, content):
    """Add a message to the messages table."""
    send_message(sender_id, recipient_id, content)  # Reuse send_message for adding

def get_posts_logic():
    """Fetch all posts from the posts table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM posts")
    posts = cursor.fetchall()
    conn.close()
    return [dict(post) for post in posts]  # Convert rows to dictionaries

def get_sorted_posts(post_type, sort_by):
    """Fetch sorted posts based on type and criteria."""
    conn = get_db_connection()
    query = f"SELECT * FROM posts WHERE post_type = ?"
    if sort_by == "recent":
        query += " ORDER BY date DESC"
    elif sort_by == "name_asc":
        query += " ORDER BY title ASC"
    elif sort_by == "name_desc":
        query += " ORDER BY title DESC"
    posts = conn.execute(query, (post_type,)).fetchall()
    conn.close()
    return posts


def get_lost_posts():
    conn = get_db_connection()
    posts = conn.execute("SELECT * FROM posts WHERE post_type = 'lost'").fetchall()
    conn.close()
    return posts

def get_found_posts():
    conn = get_db_connection()
    posts = conn.execute("SELECT * FROM posts WHERE post_type = 'found'").fetchall()
    conn.close()
    return posts

def get_all_reports():
    """Fetch all reports from the database."""
    conn = get_db_connection()
    reports = conn.execute("""
        SELECT r.id AS report_id, p.id AS post_id, p.title, p.description, p.category, p.last_seen_location, p.date, r.report_reason, r.report_category, r.description AS report_details
        FROM reports r
        JOIN posts p ON r.post_id = p.id
    """).fetchall()
    conn.close()
    return reports

def delete_post(post_id):
    """Delete a post and its associated reports from the database."""
    conn = get_db_connection()
    conn.execute("DELETE FROM reports WHERE post_id = ?", (post_id,))
    conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()


# Example usage for debugging (run this file directly to initialize DB)
if __name__ == "__main__":
    initialize_db()  # Ensure the database is initialized when this script is run
    update_database()  # Ensure the database schema is updated
    update_claims_table()  # Ensure the claims table is updated