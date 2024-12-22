import sqlite3
import os

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

    # Drop the users table if it exists
    cursor.execute("DROP TABLE IF EXISTS users")

    # Recreate the users table with the correct schema
    cursor.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        student_id TEXT,
        phone_number TEXT
    )
    """)

    # Create posts table (if it doesn't already exist)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS posts (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        last_seen_location TEXT,
        date TEXT,
        photos TEXT
    )
    """)

    # Create categories table (if it doesn't already exist)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )
    """)

    # Create items table (if it doesn't already exist)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        category TEXT NOT NULL
    )
    """)

    # Create messages table (if it doesn't already exist)
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

    # Insert default categories (if not already present)
    default_categories = ["Electronics", "Clothing", "Documents", "Accessories", "Others"]
    cursor.executemany("INSERT OR IGNORE INTO categories (name) VALUES (?)", [(c,) for c in default_categories])

    conn.commit()
    conn.close()
    print("Database initialized successfully!")

# Database query functions

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

def add_item(name, description, category):
    """Add a new item to the items table."""
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO items (name, description, category) VALUES (?, ?, ?)',
        (name, description, category)
    )
    conn.commit()
    conn.close()

def add_post(id, title, description, category, last_seen_location, date, photos):
    """Add a new post to the posts table."""
    conn = get_db_connection()
    conn.execute(
        '''
        INSERT INTO posts (id, title, description, category, last_seen_location, date, photos)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''',
        (id, title, description, category, last_seen_location, date, photos)
    )
    conn.commit()
    conn.close()

def get_categories():
    """Fetch all categories from the categories table."""
    conn = get_db_connection()
    categories = conn.execute('SELECT * FROM categories').fetchall()
    conn.close()
    return categories

# Messaging functions

def send_message(sender_id, recipient_id, item_id, message):
    """Send a message from one user to another."""
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO messages (sender_id, recipient_id, item_id, message) VALUES (?, ?, ?, ?)',
        (sender_id, recipient_id, item_id, message)
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
    conn = get_db_connection()
    conversations = conn.execute(
        'SELECT * FROM messages WHERE sender_id = ? OR recipient_id = ? ORDER BY timestamp DESC',
        (user_id, user_id)
    ).fetchall()
    conn.close()
    return conversations

# Add a new message
def add_message(sender_id, recipient_id, content):
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO messages (sender_id, recipient_id, content, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)',
        (sender_id, recipient_id, content)
    )
    conn.commit()
    conn.close()

# Example usage for debugging (run this file directly to initialize DB)
if __name__ == "__main__":
    initialize_db()  # Ensure the database is initialized when this script is run