import sqlite3
import uuid
import os
from flask import jsonify

# Define the database path
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")

def create_post_logic(req_data):
    """Logic for creating a post"""
    post_id = uuid.uuid4().hex
    title = req_data.get('title')
    description = req_data.get('description')
    category = req_data.get('category')
    last_seen_location = req_data.get('last_seen_location')
    date = req_data.get('date')
    photos = req_data.get('photos', '')

    # Connect to the database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Check if the category exists in the database
    cursor.execute("SELECT name FROM categories WHERE name = ?", (category,))
    valid_category = cursor.fetchone()

    if not valid_category:
        conn.close()
        return {"error": f"Category '{category}' does not exist"}, 400

    # Insert the post into the posts table
    cursor.execute("""
    INSERT INTO posts (id, title, description, category, last_seen_location, date, photos)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (post_id, title, description, category, last_seen_location, date, photos))
    conn.commit()
    conn.close()

    return {"message": "Post created successfully", "id": post_id}, 201

def get_categories():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM categories")
    categories = [row[0] for row in cursor.fetchall()]
    conn.close()
    return jsonify({"categories": categories}), 200


def get_posts_logic():
    """Logic for fetching posts"""
    # Connect to the database
    conn = sqlite3.connect(DB_PATH)
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

