import sqlite3
import os

# Define the database path
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")

def find_matches_logic(req_data):

    # Extract search parameters
    title = req_data.get('title', '').lower()
    description = req_data.get('description', '').lower()
    location = req_data.get('last_seen_location', '').lower()

    # Connect to the correct database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, description, category, last_seen_location, date, photos FROM posts")
    
    # Fetch posts and format them into dictionaries
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

    matches = []

    # Check for matching criteria
    for post in posts:
        title_match = title in post["title"].lower()
        description_match = description in post["description"].lower()
        location_match = location in post["last_seen_location"].lower()

        # Add to matches if any condition is met
        if title_match or description_match or location_match:
            matches.append(post)

    # Return matching results
    if matches:
        return {"matches": matches}
    else:
        return {"message": "No matching items found"}
