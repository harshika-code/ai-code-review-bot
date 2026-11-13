import subprocess
import sqlite3

def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = " + username
    cursor.execute(query)
    return cursor.fetchall()

def run_command(user_input):
    subprocess.call(user_input, shell=True)

def render_page(user_data):
    return "<div>" + user_data + "</div>"
