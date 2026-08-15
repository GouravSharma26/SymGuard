import sqlite3

conn = sqlite3.connect(":memory:")
cursor = conn.cursor()

username = input("Username: ")

# VULNERABLE: tainted data concatenated directly into the query string
query = "SELECT * FROM users WHERE name = '" + username + "'"
cursor.execute(query)

# SAFE: parameterized query -- taint flows into a separate bound argument,
# never into the SQL string itself, so the analyzer will NOT flag this call.
cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
