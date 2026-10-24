user_id = input()
# Parameterized query with tuple parameters is safe
cursor.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))
