user_id = input()
query = "SELECT * FROM accounts WHERE id = '" + user_id + "'"
cursor.execute(query)
