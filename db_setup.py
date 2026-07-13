import sqlite3

conn = sqlite3.connect('users.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY, username TEXT, email TEXT,
    password TEXT, role TEXT DEFAULT 'user', credit_card TEXT, auth_token TEXT
)''')
c.execute("INSERT OR IGNORE INTO user VALUES (1,'admin','admin@example.com','admin123','admin','4111111111111111','tok_admin_9f8e7d6c')")
c.execute("INSERT OR IGNORE INTO user VALUES (2,'alice','alice@example.com','password1','user','4222222222222222','tok_alice_1a2b3c4d')")
conn.commit()
conn.close()
print('DB initialized')
