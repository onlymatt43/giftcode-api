import sqlite3

conn = sqlite3.connect("tokens.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE tokens (
    token TEXT PRIMARY KEY,
    link TEXT NOT NULL,
    ip TEXT NOT NULL,
    valid_until INTEGER NOT NULL
)
""")

conn.commit()
conn.close()

print("✅ Table 'tokens' créée avec succès.")