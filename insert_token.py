import sqlite3
import uuid
import time

# Durée du token en minutes
duration_minutes = 30
duration_seconds = duration_minutes * 60

# Génère un token unique
token = str(uuid.uuid4()).replace("-", "").upper()[:16]

# Calcule le timestamp d'expiration
now = int(time.time())
valid_until = now + duration_seconds

# Valeurs factices pour test (tu peux ajuster si besoin)
link = "https://example.com/video"
ip = "127.0.0.1"

# Connexion à SQLite
conn = sqlite3.connect("tokens.db")
c = conn.cursor()

# Insère dans les bonnes colonnes
c.execute(
    "INSERT INTO tokens (token, link, ip, valid_until) VALUES (?, ?, ?, ?)",
    (token, link, ip, valid_until)
)

conn.commit()
conn.close()

print("✅ Token ajouté :", token)