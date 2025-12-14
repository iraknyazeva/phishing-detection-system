from passlib.context import CryptContext

from database.database import SessionLocal
from database.models.user import User

pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

db = SessionLocal()

u = db.query(User).filter(User.username == "admin").first()
if not u:
    print("admin not found")
else:
    u.password_hash = pwd.hash("admin")
    db.commit()
    print("admin password reset to: admin (pbkdf2_sha256)")

db.close()
