import hashlib
from database.database import SessionLocal
from database.database import User

db = SessionLocal()
admin = db.query(User).filter(User.username == "admin").first()
if not admin:
    admin = User(
        username="admin",
        email="admin@local",
        password_hash=hashlib.sha256("12345".encode()).hexdigest(),
        role="admin"
    )
    db.add(admin)
    db.commit()
    print("Админ создан! Логин: admin | Пароль: 12345")
else:
    print("Админ уже существует")
db.close()