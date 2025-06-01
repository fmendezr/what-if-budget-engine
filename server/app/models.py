from datetime import datetime, timezone
from sqlalchemy import ForeignKey, String, DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from flask_jwt_extended import get_current_user
from app.security import pwd_context


class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ =  'user'
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(30), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    _password_hash: Mapped[str] = mapped_column("password_hash")

    def set_password(self, plaintext: str):
        self._password_hash= pwd_context.hash(plaintext)

    def verify_password(self, plaintext: str):
        valid, new_hash = pwd_context.verify_and_update(plaintext, self._password_hash)
        if valid and new_hash:
            self._password_hash = new_hash
        return valid
    
class TokenBlocklist(Base):
    __tablename__ = 'token_blocklist'
    id: Mapped[int] = mapped_column(primary_key=True)
    jti: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey(User.id), default=lambda: get_current_user().id, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
