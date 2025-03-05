from sqlmodel import Session
from models import User

class UserProvisioner:
    def __init__(self, engine):
        self.engine = engine

    def provision_user(self, email: str, name: str) -> None:
        with Session(self.engine) as session:
            existing_user = session.get(User, email)
            if existing_user:
                return
            new_user = User(email=email, name=name)
            session.add(new_user)
            session.commit()