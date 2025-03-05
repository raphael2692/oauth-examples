from sqlmodel import SQLModel, Field

class User(SQLModel, table=True):
    email: str = Field(primary_key=True)
    name: str