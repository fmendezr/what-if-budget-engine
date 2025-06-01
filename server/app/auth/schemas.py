from pydantic import BaseModel, Field, EmailStr

class LoginModel(BaseModel):
    username: str 
    password: str

class SignupModel(BaseModel):
    username: str = Field(min_length=3)
    password: str = Field(min_length=8)
    email: EmailStr