from pydantic import BaseModel


class LoginScema(BaseModel):
    email:str
    password:str
