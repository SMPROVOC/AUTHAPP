from fastapi import APIRouter, Depends, status, Request
from fastapi.security import APIKeyHeader
from fastapi.security import OAuth2PasswordRequestForm
from functions import auth_functions
from utils import schema

router = APIRouter(
    tags=['Greetings']
)

@router.get('/', status_code=status.HTTP_200_OK,  response_model=schema.ShowGreeting)
async def greeting(request: Request):
    return {'greeting': 'Welcome to Auther.'}