from fastapi import APIRouter, Depends, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from functions import auth_functions
from utils import schema

router = APIRouter(
    tags=['Users']
)

@router.get('/user/profile')
async def profile(current_user: schema.User = Depends(auth_functions.get_current_active_user)):
    return {'message': 'profile'}

# @app.get('/', status_code=status.HTTP_200_OK, response_model=schema.ShowGreeting)
# async def greeting(current_user: schema.User = Depends(auth_functions.get_current_active_user)):
#     return {'message': 'hello'}