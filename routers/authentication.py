from fastapi import APIRouter, Depends, status, Request, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from functions import auth_functions

router = APIRouter(
    tags=['Authentication']
)


@router.post('/login')
async def login(request: Request, background_task: BackgroundTasks, form_data: OAuth2PasswordRequestForm = Depends()):

    response = auth_functions.login_user(request, background_task, form_data)

    return response


@router.get('/logout')
async def logout():
    return {'message': 'logged out'}


