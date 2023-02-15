from fastapi import APIRouter, Depends, status, Request, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from functions import auth_functions
from utils import schema

router = APIRouter(
    prefix='/register',
    tags=['Registration']
)

templates = Jinja2Templates(directory="templates")


@router.post('/user')
async def register_a_user(request: Request, user_info: schema.UserRegistration, background_task: BackgroundTasks):
    return auth_functions.register_user(request, user_info, background_task)


@router.get('/verify_user/{verification_code}', response_class=HTMLResponse)
async def verify_a_registered_user(request: Request, verification_code: str):

    response = auth_functions.verify_a_registered_user(request, verification_code)

    if response['decision'] == 'valid':
        return templates.TemplateResponse( "registration_verification_approval.html",
                                           {"request": request, "pic": 'staMyQRCode1.png', 'username': response['username']})

    if response['decision'] == 'invalid':
        return templates.TemplateResponse("registration_verification_rejection.html",
                                          {"request": request})


@router.get('/resend_verification_code/{email}')
async def resend_verification_code(request: Request, email: str, background_task: BackgroundTasks):
    response = auth_functions.resend_verification_code(email, background_task)

    return response
