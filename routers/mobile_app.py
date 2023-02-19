from fastapi import APIRouter, Depends, status, Request, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from functions import auth_functions
from utils import schema

router = APIRouter(
    prefix='/app',
    tags=['Mobile App Routes']
)

templates = Jinja2Templates(directory="templates")


@router.get('/get_confirmation_request')
async def gets_active_confirmation_request(request: Request, user_info: schema.UserRegistration, background_task: BackgroundTasks):
    # return auth_functions.register_user(request, user_info, background_task)
    pass


@router.post('/send_confirmation_response', response_class=HTMLResponse)
async def responds_to_app_confirmation_requests(request: Request, verification_code: str):
    pass
