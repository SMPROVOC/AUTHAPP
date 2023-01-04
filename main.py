import json
import os
import uvicorn
from utils import schema, functions
from fastapi import FastAPI, Request, APIRouter, Depends, status, Response, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv

app = FastAPI()

load_dotenv(override=True)

@app.post('/register')
async def register(request: schema.RegisterUser):

    created_user = functions.register_user(request.name, request.surname, request.email, request.password, request.password_confirmation)

    parsed_created_user= json.loads(created_user)


    return {
        'name': parsed_created_user['name'],
        'surname': parsed_created_user['surname'],
        'password': '*****',
        'response': 'user created'
    }



@app.get('/')
async def index():

    return {
        'response': 'welcome to your projects API'
    }


@app.post('/get_otp')
async def get_otp(form_data: OAuth2PasswordRequestForm = Depends()):

    otp_json = functions.otp_request(form_data.username, form_data.password)

    parsed_otp_json = json.loads(otp_json)

    return {
        "username": form_data.username,
        "otp": parsed_otp_json['otp'],
        "base64_otp_qrcode": parsed_otp_json['base64_otp_qrcode']
    }



@app.post('/login')
async def login(form_data: OAuth2PasswordRequestForm = Depends()):

    is_valid = functions.check_login_credentials(form_data.username, form_data.password, form_data.scopes)

    parse_data = json.loads(is_valid)
    user_token = parse_data['token']
    print(user_token)


    return {
        "user": form_data.username,
        "access_token": user_token,
        "token_type": "bearer"
    }


@app.get('/check')
async def check(current_user: schema.User = Depends(functions.get_current_active_user)):
    return {'response': f'check is gud {current_user}'}



















# @app.post("/token")
# async def token_login(form_data: OAuth2PasswordRequestForm = Depends()):
#
#     return f'is_validv{form_data.username}'
#
#
# @app.post("/pple")
# async def pple(current_user: schema.User = Depends(functions.get_current_active_user)):
#
#     return f'bhoo {current_user}'


# from typing import Union
#
# from fastapi import Depends, FastAPI, HTTPException, status
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from pydantic import BaseModel
#
# fake_users_db = {
#     "johndoe": {
#         "username": "johndoe",
#         "full_name": "John Doe",
#         "email": "johndoe@example.com",
#         "hashed_password": "fakehashedsecret",
#         "disabled": False,
#     },
#     "alice": {
#         "username": "alice",
#         "full_name": "Alice Wonderson",
#         "email": "alice@example.com",
#         "hashed_password": "fakehashedsecret2",
#         "disabled": True,
#     },
# }
#
# app = FastAPI()
#
#
# from typing import Union

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

# fake_users_db = {
#     "johndoe": {
#         "username": "johndoe",
#         "full_name": "John Doe",
#         "email": "johndoe@example.com",
#         "hashed_password": "fakehashedsecret",
#         "disabled": False,
#     },
#     "alice": {
#         "username": "alice",
#         "full_name": "Alice Wonderson",
#         "email": "alice@example.com",
#         "hashed_password": "fakehashedsecret2",
#         "disabled": True,
#     },
# }
#
# app = FastAPI()
#
#
# def fake_hash_password(password: str):
#     return "fakehashed" + password
#
#
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
#
#
# class User(BaseModel):
#     username: str
#     email: Union[str, None] = None
#     full_name: Union[str, None] = None
#     disabled: Union[bool, None] = None
#
#
# class UserInDB(User):
#     hashed_password: str
#
#
# def get_user(db, username: str):
#     if username in db:
#         user_dict = db[username]
#         return UserInDB(**user_dict)
#
#
# def fake_decode_token(token):
#     # This doesn't provide any security at all
#     # Check the next version
#     user = get_user(fake_users_db, token)
#     print(user)
#     return user
#
#
# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     print(f'token - {token}')
#     #user = fake_decode_token(token)
#     # if not user:
#     #     raise HTTPException(
#     #         status_code=status.HTTP_401_UNAUTHORIZED,
#     #         detail="Invalid authentication credentials",
#     #         headers={"WWW-Authenticate": "Bearer"},
#     #     )
#     return token
#
#
# async def get_current_active_user(current_user: User = Depends(get_current_user)):
#     print(current_user)
#     # if current_user.disabled:
#     #     raise HTTPException(status_code=400, detail="Inactive user")
#     return current_user
#
#
# @app.post("/token")
# async def login(form_data: OAuth2PasswordRequestForm = Depends()):
#     user_dict = fake_users_db.get(form_data.username)
#     if not user_dict:
#         raise HTTPException(status_code=400, detail="Incorrect username or password")
#     user = UserInDB(**user_dict)
#     hashed_password = fake_hash_password(form_data.password)
#     if not hashed_password == user.hashed_password:
#         raise HTTPException(status_code=400, detail="Incorrect username or password")
#
#     return {"access_token": user.username, "token_type": "bearer"}
#
#
# @app.get("/users/me")
# async def read_users_me(current_user: User = Depends(get_current_active_user)):
#     return current_user

if __name__ == '__main__':
    uvicorn.run(app)

    #functions.capture()

    # try:
    #     raise TypeError("Sorry, no numbers below zero")
    # except Exception as e:
    #     print(e, 'k')
















    # try:
    #     pending_overdrafts = db.session.query(models.Overdrafts)
    #
    #     pbar = tqdm(pending_overdrafts, desc='overdrafts', unit='odpm', ncols=100)
    #
    #     for overdraft in pbar:
    #
    #         od = db.session.query(models.Overdrafts).filter(models.Overdrafts.id == overdraft.id).first()
    #         od.is_processed = "3"
    #         db.session.commit()
    #         pbar.set_description(f'processing: {overdraft.overdraft_tenure}')
    #
    #         log.processed_logger.info(f'[PROCESSED] : {overdraft.full_name} - {overdraft.overdraft_tenure} - {overdraft.approved_amount}')
    #         # print(f'{od.id} changed')
    #
    # except Exception as e:
    #     log.events_logger.warning(f'[Overdraft processing] {e.args[0]}')

    #print(overdraft.count())


# users = db.session.query(models.User)
    # for user in users:
    #     #print(f'{user.email}\n')
    #     record = db.session.query(models.User).filter(models.User.id == user.id).first()
    #     record.is_enabled = "0"
    #     db.session.commit()
    #     print(record.is_enabled)








    # Get all data

    #users = db.session.query(models.User)
    # for user in users:
    #     print(f'{user.email}\n')

    # Get data in order

    #ordered_users = db.session.query(models.User).order_by(models.User.name)
    # for user in ordered_users:
    #     print(f'{user.name}\n')

    # Get data by filtering

    # 1 filter
    # filtered_users = db.session.query(models.User).filter(models.User.name == "edmah").first()
    # print(filtered_users.name, filtered_users.password)

    # filtered_od = db.session.query(models.Overdrafts).filter(models.Overdrafts.overdraft_tenure != "INDIVIDUAL 30 DAYS",
    #                                                          models.Overdrafts.overdraft_tenure != "INDIVIDUAL 30 DAYS USD NOSTRO",
    #                                                          models.Overdrafts.branch_origin == "NELSON MANDELA")
    #
    # for row in filtered_od:
    #     print(f'{row.overdraft_tenure} - {row.branch_origin}')
    # print(filtered_od.count())


    # Get data count

    #user_count = db.session.query(models.User).filter(models.User.name == "edmah").count()
    #print(user_count)

    # Update data

    #user = db.session.query(models.User).filter(models.User.id == 1).first()
    #user.is_enabled = "3"
    #db.session.commit()
    #print(user.is_enabled)




