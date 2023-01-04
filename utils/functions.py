import base64
import io
import json
import os
import random
import re
from datetime import datetime, timedelta, date
from utils import database as db
from utils import models, schema
import qrcode
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from dotenv import load_dotenv
from passlib.context import CryptContext


load_dotenv(override=True)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='login')
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def otp_request(username, password):

    # Get email provided by the user from db
    user = db.session.query(models.User).filter(models.User.email == username).first()

    # Check if the user exist
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incorrect username or password")

    # Verify if password matches
    pwd_match = pwd_context.verify(password, user.password)

    # Check if the password is valid
    if not pwd_match:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incorrect username or password")

    # Generate and fetch otp
    genarated_otp = genarate_otp(user.id)

    # Get the current date time
    current_date_time = datetime.now()

    # convert datetime to string format %Y/%m/%d %H:%M:%S
    otp_created_at = current_date_time.strftime('%Y/%m/%d %H:%M:%S')

    # create new active otp session in db
    new_otp = models.Auth(
        user_id=user.id,
        otp=genarated_otp,
        token="token_string['token']",
        created_at=otp_created_at,
        deleted_at='Null',
        state='active'
    )
    db.session.add(new_otp)
    db.session.commit()

    return genarated_otp


def check_login_credentials(email, password, scope):

    # Get email provided by the user from db
    user = db.session.query(models.User).filter(models.User.email == email).first()

    # Check if the user details exists
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    # Verify if password matches
    pwd_match = pwd_context.verify(password, user.password)

    # Check if the password match
    if not pwd_match:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    # Get active otp session for the specific user in db in any
    is_otp_active = db.session.query(models.Auth).filter(models.Auth.user_id == user.id, models.Auth.state == 'active').first()

    # Check if active otp session details exist
    if not is_otp_active:
        raise HTTPException(status_code=400, detail="session not found")

    # Get the date at which the active otp was created
    otp_created_date = is_otp_active.created_at

    # Convert the date in string format to date format
    parsed_otp_created_at = datetime.strptime(otp_created_date, '%Y/%m/%d %H:%M:%S')

    # Get the current date time
    current_date_time = datetime.now()

    # Get the difference between the current date time against the time the active otp session was created
    otp_session_time = int((current_date_time - parsed_otp_created_at).seconds / 60)

    # Check to verify if the otp_session_time is greater than 1 or x (as minutes)
    if otp_session_time > int(os.getenv('OTP_EXPIRE_MINUTES')):    # this is in minutes

        # Get the current active otp session for the specific user
        auth = db.session.query(models.Auth).filter(models.Auth.user_id == user.id,models.Auth.state == 'active').first()

        # Update the current active otp session to expire
        auth.state = "expired"
        db.session.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="otp session expired")

    # Parse otp json string to json
    saved_otp_json = json.loads(is_otp_active.otp)

    # Check if the active otp session in db matches the one provided by the user
    if saved_otp_json["otp"] != scope[0]:   # scope is a dynamic array. scope = [otp]
        raise HTTPException(status_code=400, detail="invalid otp")

    # Create an access token
    access_token = create_access_token(data={'sub': scope[0]})

    # Insert token in db where the user has an active otp session
    is_otp_active.token = access_token
    db.session.commit()

    # Create response dictionary/json
    response_dict = {
        'name': user.name,
        'surname': user.surname,
        'email': user.email,
        'is_enabled': user.is_enabled,
        'response': 'authenticated',
        'token': f'{access_token}',
    }

    return json.dumps(response_dict)



def register_user(name, surname, email, password, password_confirmation):

    '''
        A password is considered strong if:
        8 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more
    '''



    full_name = "".join([name, surname])

    if full_name == "":
        raise HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT, detail="name/surname can not be blank")

    if len(full_name) < 6:
        raise HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT, detail="name/surname can not have less than 3"
                                                                                " characters")

    if has_numbers(full_name):
        raise HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT, detail="name/surname can not contains numbers")

    if len(password) < 8:
        raise HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT, detail="password can not have less than 8 "
                                                                                "characters")

    # searching for digits
    if re.search(r"\d", password) is None:
        raise HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT, detail="password must contain atleast one "
                                                                                "digit")

    # searching for uppercase
    if re.search(r"[A-Z]", password) is None:
        raise HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT, detail="password must contain atleast one "
                                                                                "uppercase")

    # searching for lowercase
    if re.search(r"[a-z]", password) is None:
        raise HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT, detail="password must contain atleast one "
                                                                                "lowercase")

    # searching for symbols
    if re.search(r"[ !@#$%&'()*+,-./[\\\]^_`{|}~" + r'"]', password) is None:
        raise HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT, detail="password must contain atleast one "
                                                                                "symbol")

    if password != password_confirmation:
        raise HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT, detail="password do not match")

    hashedPassword = pwd_context.hash(password)

    # create new user in db
    new_user = models.User(
        name=name,
        surname=surname,
        username='Null',
        password=hashedPassword,
        email=email,
        is_enabled='1',
    )
    db.session.add(new_user)
    db.session.commit()

    # Create user dictionary
    user_dict = {
        'name': name,
        'surname': surname,
        'email': email,
    }

    return json.dumps(user_dict)






def genarate_otp(user_id):

    # Check for any active otp sessions for this specific user
    active_otp = db.session.query(models.Auth).filter(models.Auth.user_id == user_id, models.Auth.state == 'active')

    # loop through all active session for the specific user to expire them
    for otps in active_otp:

        if otps.state == 'active':
            auth = db.session.query(models.Auth).filter(models.Auth.user_id == user_id, models.Auth.state == 'active').first()
            auth.state = "expired"
            db.session.commit()

    # Numbers used to generate otp
    otp_characters = os.getenv('OTP_CHARACTERS')

    # Defining otp length to X characters
    length_for_otp = int(os.getenv('OTP_STRING_LENGTH'))

    # Randomize the numbers
    otp = "".join(random.sample(otp_characters, length_for_otp))

    # Create qrcode  from otp string
    otp_qrcode = qrcode.make(otp)

    # Convert image to bytes
    img_byte_arr = io.BytesIO()

    # Save image as PNG, JPEG, JPG
    otp_qrcode.save(img_byte_arr, format=os.getenv('OTP_QRCODE_IMG_FORMAT'))
    img_byte_arr = img_byte_arr.getvalue()

    # Create response dictionary/json
    otp_dict = {
        "otp": otp,
        "base64_otp_qrcode": f"{base64.b64encode(img_byte_arr)}",
    }

    # Convert dictionary to json
    json_dict = json.dumps(otp_dict)

    return json_dict


def create_access_token(data: dict):

    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES')))
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, os.getenv('SECRET_KEY'), algorithm=os.getenv('ALGORITHM'))
    return encoded_jwt


def verify_token(token: str, credentials_exception):

    try:
        payload = jwt.decode(token, os.getenv('SECRET_KEY'), algorithms=[os.getenv('ALGORITHM')])

        verified_token: str = payload.get("sub")
        if verified_token is None:
            raise credentials_exception
        token_data = schema.TokenData(token_otp=verified_token)
    except JWTError:
        raise credentials_exception


async def get_current_user(token: str = Depends(oauth2_scheme)):

    # Check for a token where otp session is active
    active_token = db.session.query(models.Auth).filter(models.Auth.token == token, models.Auth.state == 'active').first()

    # Check if token exists
    if not active_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='could not validate credentials',
        headers={'WWW-Authenticate': 'Bearer'},
    )

    # Check validity of token
    verify_token(active_token.token, credentials_exception)

    return active_token.user_id


async def get_current_active_user(current_user_id: schema.User = Depends(get_current_user)):

    # Get the current active user
    user = db.session.query(models.User).filter(models.User.id == current_user_id).first()

    # Check if the user exists
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Check if the user is enabled
    if user.is_enabled != '1':
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive user")

    return user.email


def has_numbers(inputString):
    return any(char.isdigit() for char in inputString)