import os
import re
import io
import json
import random
import base64
import qrcode
import string
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from functions.email_functions import sendEmailToGmailUser
from functions.whatsapp_functions import send_whatsapp
from functions.text_message_functions import send_text
from functions.otp_functions import generate_otp, verify_otp
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from utils import schema, models, database as db


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='login')
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def registration_headers_check(request: Request) -> dict:
    # check for the application header in request
    if not request.headers.get('authorization'):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please include an authorization header and the authorization value.")

    # check for the application header in request
    if not request.headers.get('application'):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please include an application header and the application value.")

    application_name = request.headers.get('application')

    if application_name != 'web' and application_name != 'app':
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="An invalid application name was provided in the header. Try choosing between 'app' and 'web' "
                   "as your application header values.")

    if application_name == 'web':
        return {
            'device_name': 'default',
            'device_id': 'default',
            'authorization': request.headers.get('authorization')
        }

    if application_name == 'app':

        # check for the device name header in request
        if not request.headers.get('device_name'):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Please include a device_name header and the device_name value.")

        # check for the device id header in request
        if not request.headers.get('device_id'):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Please include a device_id header and the device_id value.")

        # get device name and device id
        device_name = request.headers.get('device_name')
        device_id = request.headers.get('device_id')

        return {
            'device_name': device_name,
            'device_id': device_id
        }


def register_user(request: Request, user_info: schema.UserRegistration, background_task) -> dict:

    # check for required headers
    headers = registration_headers_check(request)

    if user_info.First_Name == '':
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="The First name can not be empty.")

    if user_info.Last_Name == '':
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="The Last name can not be empty.")

    if user_info.Gender == '':
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="The Gender can not be empty.")

    if user_info.Email == '':
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="The Email can not be empty.")

    if user_info.Password == '':
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="The Password can not be empty.")

    if user_info.Cell_Number == '':
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="The Cell number can not be empty.")

    if user_info.DOB == '':
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="The dob can not be empty.")

    # validate DOB date format
    try:
        bool(datetime.strptime(user_info.DOB, '%Y-%m-%d'))
    except ValueError:
        raise HTTPException(status_code=403, detail=f'DOB format not correct. Try Y-m-d.')

    if len(user_info.Gender) > 1:
        raise HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT,
                            detail="gender can either be M or F.")

    # check if the DOB contains any letters
    if not re.search(r"[A-Z a-z]", user_info.DOB) is None:
        raise HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT,
                            detail="DOB can not contains letters")

    # check if the student_cell_number contains any letters or special characters
    if not re.search(r"[ !@#$%&'()*+,-./[\\\]^_`{|}~A-Za-z" + r'"]', user_info.Cell_Number) is None:
        raise HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT,
                            detail="User cell number can not contains other character.")

    # check if the all cell number have 12 digits
    if len(user_info.Cell_Number) != 12:
        raise HTTPException(status_code=status.HTTP_206_PARTIAL_CONTENT,
                            detail="All cell numbers must be 12 characters starting with 263.")

    get_user = db.session.query(models.Users).filter(models.Users.Email == user_info.Email).first()

    if get_user:
        raise HTTPException(status_code=status.HTTP_226_IM_USED, detail=f'User email already in use.')

    # get  the current datetime
    current_date_time = datetime.now()

    # convert datetime to string format %Y/%m/%d %H:%M:%S
    user_created_at = current_date_time.strftime('%Y-%m-%d %H:%M:%S')

    # new generated user id
    user_id = id_generator('UID')

    # encrypt user password
    user_encrypted_password = pwd_context.encrypt(user_info.Password)

    # create new user in db
    new_user = models.Users(
        UID=user_id,
        First_Name=user_info.First_Name.capitalize(),
        Last_Name=user_info.Last_Name.capitalize(),
        Gender=user_info.Gender.capitalize(),
        DOB=user_info.DOB,
        Email=user_info.Email,
        Cell_Number=user_info.Cell_Number,
        Password=user_encrypted_password,
        Created_at=user_created_at,
        Updated_at='Null',
        Deleted_at='Null',
    )

    # add new user in db
    db.session.add(new_user)

    # commit new user (True = error, False = success)
    if db.session.commit():
        raise HTTPException(status_code=status.HTTP_200_OK,
                            detail="There was an error creating/saving the user record.")

    # create new user settings in db
    new_user_settings = models.Settings(
        UID=user_id,
        Is_enabled='disabled',
        Auth_type='basic',
        Acc_verified='verification code not yet generated',
        Text_alerts='disabled',
        Whatsapp_alerts='disabled',
        Email_alerts='enabled',
        Device_name=headers['device_name'],
        Device_id=headers['device_id'],
        Created_at=user_created_at,
        Updated_at='Null',
        Deleted_at='Null',
    )

    # add new user in db
    db.session.add(new_user_settings)

    # commit new user (True = error, False = success)
    if db.session.commit():
        raise HTTPException(status_code=status.HTTP_200_OK,
                            detail="There was an error creating/saving the user settings record.")

    # initializing number of characters in verification code
    v_code_length = 32

    generated_verification_code = ''.join(random.choices(string.ascii_lowercase + string.digits, k=v_code_length))

    # perform a background task to send an email
    background_task.add_task(sendEmailToGmailUser, 'eddietome@gmail.com', 'register', generated_verification_code)

    return {
        'status': 'successful',
        'message': f'We have sent you an email to finish verifying your account. '
                   f'Please check your inbox at {user_info.Email} and click the link provided.'
    }


def verify_a_registered_user(request, verification_code: str) -> dict:

    data = {'decision': 'invalid'}

    # search for user with matching verification_code
    user_settings = db.session.query(models.Settings).filter(
        models.Settings.Acc_verified == verification_code,
        models.Settings.Deleted_at == 'Null',
        models.Settings.Is_enabled == 'disabled').first()

    if user_settings:
        # get  the current datetime
        current_date_time = datetime.now()

        # convert datetime to string format %Y/%m/%d %H:%M:%S
        settings_updated_at = current_date_time.strftime('%Y-%m-%d %H:%M:%S')

        user_settings.Acc_verified = 'True'
        user_settings.Is_enabled = 'enabled'
        user_settings.Updated_at = settings_updated_at
        db.session.commit()

        data = {'decision': 'valid', 'username': user_settings.users.First_Name}

    return data


def resend_verification_code(user_email: str, background_task) -> dict:

    user = db.session.query(models.Users).filter(
        models.Users.Email == user_email,
        models.Users.Deleted_at == 'Null').first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='We do not seem to recognise your email.')

    for settings_list in user.user_settings:
        settings = settings_list

    verification_code = settings.Acc_verified

    # perform a background task to send an email
    background_task.add_task(sendEmailToGmailUser, user_email, 'register', verification_code)

    return {'message': f'We have resent your verification code to {user_email}. Please check your inbox.'}


def login_user(request: Request, background_task, form_data: OAuth2PasswordRequestForm) -> dict:
    # background_task.add_task(email.send_email, 'this is an email message')
    headers = registration_headers_check(request)


    user = db.session.query(models.Users).filter(models.Users.Email == form_data.username,
                                                 models.Users.Deleted_at == 'Null').first()

    # Check if the user details exists
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    # Verify if password matches
    pwd_match = pwd_context.verify(form_data.password, user.Password)

    # Check if the password match
    if not pwd_match:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    for setting_item in user.user_settings:
        settings = setting_item

    if settings.Auth_type == 'basic':

        token = create_access_token({'sub': user.Email})

        return {
            'message': 'success',
            'token': token,
            'token_type': 'Bearer',
            'authentication_type': settings.Auth_type
        }   # return token

    if settings.Auth_type == 'two-factor':

        if headers['authorization'] != 'requesting_otp' and not headers['authorization'].isdigit():
            raise HTTPException(status_code=400, detail="Please provide an authorization value of either"
                                                        " 'requesting_otp' or the actual 6 digit OTP its self.")

        # first we check if the authorization header is requesting an otp or wants to login with a given otp
        if headers['authorization'] == 'requesting_otp':

            # Generate a new OTP
            generated_otp = generate_otp(user.UID)

            # Get the current date time
            current_date_time = datetime.now()

            # convert datetime to string format %Y/%m/%d %H:%M:%S
            otp_created_at = current_date_time.strftime('%Y/%m/%d %H:%M:%S')

            # create new active otp session in db
            new_otp = models.OTP(
                User_id=user.UID,
                OTP=json.dumps(generated_otp),
                Token="default",
                State='active',
                Created_at=otp_created_at,
                Deleted_at='Null'

            )
            db.session.add(new_otp)
            db.session.commit()

            # send otp to enabled channels
            if settings.Email_alerts == 'enabled':

                # perform a background task to send an email
                background_task.add_task(sendEmailToGmailUser, user.Email, 'OTP', generated_otp['otp'])

                return {
                    'message': 'We have sent an OTP to your email. Please check your inbox.',
                    'authentication_type': settings.Auth_type
                }

            if settings.Whatsapp_alerts == 'enabled':

                message = f'*AUTHER*\n\n OTP REQUEST\n\n Hie {user.First_Name}\n\n' \
                          f' *Your OPT is {generated_otp["otp"]}*' \
                          f'\n\n\n _Please note that this OTP will expire {os.getenv("OTP_EXPIRE_MINUTES")} minutes from now._'
                # perform a background task to send an whatsapp
                background_task.add_task(send_whatsapp, message, user.Cell_Number)

                return {
                    'message': 'We have sent an OTP to your whatsapp. Please check your messages.',
                    'authentication_type': settings.Auth_type
                }  # return otp

            if settings.Text_alerts == 'enabled':
                message = f'AUTHER\n\n OTP REQUEST\n\n Hie {user.First_Name}\n\n' \
                          f' Your OPT is {generated_otp["otp"]}' \
                          f'\n\n\n Please note that this OTP will expire {os.getenv("OTP_EXPIRE_MINUTES")} minutes from now.'
                # perform a background task to send an whatsapp
                background_task.add_task(send_text, message, user.Cell_Number)

                return {
                    'message': 'We have sent an OTP text message to your phone number. Please check your messages.',
                    'authentication_type': settings.Auth_type
                }  # return otp

        if headers['authorization'].isdigit() and len(headers['authorization']) != 6:
            raise HTTPException(status_code=400, detail="Please provide a valid OTP of 6 numeric characters.")

        if headers['authorization'].isdigit():

            otp_from_request = headers['authorization']

            otp = db.session.query(models.OTP).filter(models.OTP.User_id == user.UID,
                                                      models.OTP.State == 'active').first()

            # Check if active otp session details exist
            if not otp:
                raise HTTPException(status_code=400, detail="You do not currently have an active OTP. "
                                                            "Consider logging in once more.")

            # Get the date at which the active otp was created
            otp_created_date = otp.Created_at

            # Convert the date in string format to date format
            parsed_otp_created_at = datetime.strptime(otp_created_date, '%Y/%m/%d %H:%M:%S')

            # Get the current date time
            current_date_time = datetime.now()

            # Get the difference between the current date time against the time the active otp session was created
            otp_session_time = int((current_date_time - parsed_otp_created_at).seconds / 60)

            # Check to verify if the otp_session_time is greater than 1 or x (as minutes)
            if otp_session_time > int(os.getenv('OTP_EXPIRE_MINUTES')):  # this is in minutes

                # Update the current active otp session to expire
                otp.State = "expired"
                db.session.commit()
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your Session has expired. "
                                                                                     "Consider logging in once more.")

            # Parse otp json string to json
            saved_otp_json = json.loads(otp.OTP)

            # Check if the active otp session in db matches the one provided by the user
            if saved_otp_json["otp"] != otp_from_request:
                raise HTTPException(status_code=400, detail="You have provided an invalid OTP.")

            # Create an access token
            access_token = create_access_token(data={'sub': user.UID})

            otp.State = 'expire'
            db.session.commit()

            return {
                'message': 'success',
                'token': access_token,
                'token_type': 'Bearer'
            }   # return token




def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES')))
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, os.getenv('SECRET_KEY'), algorithm=os.getenv('ALGORITHM'))
    return encoded_jwt


def verify_token(token: str):

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='could not validate credentials',
        headers={'WWW-Authenticate': 'Bearer'},
    )

    try:
        payload = jwt.decode(token, os.getenv('SECRET_KEY'), algorithms=[os.getenv('ALGORITHM')])

        verified_token: str = payload.get("sub")
        if verified_token is None:
            raise credentials_exception
        token_data = schema.TokenData(token_info=verified_token)
        return token_data
    except JWTError:
        raise credentials_exception


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials.',
        headers={'WWW-Authenticate': 'Bearer'},
    )

    # Check validity of token
    verify_token(token, credentials_exception)

    return 'token verified'


async def get_current_active_user(current_user_id: schema.User = Depends(get_current_user)):
    return 'user data'


def id_generator(id_type):
    # global check
    global new_id
    check = True
    loop_count = 0

    while check:
        new_id = f'{id_type}{random.randint(1000, 9999)}'
        if id_type == 'UID':
            verify_id = db.session.query(models.Users).filter(models.Users.UID == new_id).first()
        else:
            return 'GIDERR00'  # id type not recognised. Try UID

        if not verify_id:   # if id does not exist exit loop
            check = False

        if loop_count > 8999:
            check = False
            return 'GIDERR01'  # can not create id between range 1000 to 9999. They are all taken.

        loop_count += 1

    return new_id



