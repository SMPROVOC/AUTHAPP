import os
import io
import random
import base64
import qrcode

from utils import schema, models, database as db


def generate_otp(user_uid):

    # Check for any active otp sessions for this specific user
    active_otp = db.session.query(models.OTP).filter(models.OTP.User_id == user_uid, models.OTP.State == 'active')

    # loop through all active sessions for the specific user to expire them
    for otps in active_otp:

        if otps.State == 'active':
            otp = db.session.query(models.OTP).filter(
                models.OTP.User_id == user_uid, models.OTP.State == 'active').first()
            otp.State = "expired"
            db.session.commit()

    # Numbers used to generate otp
    otp_characters = os.getenv('OTP_CHARACTERS')

    # Defining number of character to create otp
    length_for_otp = int(os.getenv('OTP_STRING_LENGTH'))

    # Randomize the numbers
    otp = "".join(random.sample(otp_characters, length_for_otp))

    # Create qrcode from otp string
    otp_qrcode = qrcode.make(otp)

    # Convert image to bytes
    img_byte_arr = io.BytesIO()

    # Save image as PNG, JPEG, JPG
    otp_qrcode.save(img_byte_arr, format=os.getenv('OTP_QRCODE_IMG_FORMAT'))
    img_byte_arr = img_byte_arr.getvalue()

    return {
        "otp": otp,
        "base64_otp_qrcode": f"{base64.b64encode(img_byte_arr)}",
    }


def verify_otp():
    pass


def generate_otp_verification_link(user_email) -> dict:

    # get user name
    user = db.session.query(models.Users).filter(models.Users.Email == user_email).first()

    return {'username': user.First_Name}