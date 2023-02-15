import io
import json
import os
import smtplib
import ssl
from email.message import EmailMessage
from email.mime.application import MIMEApplication
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import qrcode
from utils import database as db
from utils import models
from functions.otp_functions import generate_otp_verification_link


def sendEmailToGmailUser(user_email, markupType, code):
    global subject
    global image_paths

    try:

        email_sender = 'authernticator@gmail.com'
        email_password = 'bggfxijiseiefqrl'
        email_receiver = user_email

        image_paths = ["static/qr_image.png"]

        if markupType == 'login':
            subject = 'Auther Login Verification'

        if markupType == 'register':
            subject = 'Auther Registration Verification'

        if markupType == 'OTP':
            subject = 'Auther OTP Request'

        body = '''
    
            <html>
                <head>
                <title>Page Title</title>
                </head>
    
                <body>
    
                    <h1>This is a Heading</h1>
                    <p>This is a paragraph.</p>
                    <p><b>This is a paragraph.</b></p>
    
                </body>
            </html>
        '''

        em = MIMEMultipart('alternative')
        em['from'] = email_sender
        em['To'] = email_receiver
        em['Subject'] = subject
        # em.set_content(body)

        # Create the body of the message (a plain-text and an HTML version).
        text = "Hi!\nHow are you?\nHere is the link you wanted:\nhttp://www.python.org"
        html = markupFor(markupType, user_email, code)

        counter = 1

        for fp in image_paths:
            fp = open(fp, 'rb')
            msgImage = MIMEImage(fp.read())
            fp.close()

            # Define the image's ID as referenced above

            msgImage.add_header('Content-ID', '<image' + str(counter) + '>')

            em.attach(msgImage)

            counter += 1

            # iterating through images to add as attachment

        for f in image_paths:
            attachment = MIMEApplication(open(f, "rb").read(), _subtype="txt")

            attachment.add_header('Content-Disposition', 'attachment', filename=f)
            em.attach(attachment)

        # Record the MIME types of both parts - text/plain and text/html.
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')

        # Attach parts into message container.
        # According to RFC 2046, the last part of a multipart message, in this case
        # the HTML message, is best and preferred.
        em.attach(part1)
        em.attach(part2)

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(email_sender, email_password)
            smtp.sendmail(email_sender, email_receiver, em.as_string())

    except Exception as e:
        print('email sending ', e)


def markupFor(markup_type, user_email, code):
    global image_paths


    if markup_type == 'register':
        register_verification_data = generate_registration_verification_link(user_email, code)
        verification_link = register_verification_data['verification_link']
        user_to_be_verified = register_verification_data['username']

        # Encoding data using make() function
        qrcode_img = qrcode.make(verification_link)

        # Saving as an image file
        qrcode_img.save(f'static/{user_email}.png')

        image_paths = [f"static/{user_email}.png"]


        return '    <html>' \
                     '      <head>' \
                     '        <style type="text/css">' \
                     '.logo-div{' \
                     '                background: #363636;' \
                     '                color:aliceblue;' \
                     '            }' \
                     '            .conatiner-center-div{' \
                     '                background: #363636;' \
                     '                width: 100%;' \
                     '                height: 50%;' \
                     '                border-radius: 8px;' \
                     '                overflow: hidden;' \
                     '            }' \
                     '            .container-body{' \
                     '                /* background: blue; */' \
                     '                width: 100%;' \
                     '                height: 100%;' \
                     '                color:aliceblue;' \
                     '            }' \
                     '            .container-body-center p{' \
                     '                /* background: green; */' \
                     '                width: 100%;' \
                     '            }' \
                     '            .container-body-center{' \
                     '                /* background: green; */' \
                     '                width: 100%;' \
                     '                color:aliceblue;' \
                     '                /* background-color: red; */' \
                     '                margin-right: 10px;' \
                     '            }' \
                     '            .confirm-btn{' \
                     '                /* background: green; */' \
                     '                width: 100px;' \
                     '                height: 30px;' \
                     '                color:green;' \
                     '                border-style: none;' \
                     '                border-radius: 4px;' \
                     '                text-decoration: none;' \
                     '                font-size: large;' \
                     '            }' \
                     '            .reject-btn{' \
                     '                /* background: red; */' \
                     '                width: 100px;' \
                     '                height: 80px;' \
                     '                color:red;' \
                     '                border-style: none;' \
                     '                border-radius: 4px;' \
                     '                text-decoration: none;' \
                     '                font-size: large;' \
                     '            }' \
                     '            </style>' \
                     '      </head>' \
                     '      <body>' \
                     '        <div class="container">' \
                     '            <div class="conatiner-center-div">' \
                     '                <div class="logo-div">' \
                     '                   <center><h1>AUTHER</h1></center> ' \
                     '                </div>' \
                     '                <div class="container-body">' \
                     '                    <div class="container-body-top">' \
                     f'                        <center><h3>Hie {user_to_be_verified}!</h3></center>' \
                     '                    </div>' \
                     '                       <div class="qrcode-div">'\
                     f'                       <center><img src="cid:image1" alt="qrcode" width="80" height="80"></center>'\
                     '  </div>'  \
                     '                    <div class="container-body-center">' \
                     '                        <center>' \
                     '                            <p>Your registration was successful. Continue by clicking confirm or scanning the qrcode, so that we can activate your profile.' \
                     '                            </p>' \
                     '                        </center>' \
                     '                    </div>' \
                     '                    <br>' \
                     '                    <div class="container-body-bottom">' \
                     '                       <center>' \
                     '                            <p>' \
                     f'                                <a href="{verification_link}" class="confirm-btn">CONFIRM</a>' \
                     '                            </p>' \
                     '                       </center> ' \
                     '                    </div>' \
                     '                </div>' \
                     '            </div>' \
                     '        </div>' \
                     '      </body>' \
                     '    </html>'

    if markup_type == 'OTP':
        otp_verification_data = generate_otp_verification_link(user_email)

        user_to_be_verified = otp_verification_data['username']     # username

        # Encoding data using make() function
        qrcode_img = qrcode.make(code)

        # Saving as an image file
        qrcode_img.save(f'static/{user_email}.png')

        image_paths = [f"static/{user_email}.png"]


        return '    <html>' \
                     '      <head>' \
                     '        <style type="text/css">' \
                     '.logo-div{' \
                     '                background: #363636;' \
                     '                color:aliceblue;' \
                     '            }' \
                     '            .conatiner-center-div{' \
                     '                background: #363636;' \
                     '                width: 100%;' \
                     '                height: 50%;' \
                     '                border-radius: 8px;' \
                     '                overflow: hidden;' \
                     '            }' \
                     '            .container-body{' \
                     '                /* background: blue; */' \
                     '                width: 100%;' \
                     '                height: 100%;' \
                     '                color:aliceblue;' \
                     '            }' \
                     '            .container-body-center p{' \
                     '                /* background: green; */' \
                     '                width: 100%;' \
                     '            }' \
                     '            .container-body-center{' \
                     '                /* background: green; */' \
                     '                width: 100%;' \
                     '                color:aliceblue;' \
                     '                /* background-color: red; */' \
                     '                margin-right: 10px;' \
                     '            }' \
                     '            .confirm-btn{' \
                     '                /* background: green; */' \
                     '                width: 100px;' \
                     '                height: 30px;' \
                     '                color:green;' \
                     '                border-style: none;' \
                     '                border-radius: 4px;' \
                     '                text-decoration: none;' \
                     '                font-size: large;' \
                     '            }' \
                     '            .reject-btn{' \
                     '                /* background: red; */' \
                     '                width: 100px;' \
                     '                height: 80px;' \
                     '                color:red;' \
                     '                border-style: none;' \
                     '                border-radius: 4px;' \
                     '                text-decoration: none;' \
                     '                font-size: large;' \
                     '            }' \
                     '            </style>' \
                     '      </head>' \
                     '      <body>' \
                     '        <div class="container">' \
                     '            <div class="conatiner-center-div">' \
                     '                <div class="logo-div">' \
                     '                   <center><h1>AUTHER</h1></center> ' \
                     '                </div>' \
                     '                <div class="container-body">' \
                     '                    <div class="container-body-top">' \
                     f'                        <center><h3>Hello {user_to_be_verified}!</h3></center>' \
                     '                    </div>' \
                     '                       <div class="qrcode-div">'\
                     f'                       <center><img src="cid:image1" alt="qrcode" width="80" height="80"></center>'\
                     '  </div>'  \
                     '                    <div class="container-body-center">' \
                     '                        <center>' \
                     f'                            <p><h1><b>Your OTP is {code}.' \
                     '                            <b></h1></p>' \
                     '                        </center>' \
                     '                    </div>' \
                     '                    <br>' \
                     '                    <div class="container-body-bottom">' \
                     '                       <center>' \
                     '                            <p>' \
                     f'                                This OTP will expire in {os.getenv("OTP_EXPIRE_MINUTES")} minutes from now.' \
                     '                            </p>' \
                     '                       </center> ' \
                     '                    </div>' \
                     '                </div>' \
                     '            </div>' \
                     '        </div>' \
                     '      </body>' \
                     '    </html>'


def generate_registration_verification_link(user_email, verification_code) -> dict:

    verification_link = f'http://192.168.1.107:8000/register/verify_user/{verification_code}'

    # set user verification code in db
    user = db.session.query(models.Users).filter(models.Users.Email == user_email).first()

    # get user settings from user relationship list
    for listItem in user.user_settings:
        settings = listItem

    # set verification code to user in db
    settings.Acc_verified = verification_code

    db.session.commit()

    return {'verification_link': verification_link, 'username': user.First_Name}


