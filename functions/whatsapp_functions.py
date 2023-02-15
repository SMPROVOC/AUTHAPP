#from twilio.rest import Client
from twilio.rest import Client


def send_whatsapp(message, phone_number):

    account_sid = 'AC254d852d324a64668d5bb71883bd0d5b'
    auth_token = '09c53407e515f7986e4227239eb0a92b'
    client = Client(account_sid, auth_token)

    message = client.messages.create(
        from_='whatsapp:+14155238886',
        body=f'{message}',
        to=f'whatsapp:+{phone_number}'
    )

    print(f'twilio message sid {message.sid}')