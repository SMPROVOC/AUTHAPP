from twilio.rest import Client


def send_text(message: str, phone_number: str):

    account_sid = 'AC254d852d324a64668d5bb71883bd0d5b'
    auth_token = '09c53407e515f7986e4227239eb0a92b'
    client = Client(account_sid, auth_token)

    message = client.messages.create(
        messaging_service_sid='MGd80849774907dbec5dcc97d4de953424',
        body=message,
        to=f'+{phone_number}'
    )

    print(message.sid)
