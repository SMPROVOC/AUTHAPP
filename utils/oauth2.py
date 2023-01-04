from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from utils import functions

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='login')


def get_current_user(token: str = Depends(oauth2_scheme)):

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='could not validate credentials',
        headers={'WWW-Authenticate':'Bearer'},
    )

    c = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI4NzIzNDUiLCJleHAiOjE2NjQxMjUyNDV9.JW3Kjr55fQ_7lwQ53pwOpBEvETEiPYS8mwp7SRG7Wd4'

    # functions.verify_token(c, credentials_exception)

