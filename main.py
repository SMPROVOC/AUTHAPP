import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from routers import authentication, greeting, registration, users
from dotenv import load_dotenv
from utils import models, database as db

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

models.Base.metadata.create_all(db.engine)

load_dotenv(override=True)

# Set up routes
app.include_router(greeting.router)
app.include_router(authentication.router)
app.include_router(registration.router)
app.include_router(users.router)




if __name__ == '__main__':
    uvicorn.run(app)

