import os

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from utils import logger as log
from dotenv import load_dotenv
load_dotenv(override=True)


try:


    SQL_ALCHAMY_DATABASE_URL = os.getenv("SQL_ALCHAMY_DATABASE_URL")

    engine = create_engine(SQL_ALCHAMY_DATABASE_URL, echo=False)

    Session = sessionmaker(bind=engine)
    session = Session()


    Base = declarative_base()
    Base.metadata.create_all(engine)

except Exception as e:
    log.events_logger.warning(f'[database connection] {e.args[0]}')

