from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


SQL_ALCHAMY_DATABASE_URL = f'mssql://user_one:12345678@SMPROVOC/auther_db?driver=ODBC Driver 17 for SQL Server'

engine = create_engine(SQL_ALCHAMY_DATABASE_URL, echo=False)

try:
    Session = sessionmaker(bind=engine)
    session = Session()

    #Base = declarative_base()
    #Base.metadata.create_all(engine)

except Exception as e:
    print('database error')
