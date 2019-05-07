import os
    
POSTGRES = {
    'user': os.getenv('PSQL_USER'),
    'pw': os.getenv('PSQL_PWD'),
    'db': os.getenv('PSQL_DB'),
    'host': os.getenv('PSQL_HOST'),
    'port': os.getenv('PSQL_PORT'),
}

class Config(object):
    SECRET_KEY = os.getenv('SECRET_KEY') or 'abc'
    SQLALCHEMY_DATABASE_URI = 'postgresql://%(user)s:%(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    