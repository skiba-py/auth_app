import os
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request, Depends
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import jwt

DB_USER = os.getenv('DB_USER', 'user')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'password')
DB_HOST = os.getenv('DB_HOST', 'db')
DB_NAME = os.getenv('DB_NAME', 'app_db')
JWT_SECRET = os.getenv('JWT_SECRET', 'supersecret')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI()

class Message(Base):
    __tablename__ = 'messages'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    time = Column(DateTime, default=datetime.utcnow)
    message = Column(String, nullable=False)

class MessageCreate(BaseModel):
    message: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

Base.metadata.create_all(bind=engine)

@app.post('/post', status_code=201)
def post_message(req: Request, body: MessageCreate, db: Session = Depends(get_db)):
    authorization: str = req.headers.get('Authorization')
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(status_code=400)
    token = authorization.split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:  # проверка на истекший токен
        raise HTTPException(status_code=401)
    except jwt.InvalidTokenError:  # проверка на валидность токена
        raise HTTPException(status_code=400)
    user_id = payload.get('user_id')
    if not user_id:
        raise HTTPException(status_code=400)
    message = Message(user_id=user_id, message=body.message)
    db.add(message)
    db.commit()
    return {'user_id': user_id, 'message': message.message} if message else message.message
