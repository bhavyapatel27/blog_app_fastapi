import re
from typing import Annotated

from fastapi import FastAPI, Depends, status, Body, Path
from passlib.hash import bcrypt
from pydantic import BaseModel
from sqlalchemy.orm import Session
from uvicorn import run

import CustomError
import models
from auth_bearer import JWTBearer
from database import engine, SessionLocal
from jwt_handler import signJWT

app = FastAPI()
models.Base.metadata.create_all(bind=engine)


class PostBase(BaseModel):
    title: str
    content: str
    user_id: str


class UserBase(BaseModel):
    email: str
    password: str
    username: str


class LoginBase(BaseModel):
    email: str
    password: str


class ResponseModel(BaseModel):
    data: dict = {}
    status: dict = {
        "code": 200,
        "description": "Successfully fetched",
        "status": "Success"
    }


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]


@app.post("/posts/", dependencies=[Depends(JWTBearer())], tags=["Create"], status_code=status.HTTP_201_CREATED)
async def create_post(post: PostBase):
    response = ResponseModel()
    db = SessionLocal()
    try:
        db_post = models.Post(**post.dict())
        handle_userid = post.user_id
        if post.user_id and post.title and post.content:
            db.add(db_post)
            db.commit()
            response.data = None
            response.status["code"] = status.HTTP_201_CREATED
            response.status["description"] = "Post Created"
            response.status["status"] = "Success"
        else:
            response.status["code"] = status.HTTP_400_BAD_REQUEST
            response.status["description"] = "Post Not Created"
            response.status["status"] = "Error"
    except CustomError.CustomError as e:
        response.data = None
        response.status['code'] = status.HTTP_400_BAD_REQUEST
        response.status['description'] = "Invalid userid"
        response.status['status'] = 'Error'
    finally:
        db.close()
    return response


@app.get("/posts/{post_id}", dependencies=[Depends(JWTBearer())], tags=["Get"], status_code=status.HTTP_200_OK)
async def read_post(post_id: int, db: db_dependency):
    response = ResponseModel()
    try:
        post = db.query(models.Post).filter(models.Post.id == post_id).first()
        if post:
            post_read = {
                "title": post.title,
                "content": post.content,
                "user_id": post.user_id
            }
            response.data = post_read
        else:
            response.data = None
            response.status['code'] = status.HTTP_400_BAD_REQUEST
            response.status['description'] = "Invalid post_id"
            response.status['status'] = 'Error'
    except CustomError.CustomError as e:
        response.data = None
        response.status['code'] = status.HTTP_400_BAD_REQUEST
        response.status['description'] = "Invalid post_id"
        response.status['status'] = 'Error'
    finally:
        db.close()
    return response


@app.delete("/posts/{post_id}", dependencies=[Depends(JWTBearer())], tags=["Delete"], status_code=status.HTTP_200_OK)
async def delete_post(post_id: int):
    response = ResponseModel()
    db = SessionLocal()
    try:
        db_post = db.query(models.Post).filter(models.Post.id == post_id).first()
        if db_post:
            db.delete(db_post)
            db.commit()
            deleted_post = {
                "id": post_id
            }
            response.data = deleted_post
            response.status["code"] = status.HTTP_302_FOUND
            response.status["status"] = "Deleted"
        else:
            response.data = None
            response.status['code'] = status.HTTP_400_BAD_REQUEST
            response.status['description'] = "Invalid post_id"
            response.status['status'] = 'Error'
    except CustomError.CustomError as e:
        response.data = None
        response.status['code'] = status.HTTP_400_BAD_REQUEST
        response.status['description'] = "Invalid post_id"
        response.status['status'] = 'Error'
    finally:
        db.close()
    return response


@app.post("/signup", tags=["Signup"], status_code=status.HTTP_201_CREATED)
async def create_user(user: UserBase):
    response = ResponseModel()
    db = SessionLocal()
    try:
        email = custom_email_validator(user.email)
        hashed_password = bcrypt.hash(user.password)
        user_verify = db.query(models.User).filter(models.User.email == email).first()
        db_user = models.User(email=email, password=hashed_password, username=user.username)
        if not user_verify:
            response.data = {"Message": "Signup Successfully"}
            db.add(db_user)
            db.commit()
        else:
            response.data = None
            response.status['code'] = status.HTTP_400_BAD_REQUEST
            response.status['description'] = "Invalid email format"
            response.status['status'] = 'Error'
    except CustomError.CustomError as e:
        response.data = None
        response.status['code'] = status.HTTP_400_BAD_REQUEST
        response.status['description'] = "Invalid Email Address"
        response.status['status'] = 'Error'
    finally:
        db.close()
    return response


@app.get("/users/{user_id}", dependencies=[Depends(JWTBearer())], tags=["Get"], status_code=status.HTTP_200_OK)
async def read_user(user_id: int):
    response = ResponseModel()
    db = SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if user:
            user_read = {
                "id": user.id,
                "email": user.email,
                "username": user.username,
                "password": user.password
            }
            response.data = user_read
        else:
            response.data = None
            response.status['code'] = status.HTTP_400_BAD_REQUEST
            response.status['description'] = "Invalid user_id"
            response.status['status'] = 'Error'
    except CustomError.CustomError as e:
        response.data = None
        response.status['code'] = status.HTTP_400_BAD_REQUEST
        response.status['description'] = "Invalid user_id"
        response.status['status'] = 'Error'
    finally:
        db.close()
    return response


@app.delete("/delete_user/users/{user_id}", dependencies=[Depends(JWTBearer())], tags=["Delete"],
            status_code=status.HTTP_200_OK)
async def delete_user(user_id: int = Path(..., title="The ID of user to delete")):
    response = ResponseModel()
    db = SessionLocal()
    try:
        db_user = db.query(models.User).filter(models.User.id == user_id).first()
        if db_user:
            db.delete(db_user)
            db.commit()
            deleted_response = {
                "id": user_id
            }
            response.data = deleted_response
            response.status["code"] = status.HTTP_302_FOUND
            response.status["status"] = "Deleted"
        else:
            response.data = None
            response.status['code'] = status.HTTP_400_BAD_REQUEST
            response.status['description'] = "Invalid user_id"
            response.status['status'] = 'Error'
    except CustomError.CustomError as e:
        response.data = None
        response.status['code'] = status.HTTP_400_BAD_REQUEST
        response.status['description'] = "Invalid user_id"
        response.status['status'] = 'Error'
    finally:
        db.close()
    return response


def custom_email_validator(value):
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if re.match(email_regex, value):
        return value
    else:
        raise CustomError.CustomError(status.HTTP_400_BAD_REQUEST, "Invalid email address")


@app.post("/login", tags=["login"], status_code=status.HTTP_200_OK)
async def login_user(email=Body(..., embed=True), password=Body(..., embed=True)):
    response = ResponseModel()
    db = SessionLocal()
    try:
        email = custom_email_validator(email)
        user = db.query(models.User).filter(models.User.email == email).first()
        check_password = bcrypt.verify(password, user.password)
        if user and check_password:
            user_response = {
                "id": user.id,
                "email": user.email,
                "username": user.username,
                "token": signJWT(user.email)['access_token']
            }
            response.data = user_response
        else:
            response.data = None
            response.status['code'] = status.HTTP_400_BAD_REQUEST
            response.status['description'] = "Invalid email or password"
            response.status['status'] = 'Error'
    except CustomError.CustomError as e:
        response.data = None
        response.status['code'] = status.HTTP_400_BAD_REQUEST
        response.status['description'] = "Invalid Email Address"
        response.status['status'] = 'Error'
    finally:
        db.close()
    return response

if __name__ == "__main__":
    run("main:app", host="127.0.0.1", port=3001)