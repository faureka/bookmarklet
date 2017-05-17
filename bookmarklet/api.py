#!/usr/bin/env python
from __future__ import absolute_import
import os
from flask import Flask, abort, request, jsonify, g, url_for, render_template, send_from_directory
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.httpauth import HTTPBasicAuth
from flask import render_template, flash, redirect
from sqlalchemy.dialects.postgresql import JSON
from forms import LoginForm
import bcrypt
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

# initialization
app = Flask(__name__, static_url_path='', static_folder='static')
app.config.from_pyfile('config.py')

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

class AutoSerialize(object):
    'Mixin for retrieving public fields of model in json-compatible format'
    __public__ = None

    def get_public(self, exclude=(), extra=()):
        "Returns model's PUBLIC data for jsonify"
        data = {}
        keys = self._sa_instance_state.attrs.items()
        public = self.__public__ + extra if self.__public__ else extra
        for k, field in  keys:
            if public and k not in public: continue
            if k in exclude: continue
            value = self._serialize(field.value)
            if value:
                data[k] = value
        return data

    @classmethod
    def _serialize(cls, value, follow_fk=False):
        # if type(value) in (datetime, date):
        #     ret = value.isoformat()
        if hasattr(value, '__iter__'):
            ret = []
            for v in value:
                ret.append(cls._serialize(v))
        elif AutoSerialize in value.__class__.__bases__:
            ret = value.get_public()
        else:
            ret = value

        return ret


class User(db.Model, AutoSerialize):
    __tablename__ = 'users'
    __public__ = ('id','username','token')
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))
    token = db.Column(db.String(255))

    def hash_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def verify_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        self.token = s.dumps({'id': self.id})
        return s.dumps({'id': self.id})
    def get_auth_token(self):
        return self.token
    
    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        if token != user.token:
            return None
        return user

class Posts(db.Model, AutoSerialize):
    __tablename__ = 'posts'
    __public__ = ('id','user_id','url','read','tags')
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=False)
    url = db.Column(db.String(255), index=True, unique=True)
    read = db.Column(db.Boolean, default=False, unique=False)
    tags = db.Column(JSON)
    status = db.Column(db.String(10), default='Active')
    date_created = db.Column(db.DateTime, server_default=db.func.current_timestamp())
    last_updated = db.Column(db.DateTime, server_default=db.func.current_timestamp())

    def set_read_status(self, status):
        self.read = status
        self.status = 'Active'

    @staticmethod
    def get_status_type(str):
        if str == '1' or str == 'true' or str == 't' or (isinstance(str,bool) and str):
            return True
        elif str == '0' or str == 'false' or str == 'f' or (isinstance(str,bool) and not str):
            return False


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@app.route('/',methods=["GET"])
def index():
    user_id = request.args["userid"]
    posts = Posts.query.filter_by(user_id=user_id).filter_by(status='Active').order_by("read asc, date_created asc").all()
    posts = [post.get_public() for post in posts]
    return render_template('index.html', entries=posts, userid=user_id)

@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
    user = User(username=username)
    user.hash_password(password)
    user.generate_auth_token(600)
    db.session.add(user)
    db.session.commit()
    response = jsonify({'username': user.username})
    response = app.make_response(response)
    act_app_cookie = {"uname":user.username, "uid":user.id}
    response.set_cookie('ACTApp',value=user.id, max_age=30000000, secure=True)
    response.set_cookie('authToken',value=user.token, max_age=600, secure=True)
    response.status_code = 201
    return response


@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    user = User.query.get(id)
    if not user:
        abort(400)
    token = user.token.decode('ascii')
    response = jsonify({'token': token, 'duration': 600})
    response = app.make_response(response)
    response.status_code = 200
    return response


@app.route('/api/resource')
def get_resource():
    if 'ACTApp' not in request.cookies or 'authToken' not in request.cookies:
        abort(400)
    token = request.cookies['authToken']
    user = User.query.get(token)
    if not user:
        abort(400)
    return jsonify({'data': 'Hello, %s!' % user.username})

@app.route('/api/post/<int:userid>',methods=['GET','POST','OPTIONS'])
def add_post(userid):
    if request.method == 'POST':
        post_url = request.json.get('url')
        user_id = userid
        if post_url is None and user_id is None:
            abort(400)
        if Posts.query.filter_by(url=post_url).first() is not None:
            abort(400)
        post = Posts(url=post_url,user_id=user_id)
        post.set_read_status(False)
        db.session.add(post)
        db.session.commit()
        response = app.make_response(jsonify({"post_url":post.url, "post_date_created": post.date_created}))
        response.headers['Access-Control-Allow-Origin'] = "*"
        response.headers['Access-Control-Allow-Headers'] = "Origin, X-Requested-With, Content-Type, Accept"
        return jsonify({"post_url":post.url, "post_date_created": post.date_created})
    if request.method == 'GET':
        user_id = userid
        posts = Posts.query.filter_by(user_id=user_id).order_by("read asc, date_created asc").all()
        posts = [post.get_public() for post in posts]
        response = jsonify({"posts":posts})
        response = app.make_response(response)
        return response
    if request.method == 'OPTIONS':
        response = app.make_response("")
        response.headers['Access-Control-Allow-Origin'] = "*"
        response.headers['Access-Control-Allow-Headers'] = "Origin, X-Requested-With, Content-Type, Accept"
        return response

@app.route('/api/post/status/<int:userid>/<int:postid>',methods=['GET','PUT','DELETE'])
def update_post_status(userid, postid):
    status = False
    if request.method == 'GET':
        if 'status' not in request.args:
            abort(400)
        status = Posts.get_status_type(request.args['status'])
    if request.method == 'PUT':
        status = request.json.get('status')
        if status is None:
            abort(400)
        status = Posts.get_status_type(status)
    if request.method == 'DELETE':
        post = Posts.query.filter_by(id=postid).filter_by(user_id=userid).filter_by(status='Active').first()
        if post is None:
            abort(400)
        post.last_updated = db.func.current_timestamp()
        post.status = 'Inactive'
        db.session.commit()
        return "ok"
    post = Posts.query.filter_by(id=postid).first()
    if post is None:
        abort(400)
    post.last_updated = db.func.current_timestamp()
    post.read = status
    db.session.commit()
    return jsonify({"url":post.url,"status":post.read,"last_updated":post.last_updated})

@app.route('/api/tags', methods=['GET','POST','PUT'])
def add_update_get_tags():
    if request.method == 'GET':
        return "Return tags"
    if request.method == 'POST':
        post_id = request.json.get("post_id")
        tags = request.json.get("tags")
        return "Return tags added"
    if request.method == 'PUT':
        post_id = request.json.get("post_id")
        tags = request.json.get("tags")
        return "ok"

@app.route('/api/search', methods=['GET'])
def search():
    query = request.args['q']
    userid = request.args['uid']
    query = "%{}%".format(query)
    posts = Posts.query.filter(Posts.url.ilike(query)).order_by("read asc, date_created asc").all()
    posts = [post.get_public() for post in posts]
    return render_template('index.html', entries=posts, userid=userid)

@app.route('/archive', methods=['GET'])
def archived_post():
    userid = request.args['userid']
    posts = Posts.query.filter_by(user_id=userid).filter_by(status='Inactive').order_by('last_updated asc').all()
    posts = [post.get_public() for post in posts]
    return render_template('archive.html',entries=posts, userid=userid)
@app.route('/api/post/unarchive/<int:userid>/<int:postid>', methods=['GET'])
def unarchive_post(userid, postid):
    posts = Posts.query.filter_by(user_id=userid).filter_by(id=postid).filter_by(status='Inactive').first()
    if posts is None:
        abort(400)
    posts.status = 'Active'
    posts.last_updated = db.func.current_timestamp()
    db.session.commit()
    return ""

@app.route('/api/test', methods=['GET'])
def test_route():
    try:
        print("ACTApp %s", request.cookies['ACTApp'])
    except KeyError:
        print("No Cookie found")
    return jsonify({"test":"ok"})



if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
