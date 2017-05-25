#! /usr/local/bin python
from __future__ import absolute_import
import os
import bcrypt
import ssl
import subprocess
import requests
import json
from flask import Flask, abort, request, jsonify, g, url_for, send_from_directory, render_template,redirect
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from sqlalchemy.dialects.postgresql import JSON
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

from flask_common import Common
from helpers import *

# initialization
app = Flask(__name__, static_url_path='/static', static_folder='static')
# app.debug = True
if not os.path.exists(os.path.abspath(".") + "/static/pdfs"):
    os.makedirs(os.path.abspath(".") + "/static/pdfs")

# extensions
CORS(app)
common = Common(app)
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

#constants
app.config.from_pyfile('config.py')

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
            if value or value == 0 or value == 0.0 :
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
    __public__ = ('id','user_id','url','read','tags','filepath','ratings')
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=False)
    url = db.Column(db.String(255), index=True, unique=True)
    read = db.Column(db.Boolean, default=False, unique=False)
    tags = db.Column(JSON)
    status = db.Column(db.String(10), default='Active')
    date_created = db.Column(db.DateTime, server_default=db.func.current_timestamp())
    last_updated = db.Column(db.DateTime, server_default=db.func.current_timestamp())
    filepath = db.Column(db.String(255))
    ratings = db.Column(db.Numeric(asdecimal= False, precision=10, scale=2,decimal_return_scale=None))
    def set_read_status(self, status):
        self.read = status
        self.status = 'Active'

    def set_ratings(self, ratings = 2.5):
        self.ratings = ratings

    @staticmethod
    def get_status_type(str):
        if str == '1' or str == 'true' or str == 't' or (isinstance(str,bool) and str):
            return True
        elif str == '0' or str == 'false' or str == 'f' or (isinstance(str,bool) and not str):
            return False
    
    @staticmethod
    def get_pdf_file(url):
        filepath = "/pdfs/" + url.split("/")[-1]
        resp = requests.get(url, stream=True)
        try:
            with open('static' + filepath, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=200):
                    f.write(chunk)
            return filepath
        except Exception, e:
            return e

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
@common.cache.cached(timeout=50)
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

@app.route('/api/post/<int:userid>',methods=['GET','POST'])
def add_post(userid):
    if request.method == 'POST':
        try:
            post_url = request.json.get('url')
            post_url = update_wikipedia_link(post_url)
            user_id = userid
            if post_url is None and user_id is None:
                abort(400)
            if Posts.query.filter_by(url=post_url).first() is not None:
                abort(400)
            post = Posts(url=post_url,user_id=user_id)
            post.set_read_status(False)
            post.set_ratings()
            db.session.add(post)
            db.session.commit()
            post = post.get_public()
            return jsonify({"post":post})
        except Exception, e:
            print e
            return "error"
    if request.method == 'GET':
        user_id = userid
        posts = Posts.query.filter_by(user_id=user_id).order_by("read asc, date_created asc").all()
        posts = [post.get_public() for post in posts]
        response = jsonify({"posts":posts})
        response = app.make_response(response)
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
    post = Posts.query.filter_by(id=postid).filter_by(user_id=userid).first()
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
@common.cache.cached(timeout=50)
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


@app.route('/api/topdf/<int:userid>/<int:postid>', methods=['GET'])
def get_post_as_pdf(userid, postid):
    posts = Posts.query.filter_by(user_id=userid).filter_by(id=postid).first()
    if posts is None:
        abort(400)
    parsed_url = urlparse(posts.url)
    url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
    if url.endswith(".pdf"):
        filename = Posts.get_pdf_file(url)
        print filename
        if isinstance(filename, Exception):
            abort(400)
    else :
        try:
            if url.endswith("/"):
                url = url[:-1]
            if parsed_url.path.endswith(".html") or parsed_url.path.endswith(".htm") or parsed_url.path.endswith("."):
                filename = "/pdfs/" + parsed_url.path.split("/")[-1].split(".")[0] + ".pdf"
                print filename
            else:
                filename = "/pdfs/" + url.split("/")[-1] + '.pdf'
            print_to_pdf = '--print-to-pdf=static' + filename
            chrome_canary = '/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary'
            cmds = [chrome_canary, '--headless','--disable-gpu',print_to_pdf, url]
            subprocess.call(cmds)
        except Exception,e :
            print(e)
            abort(400, e)
    posts.filepath = filename
    db.session.commit()
    return jsonify({"filepath": posts.filepath})

@app.route('/api/ratings/<int:userid>/<int:postid>', methods=['PUT','POST'])
def update_ratings(userid, postid):
    post = Posts.query.filter_by(user_id=userid).filter_by(id=postid).first()
    if post is None:
        abort(400)
    if 'rating' not in request.json:
        abort(400)
    ratings = request.json.get('rating')
    post.set_ratings(ratings)
    db.session.commint()
    return jsonify({"status":"ok"})

@app.route('/api/posts/latest', methods=['GET'])
@common.cache.cached(timeout=100)
def get_k_latest_posts():
    k = 10
    if 'k' in request.args:
        k = int(request.args.get("k"))
    posts = Posts.query.filter_by(user_id=1).filter_by(status='Active')\
            .filter_by(read=False).order_by("date_created desc").limit(k)
    posts = [post.get_public() for post in posts]
    return jsonify({"posts":posts})

@app.route('/api/test', methods=['GET'])
def test_route():
    try:
        print("ACTApp %s", request.cookies['ACTApp'])
    except KeyError:
        print("No Cookie found")
    return jsonify({"test":"ok"})

if __name__ == '__main__':
    common.serve()