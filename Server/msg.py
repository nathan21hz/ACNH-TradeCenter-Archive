#coding:utf-8

from flask import Flask,make_response,request
from flask_pymongo import PyMongo, DESCENDING
from bson import ObjectId
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import time
import datetime
import random
from hashlib import sha1

TZ = 8

#MongoDB Config
MONGO_URI = ""

app = Flask(__name__)
app.config["MONGO_URI"] = MONGO_URI
mongo = PyMongo(app)

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["3/second"]
)

@app.before_request
def before_request():
    baned = mongo.db.banip.find_one({"ip":request.remote_addr})
    if baned == None:
        return None
    else:
        response = make_response('IP Banned')
        return response, 403


@app.route('/turniptrade/island/<island_id>/sendMsg',methods = ['POST'])
def island_sendMsg(island_id):
    req_json = json.loads(request.get_data())
    text = req_json.get("text")
    token = request.args.get("token")
    island_info = mongo.db.island.find_one({"_id":ObjectId(island_id),"token":token})
    if island_info == None:
        res_data = {
            "status":4,
            "msg":"未找到指定岛屿或鉴权错误"
        }
    elif text=="" or text==None:
        res_data = {
            "status":5,
            "msg":"输入错误"
        }
    else:
        mongo.db.message.insert_one({
            "island":island_info["_id"],
            "time":datetime.datetime.now() + datetime.timedelta(hours=TZ),
            "from_type":0,
            "from_id":island_info["_id"],
            "from_name":island_info["name"],
            "text":text
            })
        res_data = {
            "status":0,
            "msg":"ok"
        }
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)

@app.route('/turniptrade/seller/<seller_id>/sendMsg',methods = ['POST'])
def seller_sendMsg(seller_id):
    req_json = json.loads(request.get_data())
    text = req_json.get("text")
    seller_info = mongo.db.seller.find_one({"_id":ObjectId(seller_id)})
    if seller_info == None:
        res_data = {
            "status":4,
            "msg":"连接已断开，请刷新页面后再试"
        }
    elif text=="" or text==None:
        res_data = {
            "status":5,
            "msg":"输入错误"
        }
    elif seller_info["island"] == None:
        res_data = {
            "status":6,
            "msg":"尚未加入岛屿"
        }
    else:
        mongo.db.message.insert_one({
            "island":seller_info["island"],
            "time":datetime.datetime.now() + datetime.timedelta(hours=TZ),
            "from_type":1,
            "from_id":seller_info["_id"],
            "from_name":seller_info["name"],
            "text":text
            })
        res_data = {
            "status":0,
            "msg":"ok"
        }
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)

@app.route('/turniptrade/getMsg/<island_id>',methods = ['GET'])
def getMsg(island_id):
    msgs = mongo.db.message.find({"island":ObjectId(island_id)}).sort("time", DESCENDING).limit(10)
    msg_list = []
    for msg in msgs:
        msg_list.append({
            "island":str(msg["island"]),
            "time":msg["time"].strftime("%m-%d %H:%M:%S"),
            "from_type":msg["from_type"],
            "from_id":str(msg["from_id"]),
            "from_name":msg["from_name"],
            "text":msg["text"]
            })
    res_data = {
        "status":0,
        "msg":"ok",
        "msg_list":msg_list
    }
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)


def handler(environ, start_response):
    # maybe pre do something here
    return app(environ, start_response)

#from flask_cors import CORS
#CORS(app, supports_credentials=True)
#app.run(host='0.0.0.0',port=80,debug=True)