#coding:utf-8

from flask import Flask,make_response,request
from flask_pymongo import PyMongo
from bson import ObjectId
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import time
import datetime
import random
from hashlib import sha1,md5
import requests
import base64

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

@limiter.request_filter
def ip_whitelist():
    return request.remote_addr == "124.243.251.15"

def addAudit(content):
    base64content = base64.b64encode(content.encode(encoding='utf-8')).decode()

    current_ts = str(int(time.time()))

    checksum_text = "{}\t{}\t{}\t{}\t{}".format("21526030","2342912",current_ts,"gtre4watg5r4eawghbt4r",base64content)
    checksum_text_b = checksum_text.encode(encoding='utf-8')
    checksum = md5(checksum_text_b).hexdigest()

    result = requests.post(
        url="https://bbs.nga.cn/nuke.php?__lib=post_from_api&__act=new_post&__output=11",
        data={
            "uid":"2342912",
            "tid":"21526030",
            "base64content":base64content,
            "charset":"utf8",
            "time":current_ts,
            "checksum":checksum
        }
    )
    return str(result.json()["data"][0])

def auditResult(pid=""):
    if pid=="":
        return 3
    tid = "21526030"
    current_ts = str(int(time.time()))
    checksum_text = "{}\t{}\t{}\t{}".format(tid,pid,current_ts,"gtre4watg5r4eawghbt4r")
    checksum_text_b = checksum_text.encode(encoding='utf-8')
    checksum = md5(checksum_text_b).hexdigest()

    a = requests.post(
        url="https://bbs.nga.cn/nuke.php?__lib=post_from_api&__act=get_audit_stat&__output=11",
        data={
            "tid":tid,
            "pid":pid,
            "time":current_ts,
            "checksum":checksum
        }
    )

    if pid in a.json()["data"][0]:
        return a.json()["data"][0][pid]
    else:
        return 0

@app.before_request
def before_request():
    if request.headers.get("CLIENT-IP"):
        _ip = request.headers.get("CLIENT-IP")
    else:
        _ip = request.remote_addr
    baned = mongo.db.banip.find_one({"ip":_ip})
    if baned == None:
        return None
    else:
        response = make_response('IP Banned')
        return response, 403

#Island Owner
@app.route('/turniptrade/island/init',methods = ['GET'])
def island_init():
    if request.headers.get("CLIENT-IP"):
        _ip = request.headers.get("CLIENT-IP")
    else:
        _ip = request.remote_addr
    token = sha1((str(random.random())+str(datetime.datetime.now())).encode()).hexdigest()
    insert = mongo.db.island.insert_one({
        "status":0,
        "name":"",
        "last_heartbeat":datetime.datetime.now(),
        "price":0,
        "password":"",
        "remark":"",
        "sellers":[],
        "queue":[],
        "ip":_ip,
        "token":token,
        "audit":4,
        "pid":None
    })
    res_data = {
        "status":0,
        "msg":"临时无人岛创建",
        "island_id":str(insert.inserted_id),
        "token":token
    }
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)


@app.route('/turniptrade/island/<island_id>/status',methods = ['GET'])
def island_status(island_id):
    token = request.args.get("token")
    island_info = mongo.db.island.find_one({"_id":ObjectId(island_id),"token":token})
    if island_info == None:
        res_data = {
            "status":4,
            "msg":"未找到指定岛屿或鉴权错误"
        }
    else:
        ###################
        #Add Audit Part
        if island_info["audit"] == 2:
            audit_result = auditResult(island_info["pid"])
            mongo.db.island.update_one({"_id":ObjectId(island_id)},{"$set":{
                "last_heartbeat":datetime.datetime.now(),
                "audit":audit_result
                }})
        else:
            audit_result = island_info["audit"]
            mongo.db.island.update_one({"_id":ObjectId(island_id)},{"$set":{
                "last_heartbeat":datetime.datetime.now(),
                }})
        ###################
        sellers = []
        queue = []
        if island_info["status"] == 1:
            for s in island_info["sellers"]:
                seller_info = mongo.db.seller.find_one({"_id":s})
                sellers.append({
                    "seller_id":str(seller_info["_id"]),
                    "name":seller_info["name"],
                    "join_time":int(time.mktime(seller_info["last_trade"].timetuple()))
                    # TODO: Return join time to islang owner
                    })
            for q in island_info["queue"]:
                seller_info = mongo.db.seller.find_one({"_id":q})
                queue.append({
                    "seller_id":str(seller_info["_id"]),
                    "name":seller_info["name"]
                    })

        res_data = {
            "island_id":island_id,
            "status":island_info["status"],
            "sellers":sellers,
            "queue":queue,
            "msg":"ok",
            "audit":audit_result
        }
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)

#0 Success;4 Not Found;5 Already Open;6Input Error
@app.route('/turniptrade/island/<island_id>/open',methods = ['POST'])
def island_open(island_id):
    req_json = json.loads(request.get_data())
    name = req_json.get("name")
    price = req_json.get("price")
    password = req_json.get("password")
    remark = req_json.get("remark")
    max_seller = req_json.get("max_seller")
    catalog = req_json.get("catalog")
    private = req_json.get("private")
    if max_seller == None:
        max_seller = 6
    token = request.args.get("token")
    island_info = mongo.db.island.find_one({"_id":ObjectId(island_id),"token":token})
    if island_info == None:
        res_data = {
            "status":4,
            "msg":"未找到指定岛屿或鉴权错误"
        }
    else:
        if island_info["status"] == 1:
           res_data = {
                "status":5,
                "msg":"岛屿已打开"
            } 
        elif island_info["status"] == 0:
            price = int(price)
            if name=="" or price=="" or password=="" or max_seller>6 or max_seller<1 or len(catalog)==0 or price>660 or price<0:
                res_data = {
                    "status":6,
                    "msg":"输入错误"
                } 
            else: 
                temp_cat = []
                for c in catalog:
                    temp_cat.append(c[-1])
                ###################
                #Add Audit Part
                pid = addAudit(name+","+remark)
                ###################
                mongo.db.island.update_one({"_id":ObjectId(island_id)},{"$set":{
                    "status":1,
                    "name":name,
                    "price":price,
                    "password":password,
                    "remark":remark,
                    "last_heartbeat":datetime.datetime.now(),
                    "last_open":datetime.datetime.now(),
                    "max_seller":max_seller,
                    "catalog":temp_cat,
                    "private":private,
                    "pid":pid,
                    "audit":2
                }})
                res_data = {
                    "status":0,
                    "msg":"岛屿开放成功"
                }
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)


#0 Success;4 Not Found;5 Already Open;6Input Error
@app.route('/turniptrade/island/<island_id>/close',methods = ['POST'])
def island_close(island_id):
    token = request.args.get("token")
    island_info = mongo.db.island.find_one({"_id":ObjectId(island_id),"token":token})
    if island_info == None:
        res_data = {
            "status":4,
            "msg":"未找到指定岛屿或鉴权错误"
        }
    else:
        if island_info["status"] == 0:
           res_data = {
                "status":5,
                "msg":"岛屿已经关闭"
            } 
        elif island_info["status"] == 1:
            mongo.db.island.update_one({"_id":ObjectId(island_id)},{"$set":{
                "status":0,
                "last_heartbeat":datetime.datetime.now(),
                "sellers":[],
                "queue":[],
                "audit":4
            }})
            mongo.db.seller.update_many({"island":ObjectId(island_id)},{"$set": {
                "status":0,
                "island":None
            }})
            res_data = {
                "status":0,
                "msg":"岛屿关闭成功"
            }
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)

@app.route('/turniptrade/island/<island_id>/update',methods = ['POST'])
def island_update(island_id):
    req_json = json.loads(request.get_data())
    name = req_json.get("name")
    price = req_json.get("price")
    password = req_json.get("password")
    remark = req_json.get("remark")
    max_seller = req_json.get("max_seller")
    private = req_json.get("private")
    catalog = req_json.get("catalog")
    if max_seller == None:
        max_seller = 6
    token = request.args.get("token")
    island_info = mongo.db.island.find_one({"_id":ObjectId(island_id),"token":token})
    if island_info == None:
        res_data = {
            "status":4,
            "msg":"未找到指定岛屿或鉴权错误"
        }
    else:
        if island_info["status"] == 0:
           res_data = {
                "status":5,
                "msg":"岛屿未打开"
            } 
        elif island_info["status"] == 1:
            price = int(price)
            if name=="" or price=="" or password=="" or max_seller>6 or max_seller<1 or len(catalog)==0 or price>660 or price<0:
                res_data = {
                    "status":6,
                    "msg":"输入错误"
                } 
            else:
                temp_cat = []
                for c in catalog:
                    temp_cat.append(c[-1])
                ###########################
                pid = addAudit(name+","+remark)
                ###########################
                mongo.db.island.update_one({"_id":ObjectId(island_id)},{"$set":{
                    "name":name,
                    "price":price,
                    "password":password,
                    "remark":remark,
                    "last_heartbeat":datetime.datetime.now(),
                    "max_seller":max_seller,
                    "private":private,
                    "catalog":temp_cat,
                    "pid":pid,
                    "audit":2
                }})
                res_data = {
                    "status":0,
                    "msg":"岛屿开放成功"
                }
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)

@app.route('/turniptrade/island/<island_id>/report',methods = ['POST'])
def island_report(island_id):
    req_json = json.loads(request.get_data())
    seller_id = req_json.get("seller_id")
    token = request.args.get("token")
    r_type = req_json.get("r_type")
    r_msg = req_json.get("r_msg")
    island_info = mongo.db.island.find_one({"_id":ObjectId(island_id),"token":token})
    if island_info == None:
        res_data = {
            "status":4,
            "msg":"未找到指定岛屿或鉴权错误"
        }
    else: 
        seller_info = mongo.db.seller.find_one({"_id":ObjectId(seller_id)})
        if seller_info == None:
            res_data = {
                "status":6,
                "msg":"未找到指定股民"
            }
        else:
            mongo.db.report.insert_one({
                        "time":datetime.datetime.now(),
                        "from_name":island_info["name"],
                        "from_ip":island_info["ip"],
                        "seller_name":seller_info["name"],
                        "seller_ip":seller_info["ip"],
                        "report_type":r_type,
                        "report_msg":r_msg
                        })
            res_data = {
                "status":0,
                "msg":"举报成功 我们将核实后进行处理"
            }
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)

@app.route('/turniptrade/island/<island_id>/kick',methods = ['POST'])
def island_kick(island_id):
    req_json = json.loads(request.get_data())
    seller_id = req_json.get("seller_id")
    token = request.args.get("token")
    island_info = mongo.db.island.find_one({"_id":ObjectId(island_id),"token":token})
    if island_info == None:
        res_data = {
            "status":4,
            "msg":"未找到指定岛屿或鉴权错误"
        }
    else: 
        seller_info = mongo.db.seller.find_one({"_id":ObjectId(seller_id)})
        if seller_info == None:
            res_data = {
                "status":6,
                "msg":"未找到指定股民"
            }
        else:
            mongo.db.island.update_one({"_id":ObjectId(island_id)},{ "$pull":{"sellers":ObjectId(seller_id)}})
            mongo.db.seller.update_one({"_id":seller_info["_id"]},{"$set":{
                "status":0,
                "island":None,
                "last_trade":datetime.datetime.fromtimestamp(0.0)
            }})

            if len(island_info["queue"]) > 0 and len(island_info["sellers"]) <= island_info["max_seller"]:
                new_seller = island_info["queue"][0]
                mongo.db.seller.update_one({"_id":new_seller},{"$set":{
                    "status":1,
                    "last_trade":datetime.datetime.now()
                }})
                mongo.db.island.update_one({"_id":seller_info["island"]},{"$addToSet":{"sellers":new_seller}})
                mongo.db.island.update_one({"_id":seller_info["island"]},{ "$pull":{"queue":new_seller}})

            res_data = {
                "status":0,
                "msg":"Success"
            }
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)

@app.route('/turniptrade/island/list/<page>',methods = ['GET'])
def island_list(page):
    catalog = request.args.get("cat")
    ###################
    #Add Audit Part
    ###################
    if catalog==None or catalog=="":
        find_dic = {"status":1,"private":False,"audit":0}
    else:
        catalog = [int(c) for c in catalog.split(",")]
        find_dic = {"status":1,"private":False,"catalog":{"$in":catalog},"audit":0}
    page = int(page)
    i_list = []
    islands = mongo.db.island.find(find_dic)
    for i in islands:
        i_list.append({
            "island_id":str(i["_id"]),
            "name":i["name"],
            "price":i["price"],
            "remark":i["remark"],
            "seller_count":len(i["sellers"]),
            "queue_length":len(i["queue"]),
            "max_seller":i.get("max_seller"),
            "catalog":i.get("catalog")
        })
    res_data = {
        "status":0,
        "msg":"ok",
        "list":i_list
    }
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)


#Turnip Seller
@app.route('/turniptrade/seller/init',methods = ['GET'])
def seller_init():
    if request.headers.get("CLIENT-IP"):
        _ip = request.headers.get("CLIENT-IP")
    else:
        _ip = request.remote_addr
    insert = mongo.db.seller.insert_one({
        "status":0,
        "last_heartbeat":datetime.datetime.now(),
        "last_trade":datetime.datetime.fromtimestamp(0.0),
        "name":"",
        "island":None,
        "ip":_ip
    })
    res_data = {
        "status":0,
        "msg":"临时股民创建成功",
        "seller_id":str(insert.inserted_id)
    }
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)


@app.route('/turniptrade/seller/<seller_id>/status',methods = ['GET'])
def seller_status(seller_id):
    seller_info = mongo.db.seller.find_one({"_id":ObjectId(seller_id)})
    if seller_info == None:
        res_data = {
            "status":4,
            "msg":"未找到股民，请刷新页面后再试"
        }
    else:
        mongo.db.seller.update_one({"_id":ObjectId(seller_id)},{"$set":{
            "last_heartbeat":datetime.datetime.now(),
        }})
        island_info = {}
        if seller_info["status"] == 1:
            island_data = mongo.db.island.find_one({"_id":seller_info["island"]})
            island_info = {
                "island_id":str(island_data["_id"]),
                "name":island_data["name"],
                "price":island_data["price"],
                "remark":island_data["remark"],
                "password":island_data["password"],
                "catalog":island_data["catalog"]
            }
        if seller_info["status"] == 2:
            island_data = mongo.db.island.find_one({"_id":seller_info["island"]})
            queue_pos = 0
            for q in island_data["queue"]:
                queue_pos += 1
                if str(q) == seller_id:
                    break
            island_info = {
                "island_id":str(island_data["_id"]),
                "name":island_data["name"],
                "price":island_data["price"],
                "remark":island_data["remark"],
                "queue_pos":queue_pos,
                "queue_length":len(island_data["queue"]),
                "catalog":island_data["catalog"]
            }
        res_data = {
            "seller_id":seller_id,
            "status":seller_info["status"],
            "island":island_info,
            "msg":"ok"
        }
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)


@app.route('/turniptrade/seller/<seller_id>/join',methods = ['POST'])
def seller_join(seller_id):
    req_json = json.loads(request.get_data())
    island = req_json.get("island")
    name = req_json.get("name")
    seller_info = mongo.db.seller.find_one({"_id":ObjectId(seller_id)})
    if seller_info == None:
        res_data = {
            "status":4,
            "msg":"未找到股民，请刷新页面后再试"
        }
    else:
        if seller_info["status"] == 1:
            res_data = {
                "status":5,
                "msg":"已在交易中"
            }
        elif seller_info["status"] == 2:
            res_data = {
                "status":9,
                "msg":"已在排队中"
            }
        else:
            if island=="" or island==None or name=="" or name==None:
                res_data = {
                    "status":6,
                    "msg":"输入错误"
                }
            else:
                island_data = mongo.db.island.find_one({"_id":ObjectId(island)})
                if island_data==None or island_data["status"]==0:
                    res_data = {
                        "status":8,
                        "msg":"岛屿未开放"
                    }
                elif len(island_data["sellers"]) >= island_data["max_seller"]:
                    mongo.db.seller.update_one({"_id":ObjectId(seller_id)},{"$set":{
                        "status":2,
                        "island":ObjectId(island),
                        "name":name
                    }})
                    mongo.db.island.update_one({"_id":ObjectId(island)},{"$addToSet":{"queue":ObjectId(seller_id)}})
                    res_data = {
                        "status":1,
                        "msg":"已加入排队"
                    }
                else:
                    mongo.db.seller.update_one({"_id":ObjectId(seller_id)},{"$set":{
                        "status":1,
                        "island":ObjectId(island),
                        "name":name,
                        "last_trade":datetime.datetime.now()
                    }})
                    mongo.db.island.update_one({"_id":ObjectId(island)},{"$addToSet":{"sellers":ObjectId(seller_id)}})
                    res_data = {
                        "status":0,
                        "msg":"Success"
                    }
                    try:
                        mongo.db.log.insert_one({
                            "time":datetime.datetime.now(),
                            "island_name":island_data["name"],
                            "island_ip":island_data["ip"],
                            "seller_name":name,
                            "seller_ip":seller_info["ip"],
                            "price":island_data["price"]
                            })
                    except:
                        pass
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)

@app.route('/turniptrade/seller/<seller_id>/quit',methods = ['POST'])
def seller_quit(seller_id):
    seller_info = mongo.db.seller.find_one({"_id":ObjectId(seller_id)})
    if seller_info == None:
        res_data = {
            "status":4,
            "msg":"未找到股民，请刷新页面后再试"
        }
    else:
        if seller_info["status"] == 0:
            res_data = {
                "status":5,
                "msg":"未在交易或排队中"
            }
        elif seller_info["status"] == 2:
            mongo.db.island.update_one({"_id":seller_info["island"]},{ "$pull":{"queue":ObjectId(seller_id)}})
            mongo.db.seller.update_one({"_id":seller_info["_id"]},{"$set":{
                "status":0,
                "island":None,
                "last_trade":datetime.datetime.fromtimestamp(0.0)
            }})
            res_data = {
                "status":0,
                "msg":"Success"
            }

        else:
            mongo.db.island.update_one({"_id":seller_info["island"]},{ "$pull":{"sellers":ObjectId(seller_id)}})
            mongo.db.seller.update_one({"_id":seller_info["_id"]},{"$set":{
                "status":0,
                "island":None,
                "last_trade":datetime.datetime.fromtimestamp(0.0)
            }})

            island_data = mongo.db.island.find_one({"_id":seller_info["island"]})
            if len(island_data["queue"]) > 0 and len(island_data["sellers"]) <= island_data["max_seller"]:
                new_seller = island_data["queue"][0]
                mongo.db.seller.update_one({"_id":new_seller},{"$set":{
                    "status":1,
                    "last_trade":datetime.datetime.now()
                }})
                mongo.db.island.update_one({"_id":seller_info["island"]},{"$addToSet":{"sellers":new_seller}})
                mongo.db.island.update_one({"_id":seller_info["island"]},{ "$pull":{"queue":new_seller}})

            res_data = {
                "status":0,
                "msg":"Success"
            }

    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)

@app.route('/turniptrade/seller/<seller_id>/extend',methods = ['POST'])
def seller_extend(seller_id):
    seller_info = mongo.db.seller.find_one({"_id":ObjectId(seller_id)})
    if seller_info == None:
        res_data = {
            "status":4,
            "msg":"未找到股民，请刷新页面后再试"
        }
    else:
        if seller_info["status"] == 0 or seller_info["status"] == 2:
            res_data = {
                "status":5,
                "msg":"未在交易中"
            }
        else:
            mongo.db.seller.update_one({"_id":ObjectId(seller_id)},{"$set":{
                "last_trade":datetime.datetime.now()
            }})
            res_data = {
                "status":0,
                "msg":"续期成功"
            }

    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)

@app.route('/turniptrade/seller/<seller_id>/report',methods = ['POST'])
def seller_report(seller_id):
    req_json = json.loads(request.get_data())
    island_id = req_json.get("island_id")
    r_type = req_json.get("r_type")
    r_msg = req_json.get("r_msg")
    seller_info = mongo.db.seller.find_one({"_id":ObjectId(seller_id)})
    if seller_info == None:
        res_data = {
            "status":4,
            "msg":"未找到指定股民，请刷新后再试"
        }
    else:
        island_info = mongo.db.island.find_one({"_id":ObjectId(island_id)})
        if seller_info == None:
            res_data = {
                "status":6,
                "msg":"未找到指定岛屿"
            }
        else:
            mongo.db.report.insert_one({
                        "time":datetime.datetime.now(),
                        "from_name":seller_info["name"],
                        "from_ip":seller_info["ip"],
                        "island_name":island_info["name"],
                        "island_ip":island_info["ip"],
                        "report_type":r_type,
                        "report_msg":r_msg
                        })
            res_data = {
                "status":0,
                "msg":"举报成功 我们将核实后进行处理"
            }
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)

@app.route('/turniptrade/sys/clean',methods = ['GET'])
def clean():
    err_island = 0
    err_seller = 0

    #Clean Expired Islands
    expired_islands = mongo.db.island.find({"last_heartbeat":{"$lt":datetime.datetime.now() + datetime.timedelta(minutes=-2)}})
    expired_island_count = 0
    for ei in expired_islands:
        try:
            expired_island_count += 1
            mongo.db.seller.update_many({"island":ei["_id"]},{"$set": {
                "status":0,
                "island":None
            }})
        except:
            err_island += 1
            pass
    
    #Clean Expired Sellers
    expired_sellers = mongo.db.seller.find({"last_heartbeat":{"$lt":datetime.datetime.now() + datetime.timedelta(minutes=-2)}})
    expired_seller_count = 0
    for es in expired_sellers:
        try:
            expired_seller_count += 1
            mongo.db.island.update_many({},{ "$pull":{"sellers":es["_id"]}})
            mongo.db.island.update_many({},{ "$pull":{"queue":es["_id"]}})
            
            if es["status"] == 1:
                island_data = mongo.db.island.find_one({"_id":es["island"]})
                if len(island_data["queue"]) > 0 and len(island_data["sellers"]) <= island_data["max_seller"]:
                    new_seller = island_data["queue"][0]
                    mongo.db.seller.update_one({"_id":new_seller},{"$set":{
                        "status":1,
                        "last_trade":datetime.datetime.now()
                    }})
                    mongo.db.island.update_one({"_id":es["island"]},{"$addToSet":{"sellers":new_seller}})
                    mongo.db.island.update_one({"_id":es["island"]},{ "$pull":{"queue":new_seller}})
        except:
            err_seller += 1
            pass

    mongo.db.island.delete_many({"last_heartbeat":{"$lt":datetime.datetime.now() + datetime.timedelta(minutes=-2)}})    
    mongo.db.seller.delete_many({"last_heartbeat":{"$lt":datetime.datetime.now() + datetime.timedelta(minutes=-2)}})

    #Kick Timeout Seller
    expired_sellers_trade = mongo.db.seller.find({"status":1,"last_trade":{"$lt":datetime.datetime.now() + datetime.timedelta(minutes=-5)}})
    expired_sellers_trade_count = 0
    for est in expired_sellers_trade:
        try:
            expired_sellers_trade_count += 1
            mongo.db.island.update_many({},{ "$pull":{"sellers":est["_id"]}})
            mongo.db.seller.update_one({"_id":est["_id"]},{"$set":{
                "status":0,
                "island":None,
                "last_trade":datetime.datetime.fromtimestamp(0.0)
            }})
            island_data = mongo.db.island.find_one({"_id":est["island"]})
            if len(island_data["queue"]) > 0 and len(island_data["sellers"]) <= island_data["max_seller"]:
                new_seller = island_data["queue"][0]
                mongo.db.seller.update_one({"_id":new_seller},{"$set":{
                    "status":1,
                    "last_trade":datetime.datetime.now()
                }})
                mongo.db.island.update_one({"_id":est["island"]},{"$addToSet":{"sellers":new_seller}})
                mongo.db.island.update_one({"_id":est["island"]},{ "$pull":{"queue":new_seller}})
        except:
            err_seller += 1
            pass

    #Kick Timeout Island
    timeout_island_count = 0
    timeout_island = mongo.db.island.find({"status":1,"last_open":{"$lt":datetime.datetime.now() + datetime.timedelta(hours=-12)}})
    for ti in timeout_island:
        try:
            timeout_island_count += 1
            mongo.db.seller.update_many({"island":ti["_id"]},{"$set": {
                "status":0,
                "island":None
            }})
        except:
            err_island += 1
    mongo.db.island.update_many(
        {"status":1,"last_open":{"$lt":datetime.datetime.now() + datetime.timedelta(hours=-12)}},
        {"$set":{
                "status":0,
                "sellers":[],
                "queue":[]
            }})

    res_data = {
        "status":0,
        "msg":"Success",
        "expired_island_count":expired_island_count,
        "expired_seller_count":expired_seller_count,
        "expired_sellers_trade_count":expired_sellers_trade_count,
        "timeout_island_count":timeout_island_count,
        "err_island":err_island,
        "err_seller":err_seller
    }
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)

@app.route('/turniptrade/sys/info',methods = ['GET'])
def sys_info():
    island_count = mongo.db.island.count_documents({})
    island_open_count = mongo.db.island.count_documents({"status":1})
    seller_count = mongo.db.seller.count_documents({})
    seller_trade_count = mongo.db.seller.count_documents({"status":1})
    res_data = {
        "status":0,
        "msg":"Success",
        "island_count":island_count,
        "island_open_count":island_open_count,
        "seller_count":seller_count,
        "seller_trade_count":seller_trade_count,
        "version":"0.7.1"
    }
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)

@app.route('/turniptrade/sys/notification',methods = ['GET'])
def sys_notification():
    notis = mongo.db.notification.find({})
    noti_list = []
    for n in notis:
        noti_list.append({
            "title":n["title"],
            "msg":n["msg"]
            })
    res_data = {
        "status":0,
        "msg":"Success",
        "notifications":noti_list
    }
    response = make_response(res_data)
    response.headers["Content-Type"]="application/json;charset=utf-8"
    return(response)

def handler(environ, start_response):
    # maybe pre do something here
    return app(environ, start_response)

from flask_cors import CORS
CORS(app, supports_credentials=True)
app.run(host='0.0.0.0',port=80,debug=False)