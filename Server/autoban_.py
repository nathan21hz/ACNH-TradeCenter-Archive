import pymongo
import datetime

TZ = 8

client = pymongo.MongoClient("")
db = client["test"]
island = db["island"]
seller = db["seller"]
banip = db["banip"]
illegal_islands = island.find({"price":{"$gt":661},"status":1,"private":False})
for ii in illegal_islands:
    print(ii["name"],ii["ip"])
    banip.insert_one({
        "ip":ii["ip"],
        "type":"island",
        "name":ii["name"],
        "price":ii["price"],
        "ban_time":datetime.datetime.now() + datetime.timedelta(hours=TZ),
        "release_time":datetime.datetime.now() + datetime.timedelta(hours=TZ) + datetime.timedelta(days=2) 
        })

illegal_sellers = seller.aggregate([
    { "$match":{ "status":{"$ne":0} } },
    { "$group":{ "_id" : {"ip":"$ip","name":"$name"}, "count": { "$sum" : 1 } }},
    { "$match":{ "count": { "$gt" : 2}} }
])
for ils in illegal_sellers:
    print(ils["_id"]["ip"], ils["_id"]["name"], ils["count"])
    banip.insert_one({
        "ip":ils["_id"]["ip"],
        "type":"seller",
        "name":ils["_id"]["name"],
        "price":None,
        "ban_time":datetime.datetime.now() + datetime.timedelta(hours=TZ),
        "release_time":datetime.datetime.now() + datetime.timedelta(hours=TZ) + datetime.timedelta(days=1) 
        })

banip.delete_many({"release_time":{"$lt":datetime.datetime.now() + datetime.timedelta(hours=-TZ)}})


