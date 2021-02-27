import pymongo
import datetime
import time

while True:
    TZ = 0
    BAN_DAYS = 2

    client = pymongo.MongoClient("")
    db = client["test"]
    island = db["island"]
    seller = db["seller"]
    banip = db["banip"]
    message = db["message"]
    report = db["report"]


    FuckAd = island.find_one({"password":{"$regex":"zhangwanyin85623|.*8.*7.*7.*4.*8.*8.*5.*0.*3.*"}})
    if FuckAd:
        print(FuckAd["ip"])
        banip.insert_one({
            "ip":FuckAd["ip"],
            "type":"island",
            "name":"FuckIt2",
            "count":999,
            "ban_time":datetime.datetime.now() + datetime.timedelta(hours=TZ),
            "release_time":datetime.datetime.now() + datetime.timedelta(hours=TZ) + datetime.timedelta(days=300)
            })

    delete_result = island.delete_many({"password":{"$regex":"zhangwanyin85623|.*8.*7.*7.*4.*8.*8.*5.*0.*3.*"}})
    print("User Del ",delete_result.deleted_count)
    print("-"*20)
    time.sleep(10)