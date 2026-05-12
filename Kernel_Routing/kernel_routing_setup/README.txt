routingList.py
-loads all routes into the kernel's routing table, takes a while for 900000+ routes (30 mins?)

batch_routing_List.py
-implementation of routingList.py that uses batching, which loads all routes in one operation instead of 900000+ (10 secs)