DISCOVERY_PERIOD = 10   			# For discovering topology.

MONITOR_PERIOD = 10					# For monitoring traffic

DELAY_DETECTING_PERIOD = 5			# For detecting link delay.

TOSHOW = True						# For showing information in terminal
	
MAX_CAPACITY = 281474976710655L		# Max capacity of link

PORT_STATS_DETECTING_PERIOD = 1

DATAPATH_REFRESH_PERIOD = 5

APPLICATION_AWARE_TIMEOUT = 3

PATH_ATTR_UPDATE_PERIOD = 2

#redis config
REDIS_CONFIG = {     
    "host" : "127.0.0.1",
    "db"   : 0,
    # "password" : "dong1234",
    "port"  : 6379
}

#ofctl url
OFCTL_URL = "http://127.0.0.1:8080/"

#queue url 
QUEUE_URL = "http://192.168.99.100:7788/"

FLOW_REMOVE_THRESHOLD = 5

