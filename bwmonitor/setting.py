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
    "host" : "10.4.235.199",
    "db"   : 0,
    "password" : "dong1234",
    "port"  : 6379
}

#ofctl url
OFCTL_URL = "http://127.0.0.1:8080/"

#queue url 
QUEUE_URL = "http://10.5.237.234:7788/"

