#-*- coding:utf-8 -*-
__author__ = 'hyd'
'''
    表示链路状态的类

    {
        mac1 : {
            last_update_time : unix_time_stamp,
            last_update_interval : num,
            last_recv_bytes : num,
            last_send_bytes : num,
            bandwidth_total : num, //单位为byte/s
            bandwidth_used : num,a,
            opposite_port_mac : mac2
        }
    }
'''
import json
import math


class LinkStats(object) :
    statsMap = {}
    updateInterval = None

    @classmethod
    def loadConfig(cls,configPath):
        with open(configPath,'r+') as f :
            cls.statsMap = json.load(f)
        if not cls.statsMap :
            raise Exception('数据加载出错')

    @classmethod
    def getCurrentBandwidth(cls,mac):
        if cls.statsMap :
            item = cls.statsMap.get(mac)
            if not item :
                raise Exception('对应链路不存在')
            oppositeItem = cls.statsMap.get(item['opposite_port_mac'])
            if not oppositeItem :
                return item
            else :
                #先比较更新时间哪个新
                if abs(item['last_update_time'] - oppositeItem['last_update_time']) > cls.updateInterval :
                    result = item if item['last_update_time'] > oppositeItem['last_update_time'] else oppositeItem
                #更新时间在一个更新周期之内则比较哪个端口的更新时间间隔较小
                else :
                    result = item if item['last_update_interval'] < oppositeItem['last_update_interval'] else oppositeItem
                return result
        return None


    @classmethod
    def setCurrentBandwidth(cls,mac,currentRecvBytes,currentSendBytes,update_timestamp):
        #是否需要加锁同步?
        if cls.statsMap and mac in cls.statsMap :
            item = cls.statsMap[mac]
            totalBytes = currentRecvBytes-item['last_recv_bytes']+currentSendBytes-item['last_send_bytes']
            #update_timestamp为unix时间戳，单位为毫秒
            timeSpending = update_timestamp - item['last_update_time']
            item['bandwidth_used'] = totalBytes/(timeSpending/1000) #单位为byte/s
            item['last_update_time'] = update_timestamp
            item['last_update_interval'] = timeSpending
            item['last_recv_bytes'] = currentRecvBytes
            item['last_send_bytes'] = currentSendBytes

    @classmethod
    def getAllBandwidthStat(cls):
        return cls.statsMap




