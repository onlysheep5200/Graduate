#-*- coding:utf-8 -*-
__author__ = 'mac'

'''
    带宽监控模块，负责监控实时带宽
    通过统计一段时间内发包数量的变化，估计当前链路带宽使用情况
    利用OFPPortStatsRequest消息的rx-bytes和tx-bytes字段之和除以时间间隔来统计
    一个链路对应两个端口的统计信息，如果都在合理范围以内，取时间间隔小者为准；如果有一个超出了带宽最大值，则将链路当前速率为最大带宽
    部分信息(如可用带宽总量及mac间映射关系)经由配置文件导入
    数据结构：
        一个mac只能对应一条链路;两个mac确定一条链路
        {
            mac1 : {
                last_update_time : unix_time_stamp,
                last_update_interval : num,
                bandwidth_total : num,
                bandwidth_used : num,a, //单位为byte/s
                opposite_port_mac : mac2
            }
        }
'''