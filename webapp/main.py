#-*- coding:utf-8 -*-
from flask import Flask
from flask import render_template,request,jsonify,redirect,url_for
import redis
import json
import sys

default_encoding = 'utf-8'
if sys.getdefaultencoding() != default_encoding:
    reload(sys)
    sys.setdefaultencoding(default_encoding)

app = Flask(__name__)
redis_client = redis.StrictRedis(host='127.0.0.1', port=6379, db=0)

@app.route("/")
def index():
    return render_template('topo.html')


@app.route("/topo")
def topo_page():
    return render_template("topo.html")


@app.route("/topo_data.json")
def topo_data():
    data = {
        'switches' : json.loads(redis_client.get("topo_for_switchs")),
        'hosts' : json.loads(redis_client.get("topo_for_hosts"))
    }
    data = json.dumps(data)
    print data
    return data

@app.route("/edges")
def edges():
    data = json.loads(redis_client.get("topo_for_switchs"))
    all_edges = []
    exist = []
    heads = ['DPID1','端口1','DPID2','端口2','总带宽','时延','丢包率']
    cols = ['source','src_port','target','dst_port','bandwidth','latency','loss']
    for k in data :
        curEdges = data[k]
        for n in curEdges :
            if (k,n) in exist and (n,k) in exist :
                continue
            e = curEdges[n]
            e['source'] = k
            e['target'] = n
            all_edges.append(e)
    context = {'title':'链路信息','items':all_edges,'heads':heads,'cols':cols}
    return render_template('tables.html',**context)

'''
return {
            'src_ip' : self.match['ipv4_src'],
            'dst_ip' : self.match['ipv4_dst'],
            'path' : str(self.path),
            'src_port' : self.match['src_port'] if 'src_port' in self.match else '',
            'dst_port' : self.match['dst_port'] if 'dst_port' in self.match else '',
            'transport' : 'TCP' if self.transport_protocol == PROTOCOL_TCP else 'UDP',
            'app_type' : self.application_type,
            'speed' : self.speed,
            'proority' : self.priority,
            'bandwidth_need' : self.qos.bandwidth,
            'latency_need' : self.qos.latency
        }
'''

@app.route('/flows')
def flows():
    flows = redis_client.get('flows')
    if not flows :
        flows = []
    else :
        flows = json.loads(flows)
    print flows
    title = '流信息'
    heads = ['源IP','目的IP','路径','目的端口','目的端口','传输层协议','应用类型','当前速率(Mb/s)','优先级','带宽需求(Mb/s)']
    cols = ['src_ip','dst_ip','path','src_port','dst_port','transport','app_type','speed','priority','bandwidth_need']
    for f in flows :
        f['priority'] = get_prio(f['priority'])
        pass
    flows = sorted(flows,cmp=lambda x,y : cmp(y['speed'],x['speed']))
    return render_template('tables.html',title=title,heads=heads,items=flows,cols=cols)

@app.route('/qos',methods=['GET','POST'])
def qos() :
    if request.method == 'GET' :
        return render_template('form.html')
    else :
        qos = {
            'bandwidth' : int(request.form['min_rate']),
            'priority'  : int(request.form['priority']),
            'min_rate'  : int(request.form['min_rate']),
            'max_rate'  : int(request.form['max_rate']),
            'latency'   : 0    
        }
        key = str((request.form['src_ip'],request.form['dst_ip'],request.form['src_port'],request.form['dst_port'],
                request.form['tsl_type'],request.form['app_type']))
        key = 'qos-%s'%key
        redis_client.set(key,json.dumps(qos))
        return redirect(url_for('qos_list'))

@app.route('/qos-list',methods=['GET','DELETE'])
def qos_list():
    if request.method == 'GET':
        heads = ['键','值','操作']
        cols = ['key','value']
        keys = redis_client.keys('qos-*')
        items = []
        for key in keys:
            item = {}
            item['key'] = key
            item['value'] = redis_client.get(key)
            item['operate'] = 'delete'
            items.append(item)
        return render_template('tables_qos.html',title='qos列表',heads = heads,items = items,cols = cols)


@app.route('/qos-delete',methods = ['POST'])
def qos_delete():
    if request.method == "POST":
        key = request.form['key']
        redis_client.delete(key)
        return jsonify({'status':0})
        



def make_edge(source,target,attrs):
    return (source,target,attrs['bandwidth'],attrs['bandwidth_used'],attrs['latency'],attrs['loss'])

def get_prio(num) :
    if num == 0 :
        return '一般流量'
    if num == 1 :
        return '保障流量'
    if num == 2 :
        return '关键流量'


if __name__ == '__main__':
    app.run(debug=True)

