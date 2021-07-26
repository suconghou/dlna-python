#!/usr/bin/env python
# encoding: utf-8
import socket
import sys
from urllib import request, parse, error
import struct
import traceback
import threading
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import xml.etree.ElementTree as ET


class Req:
    def __init__(self, headers):
        self.headers = headers

    def get(self, url):
        try:
            res = request.urlopen(url)
            return res.read()
        except error.HTTPError as e:
            print(e.geturl(), e.read())
            raise e

    def post(self, url, values):
        try:
            data = parse.urlencode(values).encode('utf-8')
            req = request.Request(url, data, self.headers, method='POST')
            res = request.urlopen(req, timeout=10)
            return res.read()
        except error.HTTPError as e:
            print(e.geturl(), e.read())
            raise e

    def request(self, controlURL, actionName, data):
        try:
            serviceId = 'urn:schemas-upnp-org:service:AVTransport:1'
            data = data.encode('utf-8')
            self.headers[
                'SOAPAction'] = '"' + serviceId + '#' + actionName + '"'
            print(data)
            req = request.Request(controlURL,
                                  data,
                                  self.headers,
                                  method='POST')
            res = request.urlopen(req, timeout=10)
            return res.read()
        except error.HTTPError as e:
            print(e.geturl(), e.read())
            raise e


class XmlText():
    def setPlayURLXml(self, url):
        meta = '''&lt;?xml version='1.0' encoding='utf-8' standalone='yes' ?&gt;&lt;DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/" xmlns:dlna="urn:schemas-dlna-org:metadata-1-0/"&gt;&lt;item id="id" parentID="0" restricted="0"&gt;&lt;dc:title&gt;This is title&lt;/dc:title&gt;&lt;upnp:artist&gt;unknow&lt;/upnp:artist&gt;&lt;upnp:class&gt;object.item.videoItem&lt;/upnp:class&gt;&lt;dc:date&gt;2018-09-06T18:23:54&lt;/dc:date&gt;&lt;res protocolInfo="http-get:*:*/*:*"&gt;This is url&lt;/res&gt;&lt;/item&gt;&lt;/DIDL-Lite&gt;
        '''
        return '''<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
        <u:SetAVTransportURI xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
            <InstanceID>0</InstanceID>
            <CurrentURI>{}</CurrentURI>
            <CurrentURIMetaData>{}</CurrentURIMetaData>
        </u:SetAVTransportURI>
    </s:Body>
</s:Envelope>
        '''.format(url, meta)

    def playActionXml(self):
        return '''<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
        <u:Play xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
            <InstanceID>0</InstanceID>
            <Speed>1</Speed>
        </u:Play>
    </s:Body>
</s:Envelope>
        '''

    def pauseActionXml(self):
        return '''<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
	<s:Body>
		<u:Pause xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
			<InstanceID>0</InstanceID>
		</u:Pause>
	</s:Body>
</s:Envelope>
    '''

    def stopActionXml(self):
        return '''<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
        <u:Stop xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
            <InstanceID>0</InstanceID>
        </u:Stop>
    </s:Body>
</s:Envelope>
        '''

    def getPositionXml(self):
        return '''<?xml version="1.0" encoding="utf-8" standalone="no"?>
    <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
        <s:Body>
            <u:GetPositionInfo xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
                <InstanceID>0</InstanceID>
                <MediaDuration />
            </u:GetPositionInfo>
        </s:Body>
    </s:Envelope>
        '''

    def seekToXml(self):
        return '''<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
	<s:Body>
		<u:Seek xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
			<InstanceID>0</InstanceID>
			<Unit>REL_TIME</Unit>
			<Target>00:00:20</Target>
		</u:Seek>
	</s:Body>
</s:Envelope>
        '''


class xmlParser:
    def __init__(self, url, data):
        self.url = url
        self.data = data

    def parse(self):
        r = parse.urlparse(self.url)
        URLBase = r.scheme + '://' + r.hostname + ':' + str(r.port)
        info = {
            'URLBase': URLBase,
        }
        device = {}
        root = ET.fromstring(self.data)
        for child in root:
            tag = child.tag.split('}').pop()
            if tag == 'device':
                for d in child:
                    key = d.tag.split('}').pop()
                    if key == 'deviceType':
                        device['deviceType'] = d.text
                    elif key == 'friendlyName':
                        device['friendlyName'] = d.text
                    elif key == 'serviceList':
                        serviceList = []
                        for service in d:
                            serviceItem = {}
                            for sitem in service:
                                kk = sitem.tag.split('}').pop()
                                serviceItem[kk] = sitem.text
                            serviceList.append(serviceItem)
                        device['serviceList'] = serviceList
                    else:
                        pass  # print('ignore device tag ', key)
            else:
                pass  # print('ignore tag ', tag)
        info['device'] = device
        return info


class Device:
    def __init__(self, info):
        self.info = info
        self.header = {"Content-Type": "text/xml"}

    def url(self):
        part = ''
        for item in self.info['device']['serviceList']:
            if 'org:service:AVTransport' in item['serviceType']:
                part = item['controlURL']
        return parse.urljoin(self.info['URLBase'], part)

    def setPlayUrl(self, url):
        controlURL = self.url()
        data = XmlText().setPlayURLXml(url)
        return Req(self.header).request(controlURL, 'SetAVTransportURI', data)

    def play(self, ):
        controlURL = self.url()
        data = XmlText().playActionXml()
        return Req(self.header).request(controlURL, 'Play', data)

    def pause(self):
        controlURL = self.url()
        data = XmlText().pauseActionXml()
        return Req(self.header).request(controlURL, 'Pause', data)

    def stop(self):
        controlURL = self.url()
        data = XmlText().stopActionXml()
        return Req(self.header).request(controlURL, 'Stop', data)

    def seek(self):
        controlURL = self.url()
        data = XmlText().seekToXml()
        return Req(self.header).request(controlURL, 'Seek', data)

    def getPosition(self):
        controlURL = self.url()
        data = XmlText().getPositionXml()
        return Req(self.header).request(controlURL, 'GetPositionInfo', data)


class parser:
    def __init__(self, data, address):
        self.address = address
        self.lines = data.splitlines()

    def get(self):
        arr = self.run_method()
        if arr == None or len(arr) != 3:
            return '', {}, None
        return arr

    def run_method(self):
        method, path, version = self.lines[0].split(' ')
        method = str(method.replace('-', '')).upper()
        self.lines = self.lines[1:]
        if not hasattr(self, method):
            if method == "HTTP/1.1" or method == "HTTP/1.0":
                return self.NOTIFY()
            print("method not found", method, path, version)
            return
        return getattr(self, method)()

    # 收到别人的查询消息
    def MSEARCH(self):
        pass

    # 别人发出了存活广播,我们在此过滤投屏设备
    def NOTIFY(self):
        for line in self.lines:
            arr = line.split(':', 1)
            if len(arr) != 2:
                continue
            key = arr[0].strip().upper()
            value = arr[1].strip()
            if key == "LOCATION":
                return self.getInfo(value)

    def getInfo(self, url):
        data = {}
        try:
            data = Req({}).get(url)
        except Exception as e:
            print("request " + url + " error ", e)
            return
        info = xmlParser(url, data).parse()
        return url, info, Device(info)


class ListenWorker(threading.Thread):
    def __init__(self, onfound):
        threading.Thread.__init__(self)
        self.onfound = onfound

    def run(self):
        self.search()
        self.listen()

    def listen(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                          socket.IPPROTO_UDP)
        # 允许端口复用
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 绑定监听多播数据包的端口
        s.bind(('239.255.255.250', 1900))
        # 声明该socket为多播类型
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        # 加入多播组，组地址由第三个参数制定
        mreq = struct.pack("4sl", socket.inet_aton('239.255.255.250'),
                           socket.INADDR_ANY)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        while True:
            try:
                data, address = s.recvfrom(2048)
                self.parse(data, address)
            except Exception as e:
                traceback.print_exc()

    def parse(self, data, address):
        url, info, item = parser(data.decode(), address).get()
        if url != '' and item != None:
            self.onfound(url, info, item)

    def search(self):
        def ondata(data, address):
            try:
                self.parse(data, address)

            except Exception as e:
                traceback.print_exc()

        SearchWorker(ondata).start()


class SearchWorker(threading.Thread):
    def __init__(self, ondata):
        threading.Thread.__init__(self)
        self.ondata = ondata
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def run(self):
        while True:
            self.search("ssdp:all")
            time.sleep(1)
            self.search("urn:schemas-upnp-org:service:AVTransport:1")
            time.sleep(1)
            self.search("urn:schemas-upnp-org:device:MediaRenderer:1")

    def sendUdp(self, data):
        udp_socket = self.udp_socket
        udp_socket.sendto(data.encode(), ('239.255.255.250', 1900))
        data, address = udp_socket.recvfrom(2048)
        self.ondata(data, address)

    def search(self, st):
        text = '''M-SEARCH * HTTP/1.1
HOST: 239.255.255.250:1900
MAN: "ssdp:discover"
MX: 5
ST: {}
'''.format(st)
        self.sendUdp(text)


class Dlna:
    def __init__(self):
        self.devices = {}
        self.infos = {}

    def start(self):
        ListenWorker(self.onFound).start()

    def onFound(self, url, info, item):
        self.infos[url] = info
        self.devices[url] = item

    def getInfos(self):
        return self.infos

    def getDevice(self, url):
        return self.devices.get(url)


host = ('localhost', 8888)

dlna = Dlna()


class Resquest(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            req = parse.urlparse(self.path)
            path = req.path
            query = parse.parse_qs(req.query)
            if path.startswith('/info'):
                return self.info(query)

            return self.index()
        except Exception as e:
            traceback.print_exc()
            self.send_error(500, str(e), str(e))

    def do_POST(self):
        try:
            req = parse.urlparse(self.path)
            path = req.path
            query = parse.parse_qs(req.query)
            if path.startswith('/play'):
                return self.play(query)
            if path.startswith('/pause'):
                return self.pause(query)
            if path.startswith('/stop'):
                return self.stop(query)
            if path.startswith('/position'):
                return self.position(query)
            if path.startswith('/seek'):
                return self.seek(query)

            return self.notfound()
        except Exception as e:
            traceback.print_exc()
            self.send_error(500, str(e), str(e))

    def index(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        with open("index.html", "rb") as f:
            self.wfile.write(f.read())

    def notfound(self):
        self.send_response(404)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'404 not found')

    def info(self, query):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(dlna.getInfos()).encode())

    def play(self, query):
        url = query.get('url')
        if url is None:
            return self.err('error params')
        url = url[0]
        device = dlna.getDevice(url)
        if device is None:
            return self.err('no device')
        playUrl = query.get('playUrl')
        if playUrl is None:
            # recover play
            device.play()
            self.ok('ok')
            return
        playUrl = playUrl[0]
        ret = device.setPlayUrl(playUrl)
        return self.ok(ret.decode())

    def pause(self, query):
        url = query.get('url')
        if url is None:
            return self.err('error params')
        url = url[0]
        device = dlna.getDevice(url)
        if device is None:
            return self.err('no device')
        ret = device.pause()
        return self.ok(ret.decode())

    def stop(self, query):
        url = query.get('url')
        if url is None:
            return self.err('error params')
        url = url[0]
        device = dlna.getDevice(url)
        if device is None:
            return self.err('no device')
        ret = device.stop()
        return self.ok(ret.decode())

    def position(self, query):
        url = query.get('url')
        if url is None:
            return self.err('error params')
        url = url[0]
        device = dlna.getDevice(url)
        if device is None:
            return self.err('no device')
        ret = device.getPosition()
        return self.ok(ret.decode())

    def seek(self, query):
        url = query.get('url')
        if url is None:
            return self.err('error params')
        url = url[0]
        device = dlna.getDevice(url)
        if device is None:
            return self.err('no device')
        device.seek()
        return self.ok('ok')

    def err(self, err):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'code': -1, 'msg': err}).encode())

    def ok(self, msg):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'code': 0, 'msg': msg}).encode())


if __name__ == '__main__':
    dlna.start()
    server = HTTPServer(host, Resquest)
    print("Starting server, listen at: %s:%s" % host)
    server.serve_forever()