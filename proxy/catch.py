#! /usr/bin/python3
#-*- encoding=utf-8 -*-

import re
import time
import requests
import collections

# 快代理
kuai_url1 = "https://www.kuaidaili.com/free/intr/{}/" 		# 普通
kuai_url2 = "https://www.kuaidaili.com/free/inha/{}/" 		# 高匿

# 西刺代理
xici_url1 = "http://www.xicidaili.com/nt/{}/"               # 普通
xici_url2 = "http://www.xicidaili.com/nn/{}/"               # 高匿

class ProxyItem(object):
    """
    通用的代理实体类
    """
    def __init__(self, _ip=None, _port=None, _type=None, _location=None, _lasttime=None):
        self.ip     = str(_ip).strip()
        self.port   = str(_port).strip()
        self.type   = str(_type).strip()         # 类型 （http，socket...）
        self.loc    = str(_location).strip()     # 位置 （上海，江苏...）
        self.ltime  = str(_lasttime).strip()     # 最后更新时间

    @staticmethod
    def dict_proxy(items, flag=False):
        """
        items: ProxyItem对象的生成器or迭代器
        flag: 当传入类型位http时，是否设置同样的https（默认不设置）
        return: 符合requests使用的字典类型的proxies
        exp:
            proxies = {
              "http": "http://10.10.1.10:3128",
              "https": "http://10.10.1.10:1080",
            }
        """
        assert isinstance(items, collections.Iterable)
        rest = []
        for item in items:
            _ = {item.type.lower(): "{}://{}:{}".format(item.type.lower(), item.ip, item.port)}
            if item.type.lower() == 'http' and flag:
                _.update({'https': "{}://{}:{}".format(item.type.lower(), item.ip, item.port)})
            rest.append(_)
        return rest

    def __str__(self):
        return '{}:{}\t{}\t{}\t{}'.format(self.ip, self.port, self.type, self.loc, self.ltime)

class XiCiDaili(object):
    """
    西刺代理： https://www.xicidaili.com
    <tr class="">
        <td class="country"></td>
        <td>120.77.249.46</td>
        <td>8080</td>
        <td>长城宽带</td>
        <td class="country">高匿</td>
        <td>HTTPS</td>
        <td class="country">
            <div title="0.609秒" class="bar">
                <div class="bar_inner fast" style="width:96%"></div>
            </div>
        </td>
        <td class="country">
            <div title="0.121秒" class="bar">
                <div class="bar_inner fast" style="width:95%"></div>
            </div>
        </td>
        <td>6天</td>
        <td>18-10-19 19:52</td>
    </tr>
    """
    comp_url    = re.compile(r'http[s]?://www.xicidaili.com/.*?/.*?')  # url规则
    comp_items  = re.compile(
            r'<tr.*?>.*?'
                r'<td.*?>(.*?)</td>.*?'       # 国家
                r'<td.*?>(.*?)</td>.*?'                # ip
                r'<td.*?>(.*?)</td>.*?'                # 端口
                r'<td.*?>(.*?)</td>.*?'                # 地点杂项？（长城宽带，广西桂林。。。）
                r'<td.*?>(.*?)</td>.*?'                # 匿名度（高匿，透明）
                r'<td.*?>(.*?)</td>.*?'                # 类型（HTTP、socket）
                r'<td.*?>(.*?)</td>[\s]*?'             # 最后一个td中是日期
            r'</tr>',
            re.I | re.S)
    headers      = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36'
            }

    @staticmethod
    def gen_proxy(url, page=10, timeout=1000):
        """
        url: ^http[s]?://.*?/\{\}.*$
        page: 默认页数
        timeout: 间隔时间(毫秒）
        return: yield -> ProxyItem
        """
        assert isinstance(page, int)
        if not re.match(XiCiDaili.comp_url, url): # url校验
            print("url example: https://www.xicidaili.com/nn/{}/")
            raise Exception('url format error!')

        for i in range(1, page+1):
            time.sleep(timeout/1000)
            u = url.format(i)
            print("get {}".format(u))
            resp = requests.get(url.format(i), headers=XiCiDaili.headers)
            resp.encoding = 'utf-8'
            if resp.status_code != 200:
                print("the url: {} request error! {}".format(u, resp.status_code))
                continue
            for s in re.findall(XiCiDaili.comp_items, resp.text): # 提取ProxyItem需要的信息
                proxy_item = ProxyItem(s[1], s[2], s[5], s[3], s[5])
                yield proxy_item


class KuaiDaili(object):
    """
    快代理: https://www.kuaidaili.com/
    <tr>
        <td data-title="IP">218.66.79.175</td>
        <td data-title="PORT">54981</td>
        <td data-title="匿名度">高匿名</td>
        <td data-title="类型">HTTP</td>
        <td data-title="位置">福建省福州市  电信</td>
        <td data-title="响应速度">2秒</td>
        <td data-title="最后验证时间">2018-10-13 15:31:17</td>
    </tr>
    """
    comp_url    = re.compile(r'^http[s]?://.*?/\{\}.*$')   # url规则
    comp_items  = re.compile(
            r'<td data-title="IP">(.*?)</td>.*?'
            '<td data-title="PORT">(.*?)</td>.*?'
            '<td data-title="匿名度">(.*?)</td>.*?'
            '<td data-title="类型">(.*?)</td>.*?'
            '<td data-title="位置">(.*?)</td>.*?'
            '<td data-title="响应速度">(.*?)</td>.*?'
            '<td data-title="最后验证时间">(.*?)</td>',
            re.I | re.S)

    @staticmethod
    def gen_proxy(url, page=10, timeout=1000):
        """
        url: ^http[s]?://.*?/\{\}.*$
        page: 默认页数
        timeout: 间隔时间(毫秒）
        return: yield -> ProxyItem
        """
        assert isinstance(page, int)
        if not re.match(KuaiDaili.comp_url, url): # url校验
            print("url example: https://www.xxx.com/intr/{}/")
            raise Exception('url format error!')

        for i in range(1, page+1):
            time.sleep(timeout/1000)
            u = url.format(i)
            print("get {}".format(u))
            resp = requests.get(url.format(i))
            resp.encoding = 'utf-8'
            if resp.status_code != 200:
                print("the url: {} request error! {}".format(u, resp.status_code))
                continue
            for s in re.findall(KuaiDaili.comp_items, resp.text): # 提取ProxyItem需要的信息
                proxy_item = ProxyItem(s[0], s[1], s[3], s[4], s[6])
                yield proxy_item

def gen_kuai_1(page=10): # 快代理普通
    return KuaiDaili.gen_proxy(kuai_url1, page)

def gen_kuai_2(page=10): # 快代理高匿
    return KuaiDaili.gen_proxy(kuai_url2, page)

def gen_xici_1(page=10): # 西刺代理普通
    return XiCiDaili.gen_proxy(xici_url1, page)

def gen_xici_2(page=10): # 西刺代理高匿
    return XiCiDaili.gen_proxy(xici_url2, page)

if __name__ == '__main__':
    #for p in gen_kuai_2(2):
    #    print(p)
    #print(ProxyItem.dict_proxy(gen_kuai_2(2)))
    for p in gen_xici_2(2):
        print(p)
    print(ProxyItem.dict_proxy(gen_xici_2(2)))
