from subprocess import Popen, PIPE, STDOUT, check_output
from unittest import TestCase
from contextlib import contextmanager
import threading
import urllib2, os, re
#from ProxyHTTPConnection import ConnectHTTPSHandler

@contextmanager
def pakeproxy(host='localhost', port=8443):
    pp_env = os.getenv('pake_proxy')
    if pp_env:
        pp_env = pp_env.split(':')
        pp = {'host': pp_env[0], 'port': int(pp_env[1])}
        p = None
    else:
        pp = {'host': host, 'port': port}
        p = Popen(['src/pakeproxy'], stdout=PIPE, stderr=PIPE)
    print("pakeproxy on %(host)s:%(port)d" % pp)
    try:
        yield pp
    finally:
        if p:
            p.terminate()

def proxy_urlopen(pp, url, tls_login=None):
    https_proxy = ('%(host)s:%(port)d' % pp)
    out =  check_output(['wget', '-d', '--no-check-certificate',
                         '-O', '/dev/stdout',
                         url],
                        stderr=STDOUT,
                        env={'https_proxy': https_proxy})
    return WgetResponse(out)
    # opener = urllib2.build_opener(ConnectHTTPSHandler)
    # urllib2.install_opener(opener)
    # 
    # req = urllib2.Request(url)
    # req.set_proxy(https_proxy, 'https')
    # # req.set_tunnel('%(host)s:%(port)d' % pp, 'https')
    # return urllib2.urlopen(req)

class WgetResponse(object):
    def __init__(self, raw):
        self.raw = raw

    def read(self):
        return self.raw

    subject_re = re.compile(r'subject:\s*/CN=(.*)')
    issuer_re = re.compile(r'issuer:\s*/CN=(.*)')
    def certinfo(self):
        subject = self.subject_re.search(self.raw).groups(0)[0]
        issuer = self.issuer_re.search(self.raw).groups(0)[0]
        return {'subject': subject, 'issuer': issuer}


class ProxyURLOpenThread(threading.Thread):
    def __init__(self, pakeproxy, url, test):
        threading.Thread.__init__(self)
        self.pakeproxy = pakeproxy
        self.url = url
        self.test = test

    def run(self):
        res = proxy_urlopen(self.pakeproxy, self.url)
        TestPAKEProxy.check_response(self.test, res)
    
class TestPAKEProxy(TestCase):
    url = 'https://tls-srp.test.trustedhttp.org'
    
    def check_response(self, res):
        self.assertIn('user is: user', res.read())
        certinfo = res.certinfo()
        self.assertEquals('tls-srp.test.trustedhttp.org/O=sqs@tls-srp.test.trustedhttp.org (SRP)',
                          certinfo['subject'])
        self.assertEquals('PAKEProxy CA Certificate',
                          certinfo['issuer'])

    def test_simple(self):
        with pakeproxy() as pp:
            res = proxy_urlopen(pp, self.url)
            self.check_response(res)

    def test_concurrent(self):
        with pakeproxy() as pp:
            threads = []
            for i in range(5):
                c = ProxyURLOpenThread(pp, self.url, self)
                c.start()
                threads.append(c)
            for t in threads:
                t.join()
                  
        
            
    
    
