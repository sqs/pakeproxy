from subprocess import Popen, PIPE, STDOUT, check_output
from unittest import TestCase
from contextlib import contextmanager
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

class TestPAKEProxy(TestCase):
    def test_simple(self):
        with pakeproxy() as pp:
            res = proxy_urlopen(pp, 'https://tls-srp.test.trustedhttp.org')
            self.assertIn('user is: user', res.read())
            certinfo = res.certinfo()
            self.assertEquals('sqs@tls-srp.test.trustedhttp.org (SRP)',
                              certinfo['subject'])
            self.assertEquals('PAKEProxy CA Certificate',
                              certinfo['issuer'])

            
            
    
    
