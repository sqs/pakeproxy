from subprocess import Popen, PIPE, STDOUT, check_output, CalledProcessError, check_call
from unittest import TestCase
from nose.plugins.attrib import attr
from contextlib import contextmanager
import threading
import urllib2, os, re
#from ProxyHTTPConnection import ConnectHTTPSHandler

ACCOUNTS_INLINE1='example.com,a,b|tls-srp.test.trustedhttp.org,user,secret'

@contextmanager
def pakeproxy(host='localhost', port=8443,
              accounts_inline=''):
    pp_env = os.getenv('pake_proxy')
    if pp_env:
        pp_env = pp_env.split(':')
        pp = {'host': pp_env[0], 'port': int(pp_env[1])}
        p = None
    else:
        pp = {'host': host, 'port': port}
        cmd = ['src/pakeproxy']
        cmd += ['-a', accounts_inline]
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
    print("pakeproxy on %(host)s:%(port)d" % pp)
    try:
        yield pp
    finally:
        if p:
            p.terminate()

def proxy_urlopen(pp, url, proxy_user=None):
    https_proxy = ('%(host)s:%(port)d' % pp)
    cmd = ['curl', '-v', '-k', url]
    if proxy_user:
        cmd += ['--proxy-user', proxy_user]
    out =  check_output(cmd, stderr=STDOUT,
                        env={'https_proxy': https_proxy})
    return CurlResponse(out)

class CurlResponse(object):
    def __init__(self, raw):
        self.raw = raw

    def read(self):
        return self.raw

    subject_re = re.compile(r'subject:\s*(.*)')
    issuer_re = re.compile(r'issuer:\s*(.*)')
    def certinfo(self):
        print self.raw
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
        res = proxy_urlopen(self.pakeproxy, self.url, proxy_user='user:secret')
        TestPAKEProxy.check_response(self.test, res)
    
class TestPAKEProxy(TestCase):
    url = 'https://tls-srp.test.trustedhttp.org'
    non_tls_login_urls = ['https://encrypted.google.com']
    
    def check_response(self, res):
        self.assertIn('user is: user', res.read())
        certinfo = res.certinfo()
        self.assertEquals('CN=tls-srp.test.trustedhttp.org; O=user@tls-srp.test.trustedhttp.org (SRP)',
                          certinfo['subject'])
        self.assertEquals('CN=PAKEProxy CA Certificate',
                          certinfo['issuer'])

    def check_non_tls_login_url_response(self, res):
        self.assertIn('Host: encrypted.google.com:443', res.read())
        certinfo = res.certinfo()
        self.assertEquals('C=US; ST=California; L=Mountain View; '
                          'O=Google Inc; CN=*.google.com',
                          certinfo['subject'])
        self.assertEquals('C=US; O=Google Inc; CN=Google Internet Authority',
                          certinfo['issuer'])

    def test_simple_inline(self):
        with pakeproxy(accounts_inline=ACCOUNTS_INLINE1) as pp:
            res = proxy_urlopen(pp, self.url)
            self.check_response(res)

    def test_srp_failure(self):
        with pakeproxy() as pp:
            self.assertRaises(CalledProcessError, proxy_urlopen,
                              pp, self.url, proxy_user="bad:user")
        with pakeproxy(accounts_inline='tls-srp.test.trustedhttp.org,bad,user') as pp:
            self.assertRaises(CalledProcessError, proxy_urlopen,
                              pp, self.url)

    def test_noauth_failure(self):
        with pakeproxy() as pp:
            self.assertRaises(CalledProcessError, proxy_urlopen,
                              pp, self.url)


    def test_proxy_authz(self):
        with pakeproxy() as pp:
            res = proxy_urlopen(pp, self.url, proxy_user='user:secret')
            self.check_response(res)

    def test_concurrent(self):
        with pakeproxy(accounts_inline=ACCOUNTS_INLINE1) as pp:
            threads = []
            for i in range(5):
                c = ProxyURLOpenThread(pp, self.url, self)
                c.start()
                threads.append(c)
            for t in threads:
                t.join()
                  
    def test_passthru(self):
        for non_tls_login_url in self.non_tls_login_urls:
            with pakeproxy() as pp:
                res = proxy_urlopen(pp, non_tls_login_url)
                self.check_non_tls_login_url_response(res)

    def __detect_tls_srp(self, host):
        try:
            cmd = ['src/pakeproxy', '-D', host]
            check_call(cmd, stdout=PIPE, stderr=PIPE)
            return True
        except CalledProcessError as e:
            return False

    @attr('detect')
    def test_detect_tls_srp(self):
        self.assertTrue(self.__detect_tls_srp('tls-srp.test.trustedhttp.org'))
        self.assertFalse(self.__detect_tls_srp('chaseonline.chase.com'))
        self.assertFalse(self.__detect_tls_srp('www.stanford.edu'))



