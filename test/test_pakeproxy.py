from subprocess import Popen, PIPE, STDOUT, check_output
from unittest import TestCase
from contextlib import contextmanager
import threading
import urllib2, os, re
#from ProxyHTTPConnection import ConnectHTTPSHandler

ACCOUNTS_INLINE1='example.com,a,b|tls-srp.test.trustedhttp.org,user,secret'

@contextmanager
def pakeproxy(host='localhost', port=8443,
              accounts_inline=None,
              accounts_path=None):
    pp_env = os.getenv('pake_proxy')
    if pp_env:
        pp_env = pp_env.split(':')
        pp = {'host': pp_env[0], 'port': int(pp_env[1])}
        p = None
    else:
        pp = {'host': host, 'port': port}
        cmd = ['src/pakeproxy', '-t']
        if accounts_inline:
            cmd += ['-a', accounts_inline]
        if accounts_path:
            cmd += ['-A', accounts_path]
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
        res = proxy_urlopen(self.pakeproxy, self.url)
        TestPAKEProxy.check_response(self.test, res)
    
class TestPAKEProxy(TestCase):
    url = 'https://tls-srp.test.trustedhttp.org'
    non_tls_login_url = 'https://test.gnutls.org:5556'
    
    def check_response(self, res):
        self.assertIn('user is: user', res.read())
        certinfo = res.certinfo()
        self.assertEquals('CN=tls-srp.test.trustedhttp.org; O=sqs@tls-srp.test.trustedhttp.org (SRP)',
                          certinfo['subject'])
        self.assertEquals('CN=PAKEProxy CA Certificate',
                          certinfo['issuer'])

    def check_non_tls_login_url_response(self, res):
        self.assertIn('Host: test.gnutls.org:5556', res.read())
        certinfo = res.certinfo()
        self.assertEquals('O=GnuTLS test server; CN=test.gnutls.org',
                          certinfo['subject'])
        self.assertEquals('CN=GnuTLS test CA', certinfo['issuer'])

    def test_simple(self):
        with pakeproxy(accounts_inline=ACCOUNTS_INLINE1) as pp:
            res = proxy_urlopen(pp, self.url)
            self.check_response(res)

    def test_account_file(self):
        import os
        acctpath = '/tmp/pakeproxy_tmp/'
        acctfile = acctpath + 'tls-srp.test.trustedhttp.org'
        if not os.path.exists(acctpath):
            os.mkdir(acctpath)
        with open(acctfile, 'w') as f:
            f.write('user,secret')
        with pakeproxy(accounts_path=acctpath) as pp:
            res = proxy_urlopen(pp, self.url)
            self.check_response(res)

    def test_srp_failure(self):
        with pakeproxy() as pp:
            res = proxy_urlopen(pp, self.url)
            self.check_response(res)
            
    def test_proxy_authz(self):
        with pakeproxy(accounts_path=None, accounts_inline=None) as pp:
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
        with pakeproxy() as pp:
            res = proxy_urlopen(pp, self.non_tls_login_url)
            self.check_non_tls_login_url_response(res)
