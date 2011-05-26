import shutil, tempfile, os, unittest
from contextlib import contextmanager
from paste.fixture import TestApp
from nose.tools import *
from site import app
import config, db

@contextmanager
def tempaccount(*args):
    acct = db.Account(*args)
    acct.save()
    yield acct
    acct.delete()

class TestSite(unittest.TestCase):
    testApp = TestApp(app.wsgifunc())
    
    def setUp(self):
        config.ACCOUNTS_PATH = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(config.ACCOUNTS_PATH)
    
    def test_index(self):
        r = self.testApp.get('/')
        assert_equal(r.status, 200)
        r.mustcontain('PAKEProxy')

    def test_entry(self):
        with tempaccount('a.com', 'user', 'passwd') as acct:
            r = self.testApp.get('/')
            r.mustcontain('value="a.com"')
            r.mustcontain('value="user"')
            r.mustcontain('value="passwd"')

    def test_edit(self):
        with tempaccount('a.com', 'user', 'passwd') as acct:
            postdata = {
                'host': 'a.com',
                'user': 'user2',
                'passwd': 'passwd2'
            }
            r = self.testApp.post('/', postdata)
            r.mustcontain('value="a.com"')
            self.assertNotIn('value="user"', r)
            r.mustcontain('value="user2"')
            self.assertNotIn('value="passwd"', r)
            r.mustcontain('value="passwd2"')
            
    def test_new(self):
        r = self.testApp.get('/')
        self.assertNotIn('value="b.com"', r)
        self.assertNotIn('value="user3"', r)
        self.assertNotIn('value="passwd3"', r)
        postdata = {
            'host': 'b.com',
            'user': 'user3',
            'passwd': 'passwd3'
        }
        r = self.testApp.post('/', postdata)
        r.mustcontain('value="b.com"')
        r.mustcontain('value="user3"')
        r.mustcontain('value="passwd3"')
            
