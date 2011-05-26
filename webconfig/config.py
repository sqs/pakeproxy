import os
import web

cache = False
if 'ACCOUNTS_PATH' not in globals():
    ACCOUNTS_PATH = os.path.expanduser('~/.pakeproxy/')

