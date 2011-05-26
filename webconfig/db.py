import os, re
import config

class Account(object):
    @staticmethod
    def filepath(host):
        return os.path.join(config.ACCOUNTS_PATH, host)
    
    @classmethod
    def all(klass):
        return [klass.from_file(Account.filepath(host))
                for host in os.listdir(config.ACCOUNTS_PATH)]
        
    def __init__(self, host, user, passwd):
        self.host = host
        self.user = user
        self.passwd = passwd

    def save(self):
        self.__check_filename()
        with open(Account.filepath(self.host), 'w') as f:
            f.write('%s,%s' % (self.user, self.passwd))

    def delete(self):
        self.__check_filename()
        path = Account.filepath(self.host)
        if os.path.exists(path):
            os.unlink(path)

    def __check_filename(self):
        if re.search(r'[^a-zA-Z0-9.-]', self.host):
            raise Exception("host has illegal chars: '%s'" % self.host)

    @classmethod
    def from_file(klass, path):
        with open(path, 'r') as f:
            parts = f.read().strip().split(',', 1)
            if parts and len(parts) == 2:
                user, passwd = parts[0], parts[1]
            else:
                user, passwd = None, None
            host = os.path.basename(path)
            return klass(host, user, passwd)
