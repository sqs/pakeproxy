import web
import view, config, db
from view import render

urls = (
    '/', 'accounts'
)
app = web.application(urls, globals())

class accounts:
    def GET(self):
        return render.base(view.accounts())

    def POST(self):
        data = web.input()
        acct = db.Account(data['host'], data['user'], data['passwd'])
        acct.save()
        return self.GET()

if __name__ == "__main__":
    app.internalerror = web.debugerror
    app.run()
