import web
import db
import config

t_globals = dict()
render = web.template.render('templates/', cache=config.cache,
                             globals=t_globals)
render._keywords['globals']['render'] = render

def accounts(**k):
    return render.accounts(db.Account.all())
