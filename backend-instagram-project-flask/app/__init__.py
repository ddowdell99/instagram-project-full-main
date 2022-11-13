from flask import Flask
from config import Config
from flask_migrate import Migrate
from .models import db, User
from flask_moment import Moment
from flask_cors import CORS

# import blueprint
from .auth.routes import auth
from .ig.routes import ig

app = Flask(__name__)
moment = Moment(app)
CORS(app)



app.config.from_object(Config)

# registering your blueprint
app.register_blueprint(auth)
app.register_blueprint(ig)



# initialize our database to work with our app
db.init_app(app)
migrate = Migrate(app, db)


from . import routes
from . import models