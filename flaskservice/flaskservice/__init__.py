from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object('config.Config')

    db.init_app(app)

    with app.app_context():
        from .models import user

        from . import auth
        app.register_blueprint(auth.bp)

        from . import dashboard
        app.register_blueprint(dashboard.bp)

        @app.route('/')
        def index():
            return render_template('root.html')

        db.create_all()

        return app
