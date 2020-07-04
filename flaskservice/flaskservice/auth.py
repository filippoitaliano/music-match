import functools
import google.oauth2.credentials
import google_auth_oauthlib.flow
import os
import pickle
import sqlite3
import requests
from dotenv import load_dotenv
from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for, current_app
from flaskservice import db
from flaskservice.models.user import User
from werkzeug.security import check_password_hash, generate_password_hash


load_dotenv()


bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        error = None
        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        alredy_existing_user = User.query.filter_by(username=username).first()

        if alredy_existing_user is not None:
            error = 'User {} is already registered.'.format(username)

        if error is None:
            db.session.add(
                User(username=username, password=generate_password_hash(password)))
            db.session.commit()
            return redirect(url_for('auth.login'))

        flash(error)

    return render_template('auth/register.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        error = None

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user.password, password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            print(user.id)
            session['user_id'] = user.id
            return redirect(url_for('dashboard.dashboard'))

        flash(error)

    return render_template('auth/login.html')


@bp.route('/connect-youtube', methods=["GET"])
def connect_youtube():
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    client_config = {
        "web": {
            "client_id": os.getenv("YT_CLIENT_ID"),
            "project_id": os.getenv("YT_PROJECT_ID"),
            "auth_uri": os.getenv("YT_AUTH_URI"),
            "token_uri": os.getenv("YT_TOKEN_URI"),
            "auth_provider_x509_cert_url": os.getenv("YT_AUTH_PROVIDER_X509_CERT_URL"),
            "client_secret": os.getenv("YT_CLIENT_SECRET"),
            "redirect_uris": [os.getenv("YT_REDIRECT_URIS")],
        }
    }

    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        client_config, ['https://www.googleapis.com/auth/youtube.readonly']
    )

    flow.redirect_uri = 'http://127.0.0.1:5000/auth/connect-youtube-continue'

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')

    return redirect(authorization_url, 302)


@bp.route('/connect-youtube-continue', methods=["GET"])
def connect_youtube_continue():
    # error = request.args.get('error')
    # code = request.args.get('code')

    client_config = {
        "web": {
            "client_id": os.getenv("YT_CLIENT_ID"),
            "project_id": os.getenv("YT_PROJECT_ID"),
            "auth_uri": os.getenv("YT_AUTH_URI"),
            "token_uri": os.getenv("YT_TOKEN_URI"),
            "auth_provider_x509_cert_url": os.getenv("YT_AUTH_PROVIDER_X509_CERT_URL"),
            "client_secret": os.getenv("YT_CLIENT_SECRET"),
            "redirect_uris": [os.getenv("YT_REDIRECT_URIS")],
        }
    }

    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        client_config, ['https://www.googleapis.com/auth/youtube.readonly']
    )

    flow.redirect_uri = 'http://127.0.0.1:5000/auth/connect-youtube-continue'
    flow.fetch_token(authorization_response=request.url)

    User.query.filter_by(id=session['user_id']).update(dict(
        youtube_credentials=sqlite3.Binary(pickle.dumps(flow.credentials, protocol=2))))

    db.session.commit()

    return redirect('/dashboard', 302)


@bp.route('/connect-spotify', methods=["GET"])
def connect_spotify():
    redirect_url = '{}/auth/connect-spotify-continue'.format(
        os.getenv('SP_REDIRECT_URI'))

    return redirect('https://accounts.spotify.com/authorize?client_id={}&redirect_uri={}&response_type=code'.format(os.getenv('SP_CLIENT_ID'),
                                                                                                                    redirect_url), 302)


@bp.route('connect-spotify-continue', methods=["GET"])
def connect_spotify_continue():
    error = request.args.get('error')
    code = request.args.get('code')

    if error is None:
        redirect_url = '{}/auth/connect-spotify-continue'.format(
            os.getenv('SP_REDIRECT_URI'))

        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_url,
            'client_id': os.getenv('SP_CLIENT_ID'),
            'client_secret': os.getenv('SP_CLIENT_SECRET')
        }

        response = requests.post(
            'https://accounts.spotify.com/api/token', data=data)

        User.query.filter_by(id=session['user_id']).update(dict(
            spotify_credentials="response.text"))

        db.session.commit()

        return redirect(url_for('dashboard.dashboard'))

    return 'Si è verificato un errore'


@ bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = User.query.filter_by(id=user_id).first()


@ bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


def login_required(view):
    @ functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view
