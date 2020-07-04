import google.oauth2.credentials
import google_auth_oauthlib.flow
import os
from flask import Blueprint, render_template, redirect, current_app

bp = Blueprint('dashboard', __name__, url_prefix="/dashboard")

@bp.route('/', methods=["GET"])
def dashboard():
  return render_template('dashboard/dashboard.html')
  