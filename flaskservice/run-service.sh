#!/bin/bash

source venv/bin/activate
export FLASK_APP=flaskservice
export FLASK_ENV=development
flask run
