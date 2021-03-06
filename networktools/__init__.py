"""
Flask application init
"""

from flask import Flask

app = Flask(__name__)

app.config.from_object('networktools.settings')

from networktools import api  # pylint: disable=wrong-import-position
