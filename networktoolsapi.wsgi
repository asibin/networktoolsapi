#!/usr/bin/python

# Activate virtualenv
activate_this = '~/venvs/networktoolsapi/bin/activate_this.py'
execfile(activate_this, dict(__file__=activate_this))

import os
import sys

# Append application to path
sys.path.append(os.path.join(os.path.dirname(__name__), 'networktoolsapi'))

# Import the actual app
from networktools import app as application