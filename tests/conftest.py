import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))
os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret-key-for-pytest')
