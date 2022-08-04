from flask import Flask, Response, jsonify, request

from .errors import errors
from .versions import versions
from .trusted_list import trusted_list
from .parties import parties
from .token import token_endpoint

app = Flask(__name__)

# Register error handler
app.register_blueprint(errors)

# Register routes
app.register_blueprint(versions)
app.register_blueprint(trusted_list)
app.register_blueprint(parties)
app.register_blueprint(token_endpoint)

# Register health endpoint
@app.route("/health")
def health():
    return Response("OK", status=200)

