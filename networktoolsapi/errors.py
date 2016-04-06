from networktoolsapi import app
from flask import jsonify


@app.errorhandler(400)
def bad_request(msg):
    response = dict(
        status='error',
        msg=str(msg)
    )
    return jsonify(response), 400


@app.errorhandler(403)
def forbidden(msg):
    response = dict(
        status='error',
        msg=str(msg)
    )
    return jsonify(response), 403


@app.errorhandler(404)
def page_not_found(msg):
    response = dict(
        status='error',
        msg=str(msg)
    )
    return jsonify(response), 404


@app.errorhandler(405)
def method_not_allowed(msg):
    response = dict(
        status='error',
        msg=str(msg)
    )
    return jsonify(response), 405


@app.errorhandler(418)
def im_a_teapot(msg):
    response = dict(
        status='error',
        msg=str(msg)
    )
    return jsonify(response), 418


@app.errorhandler(500)
def internal_server_error(msg):
    response = dict(
        status='error',
        msg=str(msg)
    )
    return jsonify(response), 500


@app.errorhandler(503)
def service_unavailable(msg):
    response = dict(
        status='error',
        msg=str(msg)
    )
    return jsonify(response), 503




