"""API error responses"""

from networktools import app
from flask import jsonify  # pylint: disable=import-error


@app.errorhandler(400)
def bad_request(msg):
    """
    Error handler for Bad Request (400)
    :param msg: Human readable error message
    :return: JSON formatted API response with return code
    """
    response = dict(
        status='error',
        msg=str(msg)
    )
    return jsonify(response), 400


@app.errorhandler(403)
def forbidden(msg):
    """
    Error handler for Forbidden (403)
    :param msg: Human readable error message
    :return: JSON formatted API response with return code
    """
    response = dict(
        status='error',
        msg=str(msg)
    )
    return jsonify(response), 403


@app.errorhandler(404)
def page_not_found(msg):
    """
    Error handler for Page Not Found (404)
    :param msg: Human readable error message
    :return: JSON formatted API response with return code
    """
    response = dict(
        status='error',
        msg=str(msg)
    )
    return jsonify(response), 404


@app.errorhandler(405)
def method_not_allowed(msg):
    """
    Error handler for Method Not Allowed (405)
    :param msg: Human readable error message
    :return: JSON formatted API response with return code
    """
    response = dict(
        status='error',
        msg=str(msg)
    )
    return jsonify(response), 405


@app.errorhandler(418)
def im_a_teapot(msg):
    """
    Error handler for I'm a teapot (418)
    :param msg: Human readable error message
    :return: JSON formatted API response with return code
    """
    response = dict(
        status='error',
        msg=str(msg)
    )
    return jsonify(response), 418


@app.errorhandler(500)
def internal_server_error(msg):
    """
    Error handler for Internal Server Error (500)
    :param msg: Human readable error message
    :return: JSON formatted API response with return code
    """
    response = dict(
        status='error',
        msg=str(msg)
    )
    return jsonify(response), 500


@app.errorhandler(503)
def service_unavailable(msg):
    """
    Error handler for Service Unavailable (503)
    :param msg: Human readable error message
    :return: JSON formatted API response with return code
    """
    response = dict(
        status='error',
        msg=str(msg)
    )
    return jsonify(response), 503




