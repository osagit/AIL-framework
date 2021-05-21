#!/usr/bin/env python3
# -*-coding:UTF-8 -*

'''
    Flask functions and routes for the rest api
'''

##################################
# Import External packages
##################################
import time
import json
from flask import request, Response, jsonify
from functools import wraps
from werkzeug.exceptions import BadRequest, UnprocessableEntity, HTTPException
from werkzeug.http import HTTP_STATUS_CODES

import Flask_config


def requires_validation(validator, with_route_params=False):
    """ Validates an incoming request over given validator.
    If with_route_params is set to True, validator is called with request
    data and args taken from route, otherwise only request data is
    passed to validator. If validator raises any Exception, FpcHttpError is raised.
    """
    def wrapper(function):
        """
        Override method wrapper
        """
        @wraps(function)
        def wrapped(*args, **kwargs):
            """
            Override decorator
            """
            try:
                if with_route_params:
                    validator(request.data, request.args)
                else:
                    validator(request.data)
            except HTTPException as error:
                # raise error
                return jsonify(code=error.code, message=HTTP_STATUS_CODES[error.code], description=str(error.description)), error.code
            except Exception as err:
                # raise BadRequest(err.args)
                return Response(json.dumps(err.args, indent=2, sort_keys=True), mimetype='application/json'), 400

            return function(*args, **kwargs)
        return wrapped
    return wrapper


COMBOLEAK_BY_DOMAIN_PARAMS_MANDATORY = ['perimeters', 'since']
COMBOLEAK_BY_DOMAIN_PARAMS_OPTIONAL = ['account']

def valid_comboleak_get_params(data, args):
    """
    Validation parameter definition for search arguments
    """
    COMBOLEAK_BY_DOMAIN_PARAMS = COMBOLEAK_BY_DOMAIN_PARAMS_MANDATORY + COMBOLEAK_BY_DOMAIN_PARAMS_OPTIONAL
    
    if args and all(x in COMBOLEAK_BY_DOMAIN_PARAMS for x in args):
        errors_description = []
    
        # Match since value
        since = args.get('since')
        if since:
            try:
                time_since = time.strptime(since, "%Y-%m-%dT%H:%M:%S")
                date_timestamp = int(time.mktime(time_since))
            except:
                errors_description.append(f'since must contain a valid ISO 8601 UTC time as 2021-05-17T07:41:24 value, given: {since}')
        
        # Match perimeters values
        perimeters = args.get('perimeters')
        if perimeters:
            perimeters = perimeters.split(";")
            print(Flask_config.COMBOLEAK_PERIMETERS.keys())
            print(perimeters)
            if not( perimeters and any(x in Flask_config.COMBOLEAK_PERIMETERS.keys() for x in perimeters)):
                errors_description.append(f'perimeters must contain at least on valid perimeter, given: {perimeters}')
        
        # Is there validation errors on valid params values 
        if errors_description:
            # Format validation errors and raise an HTTP 400 exception with details
            raise UnprocessableEntity(', '.join(errors_description))

    else: 
        errors_description = f'Search parameters must match following values {COMBOLEAK_BY_DOMAIN_PARAMS}'
        if args:
            errors_description += f', given: {list(args.keys())}'
        # Format validation errors and raise an HTTP 400 exception with details
        raise BadRequest(errors_description)
