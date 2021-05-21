#!/usr/bin/env python3
# -*-coding:UTF-8 -*

'''
    Flask functions and routes for the rest api
'''

##################################
# Import External packages
##################################
import os
import re
import sys
import uuid
import json
import redis
import time
from flask import Flask, render_template, jsonify, request, Blueprint, redirect, url_for, Response, abort
from flask_login import login_required
from functools import wraps
# from flask_swagger_ui import get_swaggerui_blueprint
from redis import ResponseError
# from redisearch import Client
from redisearch import *
from redisearch.aggregation import AggregateRequest, Asc


##################################
# Import Project packages
##################################
sys.path.append(os.path.join(os.environ['AIL_BIN'], 'lib/'))
import Domain
import Import_helper
import Cryptocurrency
import Pgp
import Item
import Paste
import Tag
import Term
sys.path.append(os.path.join(os.environ['AIL_BIN'], 'import'))
import importer
from validators import *
from redis_serializer import *

# ============ VARIABLES ============
import Flask_config


app = Flask_config.app

# Init conf objects
baseUrl = Flask_config.baseUrl
r_cache = Flask_config.r_cache
r_serv_db = Flask_config.r_serv_db
r_serv_onion = Flask_config.r_serv_onion
r_serv_metadata = Flask_config.r_serv_metadata
redis_search_orange = Flask_config.redis_search_orange


restApi = Blueprint('restApi', __name__, template_folder='templates')

# ============ AUTH FUNCTIONS ============

def check_token_format(strg, search=re.compile(r'[^a-zA-Z0-9_-]').search):
    return not bool(search(strg))

def verify_token(token):
    if len(token) != 41:
        return False

    if not check_token_format(token):
        return False

    if r_serv_db.hexists('user:tokens', token):
        return True
    else:
        return False

def get_user_from_token(token):
    return r_serv_db.hget('user:tokens', token)

def verify_user_role(role, token):
    # User without API
    if role == 'user_no_api':
        return False
        
    user_id = get_user_from_token(token)
    if user_id:
        if is_in_role(user_id, role):
            return True
        else:
            return False
    else:
        return False

def is_in_role(user_id, role):
    if r_serv_db.sismember('user_role:{}'.format(role), user_id):
        return True
    else:
        return False

# ============ DECORATOR ============

def token_required(user_role):
    def actual_decorator(funct):
        @wraps(funct)
        def api_token(*args, **kwargs):
            data = authErrors(user_role)
            if data:
                return Response(json.dumps(data[0], indent=2, sort_keys=True), mimetype='application/json'), data[1]
            else:
                return funct(*args, **kwargs)
        return api_token
    return actual_decorator

def get_auth_from_header():
    token = request.headers.get('Authorization').replace(' ', '') # remove space
    return token

def authErrors(user_role):
    # Check auth
    if not request.headers.get('Authorization'):
        return ({'status': 'error', 'reason': 'Authentication needed'}, 401)
    token = get_auth_from_header()
    data = None
    # verify token format

    # brute force protection
    current_ip = request.remote_addr
    login_failed_ip = r_cache.get('failed_login_ip_api:{}'.format(current_ip))
    # brute force by ip
    if login_failed_ip:
        login_failed_ip = int(login_failed_ip)
        if login_failed_ip >= 5:
            return ({'status': 'error', 'reason': 'Max Connection Attempts reached, Please wait {}s'.format(r_cache.ttl('failed_login_ip_api:{}'.format(current_ip)))}, 401)

    try:
        authenticated = False
        if verify_token(token):
            authenticated = True

            # check user role
            if not verify_user_role(user_role, token):
                data = ({'status': 'error', 'reason': 'Access Forbidden'}, 403)

        if not authenticated:
            r_cache.incr('failed_login_ip_api:{}'.format(current_ip))
            r_cache.expire('failed_login_ip_api:{}'.format(current_ip), 300)
            data = ({'status': 'error', 'reason': 'Authentication failed'}, 401)
    except Exception as e:
        print(e)
        data = ({'status': 'error', 'reason': 'Malformed Authentication String'}, 400)
    if data:
        return data
    else:
        return None

# ============ API CORE =============

def create_json_response(data_dict, response_code):
    return Response(json.dumps(data_dict, indent=2, sort_keys=True), mimetype='application/json'), int(response_code)

def get_mandatory_fields(json_data, required_fields):
    for field in required_fields:
        if field not in json_data:
            return {'status': 'error', 'reason': 'mandatory field: {} not provided'.format(field)}, 400
    return None

# ============ FUNCTIONS ============

def is_valid_uuid_v4(header_uuid):
    try:
        header_uuid=header_uuid.replace('-', '')
        uuid_test = uuid.UUID(hex=header_uuid, version=4)
        return uuid_test.hex == header_uuid
    except:
        return False

def one():
    return 1

# ============= ROUTES ==============

# @restApi.route("/api", methods=['GET'])
# @login_required
# def api():
#     return 'api doc'

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# POST
#
# {
#   "id": item_id,      mandatory
#   "content": true,
#   "tags": true,
#
#
# }
#
# response: {
#               "id": "item_id",
#               "tags": [],
#           }
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# @restApi.errorhandler(404)
# def resource_not_found(e):
#     return jsonify(error=str(e)), 404

@restApi.route("api/v1/get/item", methods=['POST'])
@token_required('read_only')
def get_item_id():
    data = request.get_json()
    res = Item.get_item(data)
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]

@restApi.route("api/v1/get/item/default", methods=['POST'])
@token_required('read_only')
def get_item_id_basic():

    data = request.get_json()
    item_id = data.get('id', None)
    req_data = {'id': item_id, 'date': True, 'content': True, 'tags': True}
    res = Item.get_item(req_data)
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# GET
#
# {
#   "id": item_id,      mandatory
# }
#
# response: {
#               "id": "item_id",
#               "tags": [],
#           }
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
@restApi.route("api/v1/get/item/tag", methods=['POST'])
@token_required('read_only')
def get_item_tag():

    data = request.get_json()
    item_id = data.get('id', None)
    req_data = {'id': item_id, 'date': False, 'tags': True}
    res = Item.get_item(req_data)
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# POST
#
# {
#   "id": item_id,      mandatory
#   "tags": [tags to add],
#   "galaxy": [galaxy to add],
# }
#
# response: {
#               "id": "item_id",
#               "tags": [tags added],
#           }
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
@restApi.route("api/v1/add/item/tag", methods=['POST'])
@token_required('analyst')
def add_item_tags():

    data = request.get_json()
    if not data:
        return Response(json.dumps({'status': 'error', 'reason': 'Malformed JSON'}, indent=2, sort_keys=True), mimetype='application/json'), 400

    object_id = data.get('id', None)
    tags = data.get('tags', [])
    galaxy = data.get('galaxy', [])

    res = Tag.api_add_obj_tags(tags=tags, galaxy_tags=galaxy, object_id=object_id, object_type="item")
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# DELETE
#
# {
#   "id": item_id,      mandatory
#   "tags": [tags to delete],
# }
#
# response: {
#               "id": "item_id",
#               "tags": [tags deleted],
#           }
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
@restApi.route("api/v1/delete/item/tag", methods=['DELETE'])
@token_required('analyst')
def delete_item_tags():

    data = request.get_json()
    if not data:
        return Response(json.dumps({'status': 'error', 'reason': 'Malformed JSON'}, indent=2, sort_keys=True), mimetype='application/json'), 400

    object_id = data.get('id', None)
    tags = data.get('tags', [])

    res = Tag.api_delete_obj_tags(tags=tags, object_id=object_id, object_type="item")
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# GET
#
# {
#   "id": item_id,      mandatory
# }
#
# response: {
#               "id": "item_id",
#               "content": "item content"
#           }
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
@restApi.route("api/v1/get/item/content", methods=['POST'])
@token_required('read_only')
def get_item_content():

    data = request.get_json()
    item_id = data.get('id', None)
    req_data = {'id': item_id, 'date': False, 'content': True, 'tags': False}
    res = Item.get_item(req_data)
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # #        TAGS       # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

@restApi.route("api/v1/get/tag/metadata", methods=['POST'])
@token_required('read_only')
def get_tag_metadata():
    data = request.get_json()
    tag = data.get('tag', None)
    if not Tag.is_tag_in_all_tag(tag):
        return Response(json.dumps({'status': 'error', 'reason':'Tag not found'}, indent=2, sort_keys=True), mimetype='application/json'), 404
    metadata = Tag.get_tag_metadata(tag)
    return Response(json.dumps(metadata, indent=2, sort_keys=True), mimetype='application/json'), 200

@restApi.route("api/v1/get/tag/all", methods=['GET'])
@token_required('read_only')
def get_all_tags():
    res = {'tags': Tag.get_all_tags()}
    return Response(json.dumps(res, indent=2, sort_keys=True), mimetype='application/json'), 200

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # #        TRACKER       # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
@restApi.route("api/v1/add/tracker", methods=['POST'])
@token_required('analyst')
def add_tracker_term():
    data = request.get_json()
    user_token = get_auth_from_header()
    user_id = get_user_from_token(user_token)
    res = Term.parse_json_term_to_add(data, user_id)
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]

@restApi.route("api/v1/delete/tracker", methods=['DELETE'])
@token_required('analyst')
def delete_tracker_term():
    data = request.get_json()
    user_token = get_auth_from_header()
    user_id = get_user_from_token(user_token)
    res = Term.parse_tracked_term_to_delete(data, user_id)
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]

@restApi.route("api/v1/get/tracker/item", methods=['POST'])
@token_required('read_only')
def get_tracker_term_item():
    data = request.get_json()
    user_token = get_auth_from_header()
    user_id = get_user_from_token(user_token)
    res = Term.parse_get_tracker_term_item(data, user_id)
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # #        CRYPTOCURRENCY       # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
@restApi.route("api/v1/get/cryptocurrency/bitcoin/metadata", methods=['POST'])
@token_required('read_only')
def get_cryptocurrency_bitcoin_metadata():
    data = request.get_json()
    crypto_address = data.get('bitcoin', None)
    req_data = {'bitcoin': crypto_address, 'metadata': True}
    res = Cryptocurrency.get_cryptocurrency(req_data, 'bitcoin')
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]

@restApi.route("api/v1/get/cryptocurrency/bitcoin/item", methods=['POST'])
@token_required('read_only')
def get_cryptocurrency_bitcoin_item():
    data = request.get_json()
    bitcoin_address = data.get('bitcoin', None)
    req_data = {'bitcoin': bitcoin_address, 'items': True}
    res = Cryptocurrency.get_cryptocurrency(req_data, 'bitcoin')
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # #       PGP       # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
@restApi.route("api/v1/get/pgp/key/metadata", methods=['POST'])
@token_required('read_only')
def get_pgp_key_metadata():
    data = request.get_json()
    pgp_field = data.get('key', None)
    req_data = {'key': pgp_field, 'metadata': True}
    res = Pgp.get_pgp(req_data, 'key')
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]

@restApi.route("api/v1/get/pgp/mail/metadata", methods=['POST'])
@token_required('read_only')
def get_pgp_mail_metadata():
    data = request.get_json()
    pgp_field = data.get('mail', None)
    req_data = {'mail': pgp_field, 'metadata': True}
    res = Pgp.get_pgp(req_data, 'mail')
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]

@restApi.route("api/v1/get/pgp/name/metadata", methods=['POST'])
@token_required('read_only')
def get_pgp_name_metadata():
    data = request.get_json()
    pgp_field = data.get('name', None)
    req_data = {'name': pgp_field, 'metadata': True}
    res = Pgp.get_pgp(req_data, 'name')
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]

@restApi.route("api/v1/get/pgp/key/item", methods=['POST'])
@token_required('read_only')
def get_pgp_key_item():
    data = request.get_json()
    pgp_field = data.get('key', None)
    req_data = {'key': pgp_field, 'items': True}
    res = Pgp.get_pgp(req_data, 'key')
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]

@restApi.route("api/v1/get/pgp/mail/item", methods=['POST'])
@token_required('read_only')
def get_pgp_mail_item():
    data = request.get_json()
    pgp_mail = data.get('mail', None)
    req_data = {'mail': pgp_mail, 'items': True}
    res = Pgp.get_pgp(req_data, 'mail')
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]

@restApi.route("api/v1/get/pgp/name/item", methods=['POST'])
@token_required('read_only')
def get_pgp_name_item():
    data = request.get_json()
    pgp_name = data.get('name', None)
    req_data = {'name': pgp_name, 'items': True}
    res = Pgp.get_pgp(req_data, 'name')
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]

'''



@restApi.route("api/v1/get/item/cryptocurrency/key", methods=['POST'])
@token_required('analyst')
def get_item_cryptocurrency_bitcoin():
    data = request.get_json()
    item_id = data.get('id', None)
    req_data = {'id': item_id, 'date': False, 'tags': False, 'pgp': {'key': True}}
    res = Item.get_item(req_data)
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]

@restApi.route("api/v1/get/item/pgp/mail", methods=['POST'])
@token_required('analyst')
def get_item_cryptocurrency_bitcoin():
    data = request.get_json()
    item_id = data.get('id', None)
    req_data = {'id': item_id, 'date': False, 'tags': False, 'pgp': {'mail': True}}
    res = Item.get_item(req_data)
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]

@restApi.route("api/v1/get/item/pgp/name", methods=['POST'])
@token_required('analyst')
def get_item_cryptocurrency_bitcoin():
    data = request.get_json()
    item_id = data.get('id', None)
    req_data = {'id': item_id, 'date': False, 'tags': False, 'pgp': {'name': True}}
    res = Item.get_item(req_data)
    return Response(json.dumps(res[0], indent=2, sort_keys=True), mimetype='application/json'), res[1]
'''

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # #        DOMAIN       # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
@restApi.route("api/v1/get/domain/status/minimal", methods=['POST'])
@token_required('analyst')
def get_domain_status_minimal():
    data = request.get_json()
    domain = data.get('domain', None)
    # error handler
    res = Domain.api_verify_if_domain_exist(domain)
    if res:
        return create_json_response(res[0], res[1])
    res = Domain.api_get_domain_up_range(domain)
    res[0]['domain'] = domain
    return create_json_response(res[0], res[1])

@restApi.route("api/v1/get/crawled/domain/list", methods=['POST'])
@token_required('analyst')
def get_crawled_domain_list():
    data = request.get_json()
    res = get_mandatory_fields(data, ['date_from', 'date_to'])
    if res:
        return create_json_response(res[0], res[1])

    date_from = data.get('date_from', None)
    date_to = data.get('date_to', None)
    domain_type = data.get('domain_type', None)
    domain_status = 'UP'
    res = Domain.api_get_domains_by_status_daterange(date_from, date_to, domain_type)
    dict_res = res[0]
    dict_res['date_from'] = date_from
    dict_res['date_to'] = date_to
    dict_res['domain_status'] = domain_status
    dict_res['domain_type'] = domain_type
    return create_json_response(dict_res, res[1])

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # #        IMPORT     # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #




# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# POST JSON FORMAT
#
# {
#   "type": "text",         (default value)
#   "tags": [],             (default value)
#   "default_tags": True,    (default value)
#   "galaxy" [],            (default value)
#   "text": "",             mandatory if type = text
# }
#
# response: {"uuid": "uuid"}
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
@restApi.route("api/v1/import/item", methods=['POST'])
@token_required('analyst')
def import_item():

    data = request.get_json()
    if not data:
        return Response(json.dumps({'status': 'error', 'reason': 'Malformed JSON'}, indent=2, sort_keys=True), mimetype='application/json'), 400

    # unpack json
    text_to_import = data.get('text', None)
    if not text_to_import:
        return Response(json.dumps({'status': 'error', 'reason': 'No text supplied'}, indent=2, sort_keys=True), mimetype='application/json'), 400

    tags = data.get('tags', [])
    if not type(tags) is list:
        tags = []
    galaxy = data.get('galaxy', [])
    if not type(galaxy) is list:
        galaxy = []

    if not Tag.is_valid_tags_taxonomies_galaxy(tags, galaxy):
        return Response(json.dumps({'status': 'error', 'reason': 'Tags or Galaxy not enabled'}, indent=2, sort_keys=True), mimetype='application/json'), 400

    default_tags = data.get('default_tags', True)
    if default_tags:
        tags.append('infoleak:submission="manual"')

    if sys.getsizeof(text_to_import) > 900000:
        return Response(json.dumps({'status': 'error', 'reason': 'Size exceeds default'}, indent=2, sort_keys=True), mimetype='application/json'), 413

    UUID = str(uuid.uuid4())
    Import_helper.create_import_queue(tags, galaxy, text_to_import, UUID)

    return Response(json.dumps({'uuid': UUID}, indent=2, sort_keys=True), mimetype='application/json')

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# GET
#
# {
#   "uuid": "uuid",      mandatory
# }
#
# response: {
#               "status": "in queue"/"in progress"/"imported",
#               "items": [all item id]
#           }
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
@restApi.route("api/v1/get/import/item", methods=['POST'])
@token_required('analyst')
def import_item_uuid():
    data = request.get_json()
    UUID = data.get('uuid', None)

    # Verify uuid
    if not is_valid_uuid_v4(UUID):
        return Response(json.dumps({'status': 'error', 'reason': 'Invalid uuid'}), mimetype='application/json'), 400

    data = Import_helper.check_import_status(UUID)
    if data:
        return Response(json.dumps(data[0]), mimetype='application/json'), data[1]

    return Response(json.dumps({'status': 'error', 'reason': 'Invalid response'}), mimetype='application/json'), 400

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
@restApi.route("api/v1/import/json/item", methods=['POST'])
@token_required('user')
def import_json_item():

    data_json = request.get_json()
    res = importer.api_import_json_item(data_json)
    return Response(json.dumps(res[0]), mimetype='application/json'), res[1]

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
@restApi.route("api/v1/ping", methods=['GET'])
@token_required('read_only')
def v1_ping():
    return Response(json.dumps({'status': 'pong'}), mimetype='application/json'), 200



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# GET
#
# {
#   "id": item_id,      mandatory
# }
#
# response: {
#               "id": "item_id",
#               "tags": [],
#           }
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
object_dict = lambda o: {key.lstrip('_'): value for key, value in o.__dict__.items()}

@restApi.route("api/v1/comboleak", methods=['GET'])
@token_required('read_only')
@requires_validation(valid_comboleak_get_params, with_route_params=True)
def get_comboleaks():
    """
    Return combo leaks
    need params perimeters and since
    """
    result = 'pong'

    # TODO validate entry with wrapper
    perimeters = request.args.get('perimeters')
    perimeters = perimeters.split(";")
    print(f'perimeters {perimeters}')

    domain_searched = []
    for perim in perimeters:
        print(perim)
        if perim in Flask_config.COMBOLEAK_PERIMETERS.keys():
            domain_searched = unionlst(domain_searched, Flask_config.COMBOLEAK_PERIMETERS.get(perim))
    
    if domain_searched:

        print(f'domain_searched {domain_searched}')

        # modifiedList = list(map(lambda x: x + '_' , list1))
        searchstr = " | ".join(domain_searched)
        searchstr = searchstr.replace(".", "\\.")
        searchstr = searchstr.replace("-", "\\-")
        # searchstr = f'@domain_tld:{{ {searchstr} }}'
        print(searchstr)
        # Extract all perimeters
        # domains = '|'.join(perimeters)

        # Extract iso date as timestamp
        # Unix timestamps in seconds localtime
        since = request.args.get('since')
        result = time.strptime(since, "%Y-%m-%dT%H:%M:%S")
        date_timestamp = int(time.mktime(result))
        print(date_timestamp)

        query = f'@domain_tld:{{ {searchstr} }}'

        account = request.args.get('account')
        if account:
            account = account.replace(".", "\\.")
            account = account.replace("-", "\\-")
            query += f'@local:{{ {account} }}'

        # Load redisearch client
        client = Client('myrecidx', port=6383)

        try:

            # TODO test perf with filter in dedicated perimeter index vs generic index with query

            # FT.CREATE myrecidx ON HASH PREFIX 1 comboleak:record: first_seen NUMERIC domain_tld TAG local TAG
            
            # TODO return only a part of cipher_email ?
            # 
            # f'@domain_tld:{{ {searchstr} }}'
            # searchstr = 'ymail\\.com | gmail\\.com'
            q2 = Query(query).add_filter(NumericFilter('first_seen', date_timestamp, NumericFilter.INF, minExclusive=True)).sort_by('first_seen', asc=True).paging(0, 10000).return_fields('cid', 'local', 'domain_tld', 'first_seen', 'cipher_password')

            redis_resp = client.search(q2)
            # print(redis_resp)
            if redis_resp:
                print(redis_resp.total)
                result = json.dumps(redis_resp, allow_nan=False, sort_keys=False, indent=4, cls=MyEncoder)

        except ResponseError as err:
            # Index does not exist. We need to create it!
            result = err
    else:
        # 404 Not Found
        print(json.dumps('{"error":"not found", "error_description:"The perimeter(s) does not exist"}'))
        return Response(json.dumps({'error':'not found', 'error_description':'The perimeter(s) does not exist'}, indent=2, sort_keys=True), mimetype='application/json'), 404

    return Response(result, mimetype='application/json'), 200


@restApi.route("api/v1/comboleak/<leak_id>", methods=['GET'])
@token_required('read_only')
# @requires_validation(valid_comboleak_get_params, with_route_params=True)
def get_one_comboleak(leak_id):
    """
    Return a combo leak from given id
    """
    result = 'pong'
    print(f'{leak_id}')
    # Load redis client
    try:
        result = redis_search_orange.hgetall(f'comboleak:record:{leak_id}')

        if result:
            print(result)
            result = json.dumps(result, allow_nan=False, sort_keys=False, indent=4)
        else:
            # 404 Not Found
            print(json.dumps('{"error":"not found", "error_description:"The leak id does not exist"}'))
            return Response(json.dumps({'error':'not found', 'error_description':'The leak id does not exist'}, indent=2, sort_keys=True), mimetype='application/json'), 404

    except ResponseError as err:
        # Index does not exist. We need to create it!
        result = err

    return Response(result, mimetype='application/json'), 200


@restApi.route("api/v1/comboleak/domain", methods=['GET'])
@token_required('read_only')
def get_comboleaks_bydomain():
    """
    api/v1/comboleak/domain?since=2021-05-17T07:41:24&domain=hotmail&tld=com
    Return combo leaks
    need params perimeters and since
    """
    result = 'pong'

    # TODO validate entry with wrapper
    domain = request.args.get('domain')
    print(f'domain {domain}')

    tld = request.args.get('tld')
    print(f'tld {tld}')

    query = f'@domain:%{domain}% @tld:%{tld}%'

    variant = request.args.get('variant')
    if variant and variant=='true':
        print(f'variant {variant}')
        query += f' -@domain:{domain}'

    print(query)

    # Extract iso date as timestamp
    # Unix timestamps in seconds localtime
    since = request.args.get('since')
    result = time.strptime(since, "%Y-%m-%dT%H:%M:%S")
    date_timestamp = int(time.mktime(result))
    print(date_timestamp)

    recindex = 'reclevenidx'

    # Load redisearch client
    client = Client(recindex, port=6383)

    try:

        # FT.CREATE reclevenidx ON HASH PREFIX 1 "comboleak:record:" SCHEMA domain TEXT NOSTEM SORTABLE tld TEXT NOSTEM SORTABLE first_seen NUMERIC
        # TODO don't filter on tld if not provided
        # FT.SEARCH reclevenidx '@domain:%wanadoo% @tld:%fr% -@domain:wanadoo' FILTER first_seen 1621230084 +inf RETURN 1 email SORTBY first_seen LIMIT 0 10
        #  -@domain:{domain}
        q2 = Query(query).add_filter(NumericFilter('first_seen', date_timestamp, NumericFilter.INF, minExclusive=True)).sort_by('first_seen', asc=True).paging(0, 10000).return_fields('cid', 'local', 'domain_tld', 'first_seen', 'cipher_password')

        redis_resp = client.search(q2)
        # print(redis_resp)
        if redis_resp:
            # redis_resp.__class__ = ComboLeakResult
            # print(redis_resp.diameter())
        
            # print(redis_resp.total)
            # print(type(redis_resp))
            # result = json.dumps(redis_resp, default=object_dict, allow_nan=False, sort_keys=False, indent=4)

            result = json.dumps(redis_resp, allow_nan=False, sort_keys=False, indent=4, cls=MyEncoder)

    except ResponseError as err:
        # Index does not exist. We need to create it!
        result = err

    return Response(result, mimetype='application/json'), 200


# def serialize_custom_object(o):
#     res = o.__dict__.copy()
#     res['machines'] = res['_machines']
#     del res['_machines']
#     return res

# json.dumps(object, sort_keys=True,indent=4, separators=(',', ': '), 
#            default=serialize_custom_object)

class MyEncoder(json.JSONEncoder):
    def default(self, o):
        # print(o.total)
        # for x in o.docs:
        #     print(x.id)
        # return {'total': o.total}
        return {'total': o.total, 'leaks': [self.to_json(x) for x in o.docs]}
    def to_json(self, doc):
        """
        Build JSON representation of the Demand
        """
        serializer = JsonSerializer()
        serializer.start_object(doc.cid)
        serializer.add_property("account", doc.local)
        serializer.add_property("domain_tld", doc.domain_tld)
        serializer.add_property("first_seen", int(doc.first_seen))
        serializer.add_property("cipher_password", doc.cipher_password)

        return serializer._json_object

class ComboLeakResult(Result):
    def diameter(self):
        return self.total*2


class ComplexEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ComboLeakResult):
            return {'total': obj.total }
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)

# Python program to illustrate union
# Without repetition 
def unionlst(lst1, lst2):
    final_list = list(set(lst1) | set(lst2))
    return final_list

# ========= REGISTRATION =========
app.register_blueprint(restApi, url_prefix=baseUrl)
