#!/usr/bin/env python3
# -*-coding:UTF-8 -*

'''
    Flask functions and routes for the trending modules page
'''
##################################
# Import External packages
##################################
import os
import logging
import logging.handlers
import redis
from flask import Flask, Response, render_template, jsonify, request, Blueprint, stream_with_context
from flask_login import login_required, current_user
import json
import random
import time
from datetime import datetime, timedelta
from gevent import Timeout
from enum import Enum

##################################
# Import Project packages
##################################
import Flask_config
import ConfigLoader
from Role_Manager import login_admin, login_read_only
from flask import jsonify


class CompanyNames(Enum):
    """
    All company names available
    """
    ORANGE = "Orange"
    GAFA = "Gafa"
    FRENCHISP = "FrenchIsp"
    FOREIGNCIE = "ForeignCie"
    ACADEMIC = "Academic"
    BANK = "Bank"
    MISC = "Misc"

    @staticmethod
    def value_of(value) -> Enum:
        """
        Return the corresponding enum of the string value
        default Misc 
        """
        result = CompanyNames.MISC
        for key, enumitem in CompanyNames.__members__.items():
            if key.upper() == value.upper():
                result = enumitem
                break
        return result


# ============ VARIABLES ============

app = Flask_config.app
baseUrl = Flask_config.baseUrl

comboleak = Blueprint('comboleak', __name__, template_folder='templates')


# log_dir = os.path.join(os.environ['AIL_HOME'], 'logs')
# if not os.path.isdir(log_dir):
#     os.makedirs(logs_dir)
# log_filename = os.path.join(log_dir, 'flask_server.logs')
# logger = logging.getLogger()
# formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
# handler_log = logging.handlers.TimedRotatingFileHandler(log_filename, when="midnight", interval=1)
# handler_log.suffix = '%Y-%m-%d.log'
# handler_log.setFormatter(formatter)
# handler_log.setLevel(10)
# logger.addHandler(handler_log)
# logger.setLevel(10)

logger = Flask_config.redis_logger


pie_labels = [
    'Orange', 'Wanadoo', 'Other'
]

colors = ['#ff7900', '#50be87', '#4bb4e6']


# ============= ROUTES ==============

@comboleak.route("/comboleak/<company_name>", methods=['GET'])
@login_required
@login_read_only
def index_page(company_name):
    """
    Index page of company credentials
    """
    # Get the Company Name Enum from the URL 
    company_name = CompanyNames.value_of(company_name)

    # Get User id
    user_id = current_user.get_id()
    logger.debug(f'userid: {user_id}')

    # SortedSet of Credentials IDs (Salted email password HMAC)
    REDIS_KEY_CREDENTIALS_INDEX_SORTEDSET = f'credentials:{company_name.value.lower()}:index'

    total_credential_found = Flask_config.redis_ardb_orange.zcard(REDIS_KEY_CREDENTIALS_INDEX_SORTEDSET)
    logger.debug(f'total_credential_found: {total_credential_found}')
    print('total_credential_found: ', total_credential_found)

    # Daily uniq leak 
    now_day = time.strftime("%Y%m%d", time.localtime())
    daily_leak_unicity = Flask_config.redis_ardb_orange.zscore(f'{company_name.value.lower()}:stat:dailyleakunicity', now_day)
    daily_leak_unicity = daily_leak_unicity if daily_leak_unicity else "0"

    # SortedSet for domains stat
    REDIS_KEY_CREDENTIALS_DOMAIN_SORTEDSET = f'credentials:{company_name.value.lower()}:stat:domain'
    domain_pie_json, domain_pie_labels = render_pie(REDIS_KEY_CREDENTIALS_DOMAIN_SORTEDSET)

    # SortedSet for sources stat
    REDIS_KEY_CREDENTIALS_SOURCE_SORTEDSET = f'credentials:{company_name.value.lower()}:stat:source'
    source_pie_json, source_pie_labels = render_pie(REDIS_KEY_CREDENTIALS_SOURCE_SORTEDSET)

    chart_daily = leaktrends_chart_data(company_name.value.lower(), 15)

    return render_template("comboleak.html", chart_data=chart_daily, company_name=company_name.value, domain_pie_json=domain_pie_json, domain_labels_colors=domain_pie_labels, source_pie_json=source_pie_json, source_labels_colors=source_pie_labels, user_id=user_id, total_credential_found=total_credential_found, daily_leak_unicity=daily_leak_unicity)


def render_pie(redis_key):
    
    # Retrieve the top 5 keys ? or all
    key_sorted = Flask_config.redis_ardb_orange.zrevrangebyscore(redis_key, float('Inf'), float(0), withscores=True)
    logger.debug(f'redis_key: {key_sorted}')
    print('redis_key: ', key_sorted)
    
    pie_label = []
    pie_scores = []

    for label, score in key_sorted:
        print(label, score)
        pie_label.append(label)
        pie_scores.append(score)

    print(pie_scores)

    backgroundColor = ['#ff7900', '#50be87', '#4bb4e6','#ffcc00', '#000000', '#ffffff', '#5a5c69', '#cd3c14']
    hoverBackgroundColor = ['#f16e00', '#32c832', '#527edb','#ffcc00', '#000000', '#ffffff', '#5a5c69', '#cd3c14']

    nb_colors = len(backgroundColor)
    labels_colors = []
    bgc = []
    hbgc = []
    for index, item in enumerate(pie_label):
        labels_colors.append({'name': f'{item}', 'color': f'{backgroundColor[index%nb_colors]}'})
        bgc.append(backgroundColor[index%nb_colors])
        hbgc.append(hoverBackgroundColor[index%nb_colors])

    # TODO get the top 5 and sum others
    pie_data = {
            'labels': pie_label,
            'datasets': [{
                'data': pie_scores,
                'backgroundColor': bgc,
                'hoverBackgroundColor': hbgc,
                'hoverBorderColor': '#eaeced'
            }]
        }
  
    print(pie_data)
    pie_json = json.dumps(pie_data, sort_keys = False, indent = 2)

    return pie_json, labels_colors


def leaktrends_chart_data(company_name, nb_days=7):    
    # SortedSet for daily leak stat
    redis_key = f'credentials:{company_name}:stat:dailyleak'

    now = datetime.now()

    # One day interval
    interval = 3600*24

    data = []
    currdate = now.strftime('%Y%m%d')
    print('nb days %s'%nb_days)
    for x in range(0, nb_days):
        score = Flask_config.redis_ardb_orange.zscore(redis_key, currdate)
        score = score if score else 0

        data.append({'x': currdate, 'y': score})

        now -= timedelta(days=1)
        currdate = now.strftime('%Y%m%d')

        json_data = json.dumps(data)

    print(json_data)
    return json_data


@comboleak.route("/comboleak/<company_name>/leaktrend-chart-data/<nb_days>", methods=['GET'])
@login_required
@login_read_only
def chart_data(company_name, nb_days=7):
    """
    Chart data random
    nb_days: get stats back from number of days given till now 
    """
    # Get the Company Name Enum from the URL 
    company_name = CompanyNames.value_of(company_name)

    try:
        nb_days = int(nb_days)
        if  nb_days not in [7, 15, 31]:
            raise ValueError
    except ValueError:
        nb_days = 7

    chart_daily = leaktrends_chart_data(company_name.value.lower(), nb_days)
 
    return Response(chart_daily, mimetype='application/json')


@comboleak.route("/comboleak/<company_name>/daily-data", methods=['GET'])
@login_required
@login_read_only
# def daily_data(company_name: CompanyName, defaults={'company_name': CompanyName.orange}):
def daily_data(company_name):
    """
    Stream daily data
    """
    # Get the Company Name Enum from the URL 
    company_name = CompanyNames.value_of(company_name)
    print(company_name.value)
    
    def get_daily_data(company_name):
        curdate = datetime.now().strftime("%Y%m%d")
        paste_stat = 'paste_by_modules_in:ComboLeak'
        print(paste_stat)
        while True:
            # LOAD Redis/ARDB Gafa
            daily_paste = Flask_config.r_serv_statistics.hget(curdate,paste_stat)
            # print(daily_paste)
            json_data = json.dumps(
                {'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'value': daily_paste})
            yield f"data:{json_data}\n\n"
            time.sleep(5)

    return Response(get_daily_data(company_name.value), mimetype='text/event-stream')


@comboleak.route("/comboleak/<company_name>/logs")
@login_required
@login_read_only
def logs(company_name):
    """
    Stream module logs
    """
    # Get the Company Name Enum from the URL 
    company_name = CompanyNames.value_of(company_name)

    def event_stream(company_name):
        pubsub = Flask_config.r_serv_log.pubsub()
        pubsub.psubscribe('script:%s.*')
        try:
            with Timeout(30) as timeout:
                for msg in pubsub.listen():
                    type = msg['type']
                    # pattern = msg['pattern']
                    data = msg['data']
                    level = (msg['channel']).split('.')[1]

                    msg = {'level': level, 'type': type, 'data': data}

                    # if msg['type'] == 'pmessage' and level != "DEBUG":
                    yield 'data: %s\n\n' % json.dumps(msg)
                    
                    timeout.cancel()
                    timeout.start()
        except Timeout as t:
            if t is not timeout:
                raise
            else:
                yield ":\n\n"  # heartbeat
        except GeneratorExit:
            print('closed')
        except:
            print('closed')

    return Response(stream_with_context(event_stream(company_name.value)), mimetype='text/event-stream')


# ========= REGISTRATION =========
app.register_blueprint(comboleak, url_prefix=baseUrl)
