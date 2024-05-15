from flask import request
from flask_smorest import Blueprint, abort
from flask_jwt_extended import get_jwt_identity, jwt_required
from API.Keys.models import APIKeyModel
from API.Analytics.service import calculate_rounded_delta, calculate_rate, calculate_ratio, \
    calculate_rounded_sum_by_instance, calculate_rate_sum_by_instance, calculate_ratio_sum_by_instance, \
    get_delta_over_time, get_delta_per_hour, colective_calculate_ratio
from API.Auth import UserModel
import os
from dotenv import load_dotenv

load_dotenv()
prometheus_url = os.getenv('PROMETHEUS_URL')

blp = Blueprint("analytics", __name__, description="Usage Analytics")

@blp.route('/collective_endpoint_analytics', methods=['POST'])
@jwt_required()
def collective_endpoint_analytics():
    """
       Returns daily analytics for all endpoints in a json indexed by api key
       ---
       tags:
            - Analytics
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
       responses:
         200:
           description: Sucessfully returned endpoint analytics for organisation.
         400:
           description: Failed to return weekly analytics for organisation.
       """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    api_keys = APIKeyModel.query.filter_by(org_id=user.org_id).with_entities(APIKeyModel.api_key).all()
    api_names_list = [api_key for api_key, in api_keys]

    # Metric name for API key requests
    api_key_metric_name = 'requests_by_api_key'

    # API key to query (replace this with your variable API key)
    label_name = 'org_id'
    api_key = user.org_id
    day_rounded_delta = colective_calculate_ratio(label_name, api_key, prometheus_url, api_key_metric_name, 24 * 60 * 60,api_names_list)

    Analytics = {
                 "1day": day_rounded_delta}

    return Analytics



@blp.route('/endpoint_analytics', methods=['POST'])
@jwt_required()
def endpoint_analytics():
    """
       Returns analytics for a given API_key
       ---
       tags:
            - Analytics
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
         - in: body
           name: body
           description: API key to return analytics on.
           required: true
           schema:
             type: object
             required:
               - api_key
             properties:
               api_key:
                 type: string
       responses:
         200:
           description: Sucessfully returned endpoint analytics.
         400:
           description: Failed to return weekly analytics.
       """
    endpoint_data = request.get_json()
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    api_keys = APIKeyModel.query.filter_by(org_id=user.org_id).with_entities(APIKeyModel.api_key).all()
    api_names_list = [api_key for api_key, in api_keys]

    if endpoint_data["api_key"] not in api_names_list:
        abort(500, message="API key not found!")

    # Metric name for API key requests
    api_key_metric_name = 'requests_by_api_key'

    # API key to query (replace this with your variable API key)
    label_name = 'api_key'
    api_key = endpoint_data["api_key"]

    day_rounded_delta = calculate_rounded_delta(label_name, api_key, prometheus_url, api_key_metric_name, 24 * 60 * 60)
    hour_rounded_delta = calculate_rounded_delta(label_name, api_key, prometheus_url, api_key_metric_name, 1 * 60 * 60)
    week_rounded_delta = calculate_rounded_delta(label_name, api_key, prometheus_url, api_key_metric_name, 7 * 24 * 60 * 60)
    month_rounded_delta = calculate_rounded_delta(label_name, api_key, prometheus_url, api_key_metric_name, 28 * 7 * 24 * 60 * 60)
    day_rounded_rate = calculate_rate(label_name, api_key, prometheus_url, api_key_metric_name, 24 * 60 * 60)
    hour_rounded_rate = calculate_rate(label_name, api_key, prometheus_url, api_key_metric_name, 1 * 60 * 60)
    week_rounded_rate = calculate_rate(label_name, api_key, prometheus_url, api_key_metric_name, 7 * 24 * 60 * 60)
    month_rounded_rate = calculate_rate(label_name, api_key, prometheus_url, api_key_metric_name, 28 * 7 * 24 * 60 * 60)
    hour_ratio_value = calculate_ratio(label_name, api_key, prometheus_url, "requests_by_api_key", 1 * 60 * 60)
    day_ratio_value = calculate_ratio(label_name, api_key, prometheus_url, "requests_by_api_key", 24 * 60 * 60)
    week_ratio_value = calculate_ratio(label_name, api_key, prometheus_url, "requests_by_api_key", 7 * 24 * 60 * 60)
    month_ratio_value = calculate_ratio(label_name, api_key, prometheus_url, "requests_by_api_key", 28 * 7 * 24 * 60 * 60)

    Analytics = {"calls": {"hour": hour_rounded_delta, "day": day_rounded_delta, "week": week_rounded_delta,
                           "month": month_rounded_delta},
                 "rates": {"hour": hour_rounded_rate, "day": day_rounded_rate, "week": week_rounded_rate,
                           "month": month_rounded_rate},
                 "success": {"hour": round(hour_ratio_value["ratio"],5), "day": round(day_ratio_value["ratio"],5),
                             "week": round(week_ratio_value["ratio"],5), "month": round(month_ratio_value["ratio"],5)},
                 "success_raw": {
                     "hour": {"success": hour_ratio_value["successful"], "error": hour_ratio_value["errors"]},
                     "day": {"success": day_ratio_value["successful"], "error": day_ratio_value["errors"]},
                     "week": {"success": week_ratio_value["successful"], "error": week_ratio_value["errors"]},
                     "month": {"success": month_ratio_value["successful"], "error": month_ratio_value["errors"]}}}

    # Print the rounded delta
    return Analytics


@blp.route('/endpoints_analytics', methods=['POST'])
@jwt_required()
def endpoints_analytics():
    """
       Returns analytics for a given organisation
       ---
       tags:
            - Analytics
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
       responses:
         200:
           description: Sucessfully returned endpoint analytics for organisation.
         400:
           description: Failed to return weekly analytics for organisation.
       """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)
    api_keys = APIKeyModel.query.filter_by(org_id=user.org_id).with_entities(APIKeyModel.api_key).all()
    api_names_list = [api_key for api_key, in api_keys]

    # Metric name for API key requests
    api_key_metric_name = 'requests_by_api_key'

    # API key to query (replace this with your variable API key)
    label_name = 'org_id'
    api_key = user.org_id

    day_rounded_delta = calculate_rounded_sum_by_instance(label_name, api_key, prometheus_url, api_key_metric_name,
                                                          24 * 60 * 60)
    hour_rounded_delta = calculate_rounded_sum_by_instance(label_name, api_key, prometheus_url, api_key_metric_name,
                                                           1 * 60 * 60)
    week_rounded_delta = calculate_rounded_sum_by_instance(label_name, api_key, prometheus_url, api_key_metric_name,
                                                           7 * 24 * 60 * 60)
    month_rounded_delta = calculate_rounded_sum_by_instance(label_name, api_key, prometheus_url, api_key_metric_name,
                                                           28 * 7 * 24 * 60 * 60)
    day_rounded_rate = calculate_rate_sum_by_instance(label_name, api_key, prometheus_url, api_key_metric_name,
                                                      24 * 60 * 60)
    hour_rounded_rate = calculate_rate_sum_by_instance(label_name, api_key, prometheus_url, api_key_metric_name,
                                                       1 * 60 * 60)
    week_rounded_rate = calculate_rate_sum_by_instance(label_name, api_key, prometheus_url, api_key_metric_name,
                                                       7 * 24 * 60 * 60)
    month_rounded_rate = calculate_rate_sum_by_instance(label_name, api_key, prometheus_url, api_key_metric_name,
                                                       28 * 7 * 24 * 60 * 60)
    hour_ratio_value = calculate_ratio_sum_by_instance(label_name, api_key, prometheus_url, "requests_by_api_key",
                                                       1 * 60 * 60)
    day_ratio_value = calculate_ratio_sum_by_instance(label_name, api_key, prometheus_url, "requests_by_api_key",
                                                      24 * 60 * 60)
    week_ratio_value = calculate_ratio_sum_by_instance(label_name, api_key, prometheus_url, "requests_by_api_key",
                                                       7 * 24 * 60 * 60)
    month_ratio_value = calculate_ratio_sum_by_instance(label_name, api_key, prometheus_url, "requests_by_api_key",
                                                       28 * 7 * 24 * 60 * 60)

    Analytics = {"calls": {"hour": hour_rounded_delta, "day": day_rounded_delta, "week": week_rounded_delta, "month": month_rounded_delta},
                 "rates": {"hour": hour_rounded_rate, "day": day_rounded_rate, "week": week_rounded_rate, "month": month_rounded_rate},
                 "success": {"hour": round(hour_ratio_value["ratio"],5), "day": round(day_ratio_value["ratio"],5),
                             "week": round(week_ratio_value["ratio"],5), "month": round(month_ratio_value["ratio"],5)},
                 "success_raw": {
                     "hour": {"success": hour_ratio_value["successful"], "error": hour_ratio_value["errors"]},
                     "day": {"success": day_ratio_value["successful"], "error": day_ratio_value["errors"]},
                     "week": {"success": week_ratio_value["successful"], "error": week_ratio_value["errors"]},
                     "month": {"success": month_ratio_value["successful"], "error": month_ratio_value["errors"]}}}

    # Print the rounded delta
    return Analytics


@blp.route('/endpoints_analytics_overtime', methods=['POST'])
@jwt_required()
def endpoints_weekly_analytics():
    """
       Returns weekly analytics for all of a users keys
       ---
       tags:
            - Analytics
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
         - in: body
           name: body
           description: Number of days to grab data for
           required: true
           schema:
             type: object
             required:
               - offset
             properties:
               offset:
                 type: string
       responses:
         200:
           description: Sucessfully returned weekly analytics.
         400:
           description: Failed to return weekly analytics.
       """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)
    endpoint_data = request.get_json()

    label_name = 'org_id'
    metric_name = 'requests_by_api_key'

    # API key for Prometheus query (replace with your API key)
    api_key = user.org_id

    Analytics = get_delta_over_time(metric_name, prometheus_url, api_key, label_name, int(endpoint_data["offset"]),org_id=user.org_id)

    # Print the rounded delta
    return Analytics


@blp.route('/endpoints_analytics_hourly', methods=['POST'])
@jwt_required()
def endpoints_hourly_analytics():
    """
       Returns hourly usage for all of the users keys
       ---
       tags:
            - Analytics
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
       responses:
         200:
           description: returned json of hourly stats.
       """
    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    label_name = 'org_id'
    metric_name = 'requests_by_api_key'

    # API key for Prometheus query (replace with your API key)
    api_key = user.org_id

    Analytics = get_delta_per_hour(metric_name, prometheus_url, api_key, label_name)

    # Print the rounded delta
    return Analytics


@blp.route('/endpoint_analytics_overtime', methods=['POST'])
@jwt_required()
def endpoint_weekly_analytics():
    """
       Returns weekly analytics for all of a users keys
       ---
       tags:
            - Analytics
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
         - in: body
           name: body
           description: Number of days to grab data for
           required: true
           schema:
             type: object
             required:
               - offset
               - api_key
             properties:
               offset:
                 type: string
               api_key:
                 type: string
       responses:
         200:
           description: Sucessfully returned weekly analytics.
         400:
           description: Failed to return weekly analytics.
       """
    endpoint_data = request.get_json()
    if endpoint_data is None or "api_key" not in endpoint_data:
        abort(500, message="Invalid args")

    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    api_keys = APIKeyModel.query.filter_by(org_id=user.org_id).with_entities(APIKeyModel.api_key).all()
    api_names_list = [api_key for api_key, in api_keys]

    if endpoint_data["api_key"] not in api_names_list:
        abort(500, message="API key not found!")

    label_name = 'api_key'
    metric_name = 'requests_by_api_key'

    # API key for Prometheus query (replace with your API key)
    api_key = endpoint_data["api_key"]

    Analytics = get_delta_over_time(metric_name, prometheus_url, api_key, label_name, int(endpoint_data["offset"]))

    # Print the rounded delta
    return Analytics


@blp.route('/endpoint_analytics_hourly', methods=['POST'])
@jwt_required()
def endpoint_hourly_analytics():
    """
       Returns hourly usage for all of the users keys
       ---
       tags:
            - Analytics
       parameters:
         - in: header
           name: Authorization
           description: Type in the 'Value' input box below 'Bearer &lt;JWT&gt;', where JWT is the token
         - in: body
           name: body
           description: API key to return analytics on.
           required: true
           schema:
             type: object
             required:
               - api_key
             properties:
               api_key:
                 type: string
       responses:
         200:
           description: returned json of hourly stats.
       """
    endpoint_data = request.get_json()
    if endpoint_data is None or "api_key" not in endpoint_data:
        abort(500, message="Invalid args")

    current_user = get_jwt_identity()
    user = UserModel.query.get(current_user)

    api_keys = APIKeyModel.query.filter_by(org_id=user.org_id).with_entities(APIKeyModel.api_key).all()
    api_names_list = [api_key for api_key, in api_keys]

    if endpoint_data["api_key"] not in api_names_list:
        abort(500, message="API key not found!")

    label_name = 'api_key'
    metric_name = 'requests_by_api_key'

    # API key for Prometheus query (replace with your API key)
    api_key = endpoint_data["api_key"]

    Analytics = get_delta_per_hour(metric_name, prometheus_url, api_key, label_name)

    # Print the rounded delta
    return Analytics
