from prometheus_api_client import PrometheusConnect
from math import ceil
import datetime
import os
from dotenv import load_dotenv
from API.Analytics.models import AnalyticsModel
from DB import db

load_dotenv()
prometheus_url = os.getenv('PROMETHEUS_URL')

def calculate_rounded_delta(label_name, label_value, prometheus_url, metric_name, query_range_seconds):
    # Initialize Prometheus connection
    prom = PrometheusConnect(url=prometheus_url)

    # Define the Prometheus query with the specified label name and value as variables
    query = f'increase({metric_name}{{{label_name}="{label_value}"}}[{query_range_seconds}s])'

    # Fetch the result from Prometheus
    result = prom.custom_query(query)

    # Extract the delta value from the result
    if result:
        delta_value = float(result[0]['value'][1])
    else:
        delta_value = 0

    # Round the delta value using ceil to ensure rounding up to the nearest integer
    rounded_delta = ceil(delta_value)

    return rounded_delta

def colective_calculate_ratio(label_name, label_value, prometheus_url, metric_name, query_range_seconds, api_keys):
    returnData = {}

    for api_key in api_keys:
        returnData[api_key] = {
            "ratio": 100,
            "successful": 0,
            "errors": 0
        }

    prom = PrometheusConnect(url=prometheus_url)

    # Define the Prometheus query to calculate the delta of requests with status=200
    success_query = f'increase({metric_name}{{{label_name}="{label_value}", status="200"}}[{query_range_seconds}s])'

    # Define the Prometheus query to calculate the delta of all requests (any status)
    error_query = f'increase({metric_name}{{{label_name}="{label_value}", status!="200"}}[{query_range_seconds}s])'

    # Fetch the result from Prometheus for successful requests
    success_result = prom.custom_query(success_query)

    # Fetch the result from Prometheus for total requests (any status)
    error_result = prom.custom_query(error_query)

    # Extract the delta value of successful requests (status=200) from the result
    if success_result:
        for result in success_result:
            api = result['metric']['api_key']
            success_delta = round(float(result['value'][1]))
            error_delta = 0
            ratio = 100.0
            if error_result:
                for error in error_result:
                    if error['metric']['api_key'] == api:
                        error_delta = round(float(error_result[0]['value'][1]))
                        break
            if error_delta + success_delta > 0:
                ratio = (success_delta / (error_delta + success_delta)) * 100

            returnData[api] = {
                "ratio": ratio,
                "successful": success_delta,
                "errors": error_delta
            }

    return returnData

def calculate_rounded_sum_by_instance(label_name, label_value, prometheus_url, metric_name, query_range_seconds):
    # Initialize Prometheus connection
    prom = PrometheusConnect(url=prometheus_url)

    # Define the Prometheus query to calculate sum by instance
    query = f'round(sum by(instance) (increase({metric_name}{{{label_name}="{label_value}"}}[{query_range_seconds}s])), 1)'

    # Fetch the result from Prometheus
    result = prom.custom_query(query)

    # Extract the rounded sum by instance from the result
    if result:
        rounded_sum_by_instance = float(result[0]['value'][1])
    else:
        rounded_sum_by_instance = 0  # Handle case where result is empty or invalid

    return rounded_sum_by_instance

def calculate_rate_sum_by_instance(label_name, label_value, prometheus_url, metric_name, query_range_seconds):
    # Initialize Prometheus connection
    prom = PrometheusConnect(url=prometheus_url)

    # Define the Prometheus query to calculate the rate for the specified API key
    query = f'sum by(org) (rate({metric_name}{{{label_name}="{label_value}"}}[{query_range_seconds}s]))'

    # Fetch the result from Prometheus
    result = prom.custom_query(query)

    # Extract the rate value from the result
    if result:
        rate_value = float(result[0]['value'][1])
    else:
        rate_value = 0

    return round(rate_value,6)

def calculate_rate(label_name, label_value, prometheus_url, metric_name, query_range_seconds):
    # Initialize Prometheus connection
    prom = PrometheusConnect(url=prometheus_url)

    # Define the Prometheus query to calculate the rate for the specified API key
    query = f'rate({metric_name}{{{label_name}="{label_value}"}}[{query_range_seconds}s])'

    # Fetch the result from Prometheus
    result = prom.custom_query(query)

    # Extract the rate value from the result
    if result:
        rate_value = float(result[0]['value'][1])
    else:
        rate_value = 0

    return round(rate_value,6)

def calculate_ratio(label_name, label_value, prometheus_url, metric_name, query_range_seconds):
    # Initialize Prometheus connection
    prom = PrometheusConnect(url=prometheus_url)

    # Define the Prometheus query to calculate the delta of requests with status=200
    success_query = f'increase({metric_name}{{{label_name}="{label_value}", status="200"}}[{query_range_seconds}s])'

    # Define the Prometheus query to calculate the delta of all requests (any status)
    error_query = f'increase({metric_name}{{{label_name}="{label_value}", status!="200"}}[{query_range_seconds}s])'

    # Fetch the result from Prometheus for successful requests
    success_result = prom.custom_query(success_query)

    # Fetch the result from Prometheus for total requests (any status)
    error_result = prom.custom_query(error_query)

    # Extract the delta value of successful requests (status=200) from the result
    if success_result:
        success_delta = round(float(success_result[0]['value'][1]))
    else:
        success_delta = 0.0  # If no successful requests, set delta to 0

    # Extract the delta value of total requests (any status) from the result
    if error_result:
        error_delta = round(float(error_result[0]['value'][1]))
    else:
        error_delta = 0.0  # If no total requests, set delta to 0

    # Calculate the ratio of successful requests (status=200) to total requests
    if error_delta + success_delta > 0:
        ratio = (success_delta / (error_delta + success_delta)) * 100
    else:
        ratio = 100.0  # If no total requests, set ratio to 100

    # Return the result as a dictionary
    return {
        "ratio": ratio,
        "successful": success_delta,
        "errors": error_delta
    }

def calculate_ratio_sum_by_instance(label_name, label_value, prometheus_url, metric_name, query_range_seconds):
    # Initialize Prometheus connection
    prom = PrometheusConnect(url=prometheus_url)

    # Define the Prometheus query to calculate the delta of requests with status=200
    success_query = f'sum by(org) (increase({metric_name}{{{label_name}="{label_value}", status="200"}}[{query_range_seconds}s]))'

    # Define the Prometheus query to calculate the delta of all requests (any status)
    error_query = f'sum by(org) (increase({metric_name}{{{label_name}="{label_value}", status!="200"}}[{query_range_seconds}s]))'

    # Fetch the result from Prometheus for successful requests
    success_result = prom.custom_query(success_query)

    # Fetch the result from Prometheus for total requests (any status)
    error_result = prom.custom_query(error_query)

    # Extract the delta value of successful requests (status=200) from the result
    if success_result:
        success_delta = float(success_result[0]['value'][1])
    else:
        success_delta = 0.0  # If no successful requests, set delta to 0

    # Extract the delta value of total requests (any status) from the result
    if error_result:
        error_delta = float(error_result[0]['value'][1])
    else:
        error_delta = 0.0  # If no total requests, set delta to 0

    # Calculate the ratio of successful requests (status=200) to total requests
    if error_delta > 0:
        ratio = (success_delta / (error_delta + success_delta)) * 100
    else:
        ratio = 100.0  # If no total requests, set ratio to 100

    return {"ratio" : ratio, "successful": round(success_delta), "errors": round(error_delta)}

def calculate_daily_delta(metric_name, prometheus_url, api_key, label_name, offset_days):
    # Calculate the start and end time for the query based on the offset
    end_time = datetime.datetime.now() - datetime.timedelta(days=offset_days)
    start_time = end_time - datetime.timedelta(days=1) # Previous day for daily data

    # Set start time to midnight (00:00) of the specified day
    start_time = datetime.datetime.combine(start_time.date(), datetime.time.min) + datetime.timedelta(hours=23) + datetime.timedelta(minutes=58)

    # Set end time to midnight (00:00) of the day after the specified day
    end_time = datetime.datetime.combine(end_time.date(), datetime.time.min)

    # Initialize Prometheus connection
    prom = PrometheusConnect(url=prometheus_url)

    # Define the Prometheus query to calculate delta for the specified metric on a per-day basis
    querySuccess = f'sum by(org) (increase({metric_name}{{{label_name}="{api_key}", status="200"}}[1d]))'
    queryError = f'sum by(org) (increase({metric_name}{{{label_name}="{api_key}", status!="200"}}[1d]))'

    # Fetch the result from Prometheus
    # Do a 1min step and then take the last element (i.e. the last minuite of that day)
    querySuccess = prom.custom_query_range(querySuccess, start_time=start_time, end_time=end_time, step='1m')
    queryError = prom.custom_query_range(queryError, start_time=start_time, end_time=end_time, step='1m')

    # Extract delta values from the result
    if querySuccess:
        delta_Success = round(float(querySuccess[0]['values'][-1][1]))
    else:
        delta_Success = 0

    if queryError:
        delta_Error = round(float(querySuccess[0]['values'][-1][1]))
    else:
        delta_Error = 0

    return {"success": delta_Success, "error": delta_Error}

def get_delta_over_time(metric_name, prometheus_url, api_key, label_name, offset, org_id=None):
    # Dictionary to store delta values indexed by date
    delta_dict = {}

    # Iterate over the offset
    for i in range(offset):
        # Calculate offset days (0 means today, 1 means yesterday, 2 means two days ago, etc.)
        offset_days = i

        # Calculate the date for the current day
        date = (datetime.datetime.now() - datetime.timedelta(days=offset_days+1)).date()

        # check if we have a match in the DB
        if label_name == "org_id":
            filter_criteria = {"org": org_id, "date": str(date)}
        else:
            filter_criteria = {label_name: api_key, "date": str(date)}
        cache = AnalyticsModel.query.filter_by(**filter_criteria).first()
        if not cache:
            # Calculate daily delta for the current day
            delta_values = calculate_daily_delta(metric_name, prometheus_url, api_key, label_name, offset_days)

            # Store delta values in the dictionary indexed by date
            delta_dict[str(date)] = delta_values
            if label_name == "org_id":
                org = AnalyticsModel(
                    org=org_id,
                    date=str(date),
                    success=delta_values["success"],
                    errors=delta_values["error"],
                    finalised=True
                )
            else:
                org = AnalyticsModel(
                    api_key=api_key,
                    date=str(date),
                    success=delta_values["success"],
                    errors=delta_values["error"],
                    finalised=True
                )
            db.session.add(org)
            db.session.commit()

        else:
            delta_dict[str(date)] = {"success": cache.success, "error": cache.errors}

    return delta_dict

def calculate_houly_delta(metric_name, prometheus_url, api_key, label_name):
    # Calculate the start and end time for the query based on the offset
    end_time = datetime.datetime.now()
    start_time = end_time - datetime.timedelta(days=1) # Previous day for daily data

    minutes_past_hour = end_time.minute + end_time.second / 60.0 + end_time.microsecond / 60000000.0

    # If minutes_past_hour is greater than 0, round up to the next hour
    if minutes_past_hour > 0:
        # Add the remaining minutes to reach the next hour
        delta_minutes = 60 - minutes_past_hour
        end_time += datetime.timedelta(minutes=delta_minutes)

    # Set minutes, seconds, and microseconds to zero for precision
    end_time = end_time.replace(minute=0, second=0, microsecond=0)

    minutes_past_hour = start_time.minute + start_time.second / 60.0 + start_time.microsecond / 60000000.0

    # If minutes_past_hour is greater than 0, round up to the next hour
    if minutes_past_hour > 0:
        # Add the remaining minutes to reach the next hour
        delta_minutes = 60 - minutes_past_hour
        start_time += datetime.timedelta(minutes=delta_minutes)

    start_time = start_time.replace(minute=0, second=0, microsecond=0)


    # Initialize Prometheus connection
    prom = PrometheusConnect(url=prometheus_url)

    # Define the Prometheus query to calculate delta for the specified metric on a per-day basis
    querySuccess = f'sum by(org) (increase({metric_name}{{{label_name}="{api_key}", status="200"}}[1h]))'
    queryError = f'sum by(org) (increase({metric_name}{{{label_name}="{api_key}", status!="200"}}[1h]))'

    # Fetch the result from Prometheus
    # Do a 1min step and then take the last element (i.e. the last minuite of that day)
    resultSuccess = prom.custom_query_range(querySuccess, start_time=start_time, end_time=end_time, step='1h')
    resultError = prom.custom_query_range(queryError, start_time=start_time, end_time=end_time, step='1h')
    output = {}
    current_hour = start_time
    while current_hour <= end_time:
        # Format current hour to match the key format
        hour_key = current_hour.strftime("%Y-%m-%d %H:%M:%S")

        # Add the hour to the dictionary with some default value (e.g., None)
        output[hour_key] = {"success": 0, "errors": 0}

        # Move to the next hour
        current_hour += datetime.timedelta(hours=1)


    if resultSuccess:
        for sublist in resultSuccess[0]['values']:
            if len(sublist) >= 2:
                timestamp_unix = sublist[0]
                value = sublist[1]

                # Convert UNIX timestamp to datetime
                timestamp_datetime = datetime.datetime.fromtimestamp(timestamp_unix)

                # Add to dictionary
                output[str(timestamp_datetime)] = {"success": round(float(value)), "errors": 0}

    if resultError:
        for sublist in resultError[0]['values']:
            if len(sublist) >= 2:
                timestamp_unix = sublist[0]
                value = sublist[1]

                # Convert UNIX timestamp to datetime
                timestamp_datetime = datetime.datetime.fromtimestamp(timestamp_unix)

                # Add to dictionary
                output[str(timestamp_datetime)]["errors"] =round(float(value))

    return output

def get_delta_per_hour (metric_name, prometheus_url, api_key, label_name):
    # Dictionary to store delta values indexed by date
    delta_dict = {}

    delta_values = calculate_houly_delta(metric_name, prometheus_url, api_key, label_name)

    return delta_values