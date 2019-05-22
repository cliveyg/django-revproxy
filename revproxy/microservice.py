# microservice.py
# this module is basically a function based version of the ProxyView class

from rest_framework import status
from rest_framework.response import Response
from django.utils.six.moves.urllib.parse import urlparse, urlencode, quote_plus
from django.conf import settings
#from django.views.decorators.csrf import csrf_exempt

import requests
from requests.auth import HTTPBasicAuth

from .utils import normalize_request_headers, encode_items

# get an instance of a logger
import logging
logger = logging.getLogger('apiserver')

QUOTE_SAFE = r'<.;>\(}*+|~=-$/_:^@)[{]&\'!,"`'
HOP_BY_HOP_HEADERS = ['Connection',
                      'Keep-Alive',
                      'Proxy-Authenticate',
                      'Proxy-Authorization',
                      'TE',
                      'Trailers',
                      'Transfer-Encoding',
                      'Content-Length',
                      'Upgrade']

# -----------------------------------------------------------------------------

def fetch_data(**kwargs):

    logger.info("in fetch data")
    request = kwargs['request']
    upstream_urls = kwargs['upstream_urls']

    #TODO: Use proper authentication for calls to microservices
    # temporarily using a fake token
    token = settings.TOKEN

    return _dispatch(request, upstream_url)

# -----------------------------------------------------------------------------

def _dispatch(request, upstream_url):

    logger.info("attempting to dispatch upstream...")

    request_payload = request.body

    if request.GET:
        upstream_url += '?' + get_encoded_query_params()

    request_headers = get_request_headers(request)

    try:
        # 'requests' is a different library so we need to get the response 
        # from 'requests' and create a django response object from this
        # we are using requests due to problems with https proxying in urllib3
        upstream_repsonse = requests.get(upstream_url, headers=request_headers)

    except requests.exceptions as error:
        logger.error(error)
        #message = { 'message': 'Unable to complete request', 'status': status.HTTP_500_INTERNAL_SERVER_ERROR }
        #return Response(message, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return { upstream_repsonse, requests }

    #return _create_django_response_from_requests(upstream_repsonse)

# -----------------------------------------------------------------------------

def _create_django_response_from_requests(response):

    logger.info("In create_django_response_from_requests")

    headers = _build_headers(response.headers)

    return Response(response.json(), headers=headers, status=response.status_code)


# -----------------------------------------------------------------------------
# need to remove any hop-by-hop headers and django says no to these and kicks
# up a fuss

def _build_headers(headers):
    
    new_headers = {}

    for (key, value) in headers.items():
        if key not in HOP_BY_HOP_HEADERS:
            new_headers[key] = value

    return new_headers

# -----------------------------------------------------------------------------

def get_proxy_request_headers(request):
    """Get normalized headers for the upstream
    Gets all headers from the original request and normalizes them.
    Normalization occurs by removing the prefix ``HTTP_`` and
    replacing and ``_`` by ``-``. Example: ``HTTP_ACCEPT_ENCODING``
    becames ``Accept-Encoding``.
    .. versionadded:: 0.9.1
    :param request:  The original HTTPRequest instance
    :returns:  Normalized headers for the upstream
    """
    return normalize_request_headers(request)

# -----------------------------------------------------------------------------

def get_request_headers(request):
    """Return request headers that will be sent to upstream.
    The header REMOTE_USER is set to the current user
    if AuthenticationMiddleware is enabled and
    the view's add_remote_user property is True.
    .. versionadded:: 0.9.8
    """
    request_headers = get_proxy_request_headers(request)

    return request_headers

# -----------------------------------------------------------------------------

def get_quoted_path(path):
    """Return quoted path to be used in proxied request"""
    return quote_plus(path.encode('utf8'), QUOTE_SAFE)

# -----------------------------------------------------------------------------

def get_encoded_query_params(request):
    """Return encoded query params to be used in proxied request"""
    get_data = encode_items(request.GET.lists())
    return urlencode(get_data)

# -----------------------------------------------------------------------------




