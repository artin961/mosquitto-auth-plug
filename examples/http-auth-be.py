#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__    = 'Jan-Piet Mens <jp@mens.de>'
__copyright__ = 'Copyright 2014 Jan-Piet Mens'

import sys
import bottle
import json
from bottle import response, request
from urllib.parse import unquote

app = application = bottle.Bottle()


@app.route('/api/broker/auth', method='POST')
def auth():
    response.content_type = 'application/json'
    response.status = 403
    data = bottle.request.body.read()
    data = unquote(data)
    print(data)
    jj=json.loads(data)

#    if jj['username'] == 'device' and jj['password'] == '1234':
    response.status = 200

    return None

@app.route('/api/broker/sup', method='POST')
def superuser():
    response.content_type = 'application/json'
    response.status = 403

    data = bottle.request.body.read()   # username=jane%40mens.de&password=&topic=&acc=-1
    data = unquote(data)
    print(data)
    jj=json.loads(data)


    if jj['username'] == 'device':
        response.status = 200

    return None


@app.route('/api/broker/acl', method='POST')
def acl():
    response.content_type = 'application/json'
    response.status = 403
    
    data = bottle.request.body.read()   # username=jane%40mens.de&password=&topic=t%2F1&acc=2&clientid=JANESUB
    
    data = unquote(data)
    print(data)
    jj=json.loads(data)
    #if  jj['topic'] == 'device/aabccaabbcc/commands':
    response.status = 200

    return None

if __name__ == '__main__':

    bottle.debug(True)
    bottle.run(app,
        # server='python_server',
        host= "127.0.0.1",
        port= 8089)
