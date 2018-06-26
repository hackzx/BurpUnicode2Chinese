#!/usr/bin/env python
# coding=utf8
from burp import IBurpExtender
from burp import IHttpListener

import re

print 'Unicode To 中文'


class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Unicode To Chinese Test")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == 64 or toolFlag == 16 or toolFlag == 32:
            if not messageIsRequest:
                response = messageInfo.getResponse()
                analyzedResponse = self._helpers.analyzeResponse(response)
                headers = analyzedResponse.getHeaders()
                new_headers = []
                for header in headers:
                    if header.startswith("Content-Type:"):
                        new_headers.append(header.replace('iso-8859-1', 'utf-8'))
                    else:
                        new_headers.append(header)

                body = response[analyzedResponse.getBodyOffset():]
                body_string = body.tostring().decode('utf8').encode('unicode_escape')
                body_string = re.sub(r'(\\\\u)([\w\d]{4})', r'\\u\2', body_string)
                new_body = body_string.decode('unicode_escape').encode('utf8')
                messageInfo.setResponse(self._helpers.buildHttpMessage(new_headers, new_body))
