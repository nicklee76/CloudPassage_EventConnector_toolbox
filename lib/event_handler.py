#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys, requests
from event_handlers import monitoredEvents


class EventHandler(object):
    def __init__(self):
        self.max_retry = 3

    def event_parser(self, event):
        # print ("%s - %s" % (event['type'], event['name']))
        return_message = monitoredEvents.events_classification[event['type']]['lib'].parse_event(event['name'])
        print return_message

