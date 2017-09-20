#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Sumo class"""
import lib.loadyaml as loadyaml
import requests
import sys


class Sumologic(object):
    def __init__(self):
        self.configs = loadyaml.load_portal()
        self.max_retry = 3

    def https_forwarder(self, data):
        reply = requests.post(self.configs['sumologic_https_url'], data=data)
        reply_status_code = reply.status_code
        num_attempts = 1

        while (reply.status_code != 200) and (num_attempts < self.max_retry):
            reply = requests.post(self.configs['sumologic_https_url'], data=data)
            reply_status_code = reply.status_code

            num_attempts += 1
            if num_attempts == self.max_retry:
                print ('[Error] HTTPS POST %d to SumoLogic failed. Resp: %s' % (reply_status_code, reply))
                sys.exit(1)
