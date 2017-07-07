#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Event helper class"""
from lib.xml_controller import Xml
import lib.loadyaml as loadyaml
import re


class EventHelper(object):
    """Event helper class"""
    def __init__(self):
        self.xml = Xml()
        self.configs = loadyaml.load_cef()

    def parse_server_label(self, event):
        """parse server label for ec2 instance and account id"""
        if "server_label" in event:
            search = re.search('(^\d+)_(i.+)', str(event['server_label']))
            if search:
                return {
                    'ec2_account_id': search.group(1),
                    'ec2_instance_id': search.group(2)
                }

    def build_event_id(self, event):
        """use windows channel id if exists"""
        if self.is_lids(event) and event["server_platform"] == 'Windows':
            xml = self.xml.to_hash(event['original_log_entry'])
            if 'EventID' in xml:
                return xml['EventID']
        return self.configs["eventIdMap"][event["type"]]

    def is_lids(self, event):
        """check if events is lids"""
        if event['type'] == 'lids_rule_failed':
            return True

    def select_custom_mapping(self, event):
        """select platform mapping based on event type and platform"""
        if self.is_lids(event) and event['server_platform'] == 'Windows':
            return self.configs['windowsLidsMapping']
        return self.configs['linuxLidsMapping']
