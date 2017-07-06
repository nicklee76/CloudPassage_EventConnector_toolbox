#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Cef class"""
from lib.options import Options
from lib.xml_controller import Xml
import lib.loadyaml as loadyaml
import datetime
import re


class Cef(object):
    """Cef class"""
    def __init__(self, options=None):
        self.options = options or Options()
        self.configs = loadyaml.load_cef()
        self.xml = Xml()

    def cef_constants(self, event):
        """build cef constants"""
        severity = 9 if event["critical"] else 3
        return "CEF:%s|%s|%s|%s|%s|%s|%s|" % (self.configs["cefVersion"],
                                              self.configs["cefVendor"],
                                              self.configs["cefProduct"],
                                              self.configs["cefProductVersion"],
                                              self.build_event_id(event),
                                              event["name"],
                                              severity)

    def build_cef_outliers(self, mapping, event):
        """build cef outliers"""
        mapping['deviceDirection'] = 1 if 'actor_username' in event else 0
        server_label = self.parse_server_label(event)
        if server_label:
            mapping[self.configs['cefFieldMapping']['ec2_account_id']] = server_label['ec2_account_id']
            mapping[self.configs['cefFieldMapping']['ec2_instance_id']] = server_label['ec2_instance_id']

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
        if self.event_is_lids(event) and event["server_platform"] == 'Windows':
            xml = self.xml.to_hash(event['original_log_entry'])
            if 'EventID' in xml:
                return xml['EventID']
        return self.configs["eventIdMap"][event["type"]]

    def format_cef_date(self, date):
        """format cef date"""
        date_time = datetime.datetime.strptime(date, '%Y-%m-%dT%H:%M:%S.%fZ')
        return date_time.strftime('%b %d %Y %H:%M:%S UTC')

    def build_cef_mapping(self, event):
        """build cef mapping"""
        mapping = {}
        self.build_cef_outliers(mapping, event)
        for key, value in self.configs['cefFieldMapping'].items():
            if key in event:
                if key == "created_at":
                    cef_date = self.format_cef_date(event[key])
                    mapping[value] = cef_date
                else:
                    mapping[value] = event[key]
                del event[key]
        if event:
            mapping["cs1Label"] = "extras"
            mapping["cs1"] = event
        return mapping

    def build_lids_mapping(self, event):
        """build lids mapping"""
        mapping = {}
        self.build_cef_outliers(mapping, event)
        platform = event['server_platform']
        if platform == 'Windows':
            event.update(self.xml.to_hash(event['original_log_entry']))

        schema = self.select_lids_platform_mapping(platform)
        for key, value in schema.items():
            if key in event:
                mapping[value] = event[key]
        return mapping

    def select_lids_platform_mapping(self, platform):
        """select lids platform mapping"""
        if platform == 'Linux':
            return self.configs['linuxLidsMapping']
        return self.configs['windowsLidsMapping']

    def event_is_lids(self, event):
        """check if events is lids"""
        if event['type'] == 'lids_rule_failed':
            return True

    def escape_specials(self, cef_str):
        """escape special characters"""
        formatted = cef_str.replace("\\","\\\\")
        formatted = cef_str.replace("=","\\=")

        return formatted

    def build_custom_schema(self, event):
        """build schema based on event type"""
        if self.event_is_lids(event):
            return self.build_lids_mapping(event)
        return self.build_cef_mapping(event)

    def format_cef(self, batched):
        """format cef"""
        aggregated_cef = []
        for event in batched:
            cef_str = ""
            constants_map = self.cef_constants(event)
            schema = self.build_custom_schema(event)

            for key, value in schema.items():
                cef_str += "%s=%s " % (key, self.escape_specials(str(value)))
            aggregated_cef.append("%s%s" % (constants_map, cef_str))
        return aggregated_cef
