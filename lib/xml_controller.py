#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Xml class"""
import xml.etree.ElementTree as ET
import re


class Xml(object):
    """Xml class"""
    def remove_namespace(self, raw_xml):
        return re.sub('xmlns[^>]*', '', raw_xml, count=1)

    def xml_to_hash(self, raw_xml):
        xml = ET.fromstring(self.remove_namespace(raw_xml))

        result = {}
        for child in xml.iter():
            if child.tag == 'Data':
                result[child.attrib['Name']] = child.text
            else:
                result[child.tag] = child.text
        return result
