#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Xml class"""
import xml.etree.ElementTree as ET
import re


class Xml(object):
    """Xml class"""
    def remove_namespace(self, raw_xml):
        return re.sub('xmlns[^>]*', '', raw_xml, count=1)

    def to_hash(self, raw_xml):
        xml = ET.fromstring(self.remove_namespace(raw_xml))

        result = {}
        for child in xml.iter():
            if child.tag == 'Data' and 'Name' in child.attrib:
                result[child.attrib['Name']] = child.text
            elif not child.text:
                result[child.tag] = child.attrib
            else:
                result[child.tag] = child.text
        return result
