import cloudpassage
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../', 'lib'))
from event_helper import EventHelper


class TestUnitEventHelper:
    def create_ehelper_object(self):
        ehelper = EventHelper()
        return ehelper

    def windows_lids_stub(self):
        stub = {
            "id": "abc123abc123abc123abc123",
            "type": "lids_rule_failed",
            "name": "Log-based intrusion detection rule matched",
            "message": "Log-based intrusion detection msg",
            "server_id": "123abc123abc123abc123abc123",
            "created_at": "2017-07-06T21:30:39.838Z",
            "critical": False,
            "server_platform": "Windows",
            "server_hostname": "WIN-72N3D1BVKHM",
            "server_group_name": "foobar",
            "server_ip_address": "12.34.56.789",
            "server_reported_fqdn": "windows_fqdn",
            "server_label": "windows_label",
            "server_primary_ip_address": "12.34.56.789",
            "ec2_instance_id": "i-1234567890",
            "ec2_account_id": "1234567890",
            "policy_name": "policy name",
            "rule_name": "An account failed to logon (4625)",
            "original_log_entry": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4625</EventID></System></Event>",
            "additional_details": True,
            "server_display_name": "windows displayname"
        }

        return stub

    def linux_lids_stub(self):
        stub = {
            "id": "123456789012345678901234567890",
            "type": "lids_rule_failed",
            "name": "Log-based intrusion detection rule matched",
            "message": "linux lids rule failed message",
            "server_id": "123456789012345678901234567890",
            "created_at": "2017-07-06T21:49:35.842Z",
            "critical": True,
            "server_platform": "Linux",
            "server_hostname": "ip-123-456-789",
            "server_group_name": "Ubuntu",
            "server_ip_address": "12.34.56.789",
            "server_reported_fqdn": "server fqdn",
            "server_label": "ubuntu label",
            "server_primary_ip_address": "12.34.56.789",
            "ec2_instance_id": "i-1234567890",
            "ec2_account_id": "1234567890",
            "policy_name": "policy name",
            "rule_name": "Potential account brute-force attempt",
            "original_log_entry": "log entry",
            "additional_details": True,
            "server_display_name": "ip-123-456-789"
        }
        return stub

    def non_server_event_stub(self):
        stub = {
            "id": "123456789012345678901234567890",
            "type": "halo_login_success",
            "name": "Halo login success",
            "message": "Halo user login msg",
            "server_id": None,
            "created_at": "2017-07-07",
            "critical": True,
            "actor_username": "test user",
            "actor_ip_address": "12.34.56.789",
            "actor_country": "USA",
            "server_display_name": None
        }
        return stub

    def test_good_parse_server_label(self):
        ehelper = self.create_ehelper_object()
        event = { 'server_label': '776183744304_i-0b8c898d867d239a6' }
        actual = ehelper.parse_server_label(event)
        expected = {
            'ec2_account_id': '776183744304',
            'ec2_instance_id': 'i-0b8c898d867d239a6'
        }
        assert expected == actual

    def test_bad_parse_server_label(self):
        ehelper = self.create_ehelper_object()
        event = { 'server_label': 'foobar' }
        actual = ehelper.parse_server_label(event)
        assert None == actual

    def test_event_id_with_windows_channel(self):
        ehelper = self.create_ehelper_object()
        event = self.windows_lids_stub()
        actual = ehelper.build_event_id(event)
        assert '4625' == actual


    def test_event_id_with_non_custom_event(self):
        ehelper = self.create_ehelper_object()
        event = self.non_server_event_stub()
        actual = ehelper.build_event_id(event)
        assert 413 == actual

    def test_if_lids_event_is_lids(self):
        ehelper = self.create_ehelper_object()
        event = self.windows_lids_stub()
        actual = ehelper.is_lids(event)
        assert actual

    def test_if_non_lids_event_is_lids(self):
        ehelper = self.create_ehelper_object()
        event = self.non_server_event_stub()
        actual = ehelper.is_lids(event)
        assert not actual

    def test_is_using_windows_lids_mapping(self):
        ehelper = self.create_ehelper_object()
        event = self.windows_lids_stub()
        actual = ehelper.select_custom_mapping(event)
        assert 'SubjectUserName' in actual

    def test_is_using_linux_lids_mapping(self):
        ehelper = self.create_ehelper_object()
        event = self.linux_lids_stub()
        actual = ehelper.select_custom_mapping(event)
        assert 'SubjectUserName' not in actual
