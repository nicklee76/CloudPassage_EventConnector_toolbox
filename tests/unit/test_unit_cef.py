import cloudpassage
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../', 'lib'))
from cef import Cef


class TestUnitCef:
    def create_cef_object(self):
        cef = Cef({'cefsyslog': None})
        return cef

    def event_stub(self):
        stub = [
            {
                "id": "e750d982688411e6b7b32f750f990d28",
                "type": "fim_target_integrity_changed",
                "name": "File Integrity change detected",
                "message": "A change was detected in file integrity target" \
                           "/opt/cloudpassage/*/* on Linux server" \
                           "Jlee-Chef-Node1 (54.183.177.195) (source: Scan)",
                "server_id": "5b1d73b63e3711e68ead7f4b70b6c2b8",
                "created_at": "2016-08-22T16:24:30.726Z",
                "critical": True,
                "server_platform": "Linux",
                "server_hostname": "ip-10-2-20-76",
                "server_group_name": "old_smoke",
                "server_ip_address": "54.183.177.195",
                "server_reported_fqdn": "localhost",
                "server_label": "Jlee-Chef-Node1",
                "server_primary_ip_address": "10.2.20.76",
                "scan_id": "e730037e688411e6b7b32f750f990d28",
                "finding_id": "e748d9c6688411e6b7b32f750f990d28",
                "policy_name": "FIM halo"
            }
        ]
        return stub

    def linux_lids_event_stub(self):
        stub = [
            {
                "id": "123456789012345678901234567890",
                "type": "lids_rule_failed",
                "name": "Log-based intrusion detection rule matched",
                "message": "Log-based intrusion detection rule Software was installed matched on Linux server 1234567890 (12.34.56.789, 1234567890). (source: Test - Policy - 123456789)",
                "server_id": "abc123abc123abc123abc123",
                "created_at": "2017-06-30T00:00:00.018Z",
                "critical": False,
                "server_platform": "Linux",
                "server_hostname": "Test-1234567890",
                "server_group_name": "test group",
                "server_ip_address": "12.34.56.789",
                "server_reported_fqdn": "ip-123-45-6-78.us-west-2.compute.internal",
                "server_label": "1234567890_i-abc123abc123",
                "server_primary_ip_address": "123.45.6.78",
                "ec2_instance_id": "i-1234567890abc",
                "ec2_account_id": "0987654321",
                "policy_name": "Test - Policy - 1234567890",
                "rule_name": "Software was installed",
                "original_log_entry": "2017-06-29 23:58:05 status installed test"
            }
        ]
        return stub

    def windows_lids_event_stub(self):
        stub = [
            {
                "id": "123456789012345678901234567890",
                "type": "lids_rule_failed",
                "name": "Log-based intrusion detection rule matched",
                "message": "Log-based intrusion detection rule PowerShell Event ID 123 matched on Windows server IP-123456789 (12.345.67.890). (source: Test - Windows Policy)",
                "server_id": "abc123abc123abc123abc123",
                "created_at": "2017-06-30T00:00:00.190Z",
                "critical": False,
                "server_platform": "Windows",
                "server_hostname": "IP-123456789",
                "server_group_name": "Microsoft Windows Server 2012 R2 Standard",
                "server_ip_address": "12.345.67.890",
                "server_reported_fqdn": "ip-123456789",
                "server_label": None,
                "server_primary_ip_address": "12.3.45.67",
                "policy_name": "Intel - Windows Policy",
                "rule_name": "PowerShell Event ID 123",
                "original_log_entry": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='PowerShell'/><EventID Qualifiers='0'>123</EventID><Level>4</Level><Task>4</Task><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2017-06-29T23:55:01.000000000Z'/><EventRecordID>156130</EventRecordID><Channel>Windows PowerShell</Channel><Computer>ip-123456789</Computer><Security/></System><EventData><Data>Available</Data><Data>None</Data><Data>\tNewEngineState=Available\r\n\tPreviousEngineState=None\r\n\r\n\tSequenceNumber=12\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion=4.0\r\n\tHostId=12345678-1234-5678-9123-1234567890\r\n\tHostApplication=powershell.exe -ExecutionPolicy Bypass C:\\Windows\\System32\\GroupPolicy\\Machine\\Scripts\\Shutdown\\test.ps1 -operation test -cfgfile c:\\test\\test.test\r\n\tEngineVersion=1.0\r\n\tRunspaceId=123456789012345678901234567890\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine=</Data></EventData></Event>"
            }
        ]
        return stub

    def test_cef_constants(self):
        cef = self.create_cef_object()
        cef_constants = cef.cef_constants(self.event_stub()[0])
        expected = "CEF:0|CloudPassage|CPHalo|1.0|" \
                   "130|File Integrity change detected|9|"
        assert expected == cef_constants

    def test_cef_outliers(self):
        cef = self.create_cef_object()
        mapping = {}
        cef.build_cef_outliers(mapping, self.event_stub()[0])
        assert {"deviceDirection": 0} == mapping

    def test_build_cef_mapping(self):
        cef = self.create_cef_object()
        cef_mapping = cef.build_cef_mapping(self.event_stub()[0])
        expected = {
            'rt': 'Aug 22 2016 16:24:30 UTC',
            'dst': '54.183.177.195',
            'cs1Label': 'extras',
            'msg': "A change was detected in file integrity target" \
                   "/opt/cloudpassage/*/* on Linux server" \
                   "Jlee-Chef-Node1 (54.183.177.195) (source: Scan)",
            'deviceDirection': 0,
            'cs1': {
                'policy_name': 'FIM halo',
                'server_id': '5b1d73b63e3711e68ead7f4b70b6c2b8',
                'finding_id': 'e748d9c6688411e6b7b32f750f990d28',
                'name': 'File Integrity change detected',
                'scan_id': 'e730037e688411e6b7b32f750f990d28',
                'server_reported_fqdn': 'localhost',
                'server_group_name': 'old_smoke',
                'server_label': 'Jlee-Chef-Node1',
                'critical': True,
                'server_primary_ip_address': '10.2.20.76',
                'server_platform': 'Linux',
                'type': 'fim_target_integrity_changed',
                'id': 'e750d982688411e6b7b32f750f990d28'
            },
            'dhost': 'ip-10-2-20-76'
        }
        assert expected == cef_mapping

    def test_format_cef(self):
        cef = self.create_cef_object()
        cef_format = cef.format_cef(self.event_stub())[0]
        expected = "CEF:0|CloudPassage|CPHalo|1.0|130|"\
                   "File Integrity change detected|9|"\
                   "rt=Aug 22 2016 16:24:30 UTC "\
                   "dst=54.183.177.195 "\
                   "cs1Label=extras "\
                   "msg=A change was detected in file integrity target"\
                   "/opt/cloudpassage/*/* on Linux serverJlee-Chef-Node1 "\
                   "(54.183.177.195) (source: Scan) "\
                   "deviceDirection=0 "\
                   "cs1={'policy_name': "\
                   "'FIM halo', "\
                   "'server_id': '5b1d73b63e3711e68ead7f4b70b6c2b8', "\
                   "'finding_id': 'e748d9c6688411e6b7b32f750f990d28', "\
                   "'name': 'File Integrity change detected', "\
                   "'scan_id': 'e730037e688411e6b7b32f750f990d28', "\
                   "'server_reported_fqdn': 'localhost', "\
                   "'server_group_name': 'old_smoke', "\
                   "'server_label': 'Jlee-Chef-Node1', "\
                   "'critical': True, "\
                   "'server_primary_ip_address': '10.2.20.76', "\
                   "'server_platform': 'Linux', "\
                   "'type': 'fim_target_integrity_changed', "\
                   "'id': 'e750d982688411e6b7b32f750f990d28'} "\
                   "dhost=ip-10-2-20-76 "
        assert expected == cef_format

    def test_format_linux_lids(self):
        cef = self.create_cef_object()
        lids_format = cef.format_cef(self.linux_lids_event_stub())[0]
        expected = "CEF:0|CloudPassage|CPHalo|1.0|831|"\
                   "Log-based intrusion detection rule matched|3|"\
                   "rt=2017-06-30T00:00:00.018Z "\
                   "src=12.34.56.789 "\
                   "flexString2=2017-06-29 23:58:05 "\
                   "status installed test "\
                   "shost=Test-1234567890 "\
                   "sourceTranslatedAddress=123.45.6.78 "\
                   "outcome=lids_rule_failed "\
                   "deviceExternalId=abc123abc123abc123abc123 "\
                   "msg=Log-based intrusion detection rule Software was installed "\
                   "matched on Linux server 1234567890 (12.34.56.789, 1234567890). "\
                   "(source: Test - Policy - 123456789) "\
                   "reason=Log-based intrusion detection rule matched "\
                   "sourceDnsDomain=ip-123-45-6-78.us-west-2.compute.internal "\
                   "cs5=Software was installed "\
                   "cs4=Test - Policy - 1234567890 "\
                   "eventId=123456789012345678901234567890 "\
                   "cs1=Linux "\
                   "cs3=1234567890_i-abc123abc123 "\
                   "cs2=test group "

        assert expected == lids_format

    def test_format_windows_lids(self):
        cef = self.create_cef_object()
        lids_format = cef.format_cef(self.windows_lids_event_stub())[0]
        expected = "CEF:0|CloudPassage|CPHalo|1.0|831|"\
                   "Log-based intrusion detection rule matched|3|"\
                   "eventId=123 "\
                   "rt={'SystemTime': '2017-06-29T23:55:01.000000000Z'} "\
                   "flexString1=ip-123456789 "\
                   "cat=Windows PowerShell "
        assert expected == lids_format
