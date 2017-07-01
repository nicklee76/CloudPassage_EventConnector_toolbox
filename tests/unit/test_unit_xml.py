import cloudpassage
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../', 'lib'))
from xml_controller import Xml


class TestUnitXml:
    def create_xml_object(self):
        xml = Xml()
        return xml

    def windows_xml_stub(self):
        raw_xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='PowerShell'/><EventID Qualifiers='0'>123</EventID><Level>4</Level><Task>4</Task><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2017-06-29T23:55:01.000000000Z'/><EventRecordID>156130</EventRecordID><Channel>Windows PowerShell</Channel><Computer>ip-123456789</Computer><Security/></System><EventData><Data>Available</Data><Data>None</Data><Data>\tNewEngineState=Available\r\n\tPreviousEngineState=None\r\n\r\n\tSequenceNumber=12\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion=4.0\r\n\tHostId=12345678-1234-5678-9123-1234567890\r\n\tHostApplication=powershell.exe -ExecutionPolicy Bypass C:\\Windows\\System32\\GroupPolicy\\Machine\\Scripts\\Shutdown\\test.ps1 -operation test -cfgfile c:\\test\\test.test\r\n\tEngineVersion=1.0\r\n\tRunspaceId=123456789012345678901234567890\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine=</Data></EventData></Event>"
        return raw_xml

    def test_windows_xml_to_hash(self):
        xml = self.create_xml_object()
        format = xml.to_hash(self.windows_xml_stub())
        expected = {
            'EventID': '123',
            'Task': '4',
            'TimeCreated': {'SystemTime': '2017-06-29T23:55:01.000000000Z'},
            'Level': '4',
            'System': {},
            'Computer': 'ip-123456789',
            'EventRecordID': '156130',
            'Provider': {'Name': 'PowerShell'},
            'Keywords': '0x80000000000000',
            'EventData': {},
            'Security': {},
            'Data': '\tNewEngineState=Available\n\tPreviousEngineState=None\n\n\tSequenceNumber=12\n\n\tHostName=ConsoleHost\n\tHostVersion=4.0\n\tHostId=12345678-1234-5678-9123-1234567890\n\tHostApplication=powershell.exe -ExecutionPolicy Bypass C:\\Windows\\System32\\GroupPolicy\\Machine\\Scripts\\Shutdown\\test.ps1 -operation test -cfgfile c:\\test\\test.test\n\tEngineVersion=1.0\n\tRunspaceId=123456789012345678901234567890\n\tPipelineId=\n\tCommandName=\n\tCommandType=\n\tScriptName=\n\tCommandPath=\n\tCommandLine=', 'Event': {}, 'Channel': 'Windows PowerShell'
        }
        assert expected == format