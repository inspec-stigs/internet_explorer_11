# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-09-16
# description: The Microsoft Internet Explorer 11 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil
# impacts
title 'V-46673 - MIME sniffing must be disallowed (Internet zone).'
control 'V-46673' do
  impact 0.5
  title 'MIME sniffing must be disallowed (Internet zone).'
  desc 'This policy setting allows you to manage MIME sniffing for file promotion from one type to another based on a MIME sniff. A MIME sniff is the recognition by Internet Explorer of the file type based on a bit signature. If you enable this policy setting, the MIME Sniffing Safety Feature will not apply in this zone. The security zone will run without the added layer of security provided by this feature. If you disable this policy setting, the actions that may be harmful cannot run; this Internet Explorer security feature will be turned on in this zone, as dictated by the feature control setting for the process. If you do not configure this policy setting, the MIME Sniffing Safety Feature will not apply in this zone.'
  tag 'stig', 'V-46673'
  tag severity: 'medium'
  tag checkid: 'C-49827r2_chk'
  tag fixid: 'F-50439r1_fix'
  tag version: 'DTBI465-IE11'
  tag ruleid: 'SV-59537r1_rule'
  tag fixtext: 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> Enable MIME Sniffing to Enabled, and select Disable from the drop-down box.  '
  tag checktext: 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> Enable MIME Sniffing must be Enabled, and Disable selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "2100" is REG_DWORD = 3, this is not a finding.'

# START_DESCRIBE V-46673
  
      describe registry_key({
        hive: 'HKLM',
        key:  'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3',
      }) do
        its('2100') { should eq 3 }
      end

# STOP_DESCRIBE V-46673

end

