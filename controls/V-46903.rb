# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-09-16
# description: The Microsoft Internet Explorer 11 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil
# impacts
title 'V-46903 - Status bar updates via script must be disallowed (Internet zone).'
control 'V-46903' do
  impact 0.5
  title 'Status bar updates via script must be disallowed (Internet zone).'
  desc 'This policy setting allows you to manage whether script is allowed to update the status bar within the zone. A script running in the zone could cause false information to be displayed on the status bar, which could confuse the user and cause them to perform an undesirable action. If you enable this policy setting, script is allowed to update the status bar. If you disable this policy setting, script is not allowed to update the status bar. If you do not configure this policy setting, status bar updates via scripts will be disabled.'
  tag 'stig', 'V-46903'
  tag severity: 'medium'
  tag checkid: 'C-49955r2_chk'
  tag fixid: 'F-50637r1_fix'
  tag version: 'DTBI910-IE11'
  tag ruleid: 'SV-59769r1_rule'
  tag fixtext: 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone Allow updates to status bar via script to Enabled, and select Disable from the drop-down box.   '
  tag checktext: 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone Allow updates to status bar via script must be Enabled, and Disable selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "2103" is REG_DWORD = 3, this is not a finding.'

# START_DESCRIBE V-46903
  
      describe registry_key({
        hive: 'HKLM',
        key:  'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3',
      }) do
        its("2103") { should eq 3 }
      end

# STOP_DESCRIBE V-46903

end

