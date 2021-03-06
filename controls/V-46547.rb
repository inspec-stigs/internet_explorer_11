# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-09-16
# description: The Microsoft Internet Explorer 11 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil
# impacts
title 'V-46547 - Dragging of content from different domains across windows must be disallowed (Restricted Sites zone).'
control 'V-46547' do
  impact 0.5
  title 'Dragging of content from different domains across windows must be disallowed (Restricted Sites zone).'
  desc 'This policy setting allows you to set options for dragging content from one domain to a different domain when the source and destination are in different windows. If you enable this policy setting, users can drag content from one domain to a different domain when the source and destination are in different windows. Users cannot change this setting. If you enable this policy setting, users cannot drag content from one domain to a different domain when both the source and destination are in different windows. Users cannot change this setting. If you do not configure this policy setting, users cannot drag content from one domain to a different domain when the source and destination are in different windows. Users can change this setting in the Internet Options dialog box.'
  tag 'stig', 'V-46547'
  tag severity: 'medium'
  tag checkid: 'C-49719r2_chk'
  tag fixid: 'F-50323r1_fix'
  tag version: 'DTBI1005-IE11'
  tag ruleid: 'SV-59411r1_rule'
  tag fixtext: 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Restricted Sites Zone Enable dragging of content from different domains across windows to Enabled, and select Disabled from the drop-down box.   '
  tag checktext: 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Restricted Sites Zone Enable dragging of content from different domains across windows must be Enabled, and Disabled selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "2709" is REG_DWORD = 3, this is not a finding.'

# START_DESCRIBE V-46547
  
      describe registry_key({
        hive: 'HKLM',
        key:  'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4',
      }) do
        its('2709') { should eq 3 }
      end

# STOP_DESCRIBE V-46547

end

