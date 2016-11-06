# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-09-16
# description: The Microsoft Internet Explorer 11 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil
# impacts
title 'V-46585 - Font downloads must be disallowed (Restricted Sites zone).'
control 'V-46585' do
  impact 0.5
  title 'Font downloads must be disallowed (Restricted Sites zone).'
  desc 'It is possible that a font could include malformed data that would cause Internet Explorer to crash when it attempts to load and render the font. Downloads of fonts can sometimes contain malicious code. Files should not be downloaded from restricted sites. This policy setting allows you to manage whether pages of the zone may download HTML fonts.'
  tag 'stig', 'V-46585'
  tag severity: 'medium'
  tag checkid: 'C-49751r2_chk'
  tag fixid: 'F-50355r1_fix'
  tag version: 'DTBI120-IE11'
  tag ruleid: 'SV-59449r1_rule'
  tag fixtext: 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> Allow font downloads to Enabled, and select Disable from the drop-down box.   '
  tag checktext: 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> Allow font downloads must be Enabled, and Disable selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1604" is REG_DWORD = 3, this is not a finding.'

# START_DESCRIBE V-46585
  
      describe registry_key({
        hive: 'HKLM',
        key:  'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4',
      }) do
        its('1604') { should eq 3 }
      end

# STOP_DESCRIBE V-46585

end

