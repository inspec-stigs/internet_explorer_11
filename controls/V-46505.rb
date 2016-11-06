# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-09-16
# description: The Microsoft Internet Explorer 11 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil
# impacts
title 'V-46505 - Font downloads must be disallowed (Internet zone).'
control 'V-46505' do
  impact 0.5
  title 'Font downloads must be disallowed (Internet zone).'
  desc 'Downloads of fonts can sometimes contain malicious code. It is possible that a font could include malformed data that would cause Internet Explorer to crash when it attempts to load and render the font. This policy setting allows you to manage whether pages of the zone may download HTML fonts. If you enable this policy setting, HTML fonts can be downloaded automatically. If you enable this policy setting and "Prompt" is selected in the drop-down box, users are queried whether to allow HTML fonts to download. If you disable this policy setting, HTML fonts are prevented from downloading.'
  tag 'stig', 'V-46505'
  tag severity: 'medium'
  tag checkid: 'C-49695r2_chk'
  tag fixid: 'F-50295r1_fix'
  tag version: 'DTBI030-IE11'
  tag ruleid: 'SV-59369r1_rule'
  tag fixtext: 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> Allow font downloads to Enabled, and select Disable from the drop-down box. '
  tag checktext: 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> Allow font downloads must be Enabled, and Disable selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "1604" is REG_DWORD = 3, this is not a finding.'

# START_DESCRIBE V-46505
  
      describe registry_key({
        hive: 'HKLM',
        key:  'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3',
      }) do
        its("1604") { should eq 3 }
      end

# STOP_DESCRIBE V-46505

end

