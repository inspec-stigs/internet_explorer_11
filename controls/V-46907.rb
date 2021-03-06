# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-09-16
# description: The Microsoft Internet Explorer 11 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil
# impacts
title 'V-46907 - .NET Framework-reliant components not signed with Authenticode must be disallowed to run (Internet zone).'
control 'V-46907' do
  impact 0.5
  title '.NET Framework-reliant components not signed with Authenticode must be disallowed to run (Internet zone).'
  desc 'Unsigned components are more likely to contain malicious code and it is more difficult to determine the author of the application - therefore they should be avoided if possible. This policy setting allows you to manage whether .NET Framework components that are not signed with Authenticode can be executed from Internet Explorer. These components include managed controls referenced from an object tag and managed executables referenced from a link. If you enable this policy setting, Internet Explorer will execute unsigned managed components. If you select "Prompt" in the drop-down box, Internet Explorer will prompt the user to determine whether to execute unsigned managed components. If you disable this policy setting, Internet Explorer will not execute unsigned managed components. If you do not configure this policy setting, Internet Explorer will not execute unsigned managed components.'
  tag 'stig', 'V-46907'
  tag severity: 'medium'
  tag checkid: 'C-49957r2_chk'
  tag fixid: 'F-50643r1_fix'
  tag version: 'DTBI920-IE11'
  tag ruleid: 'SV-59773r1_rule'
  tag fixtext: 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone Run .NET Framework-reliant components not signed with Authenticode to Enabled, and select Disable from the drop-down box.   '
  tag checktext: 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone Run .NET Framework-reliant components not signed with Authenticode must be Enabled, and Disable selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "2004" is REG_DWORD = 3, this is not a finding.'

# START_DESCRIBE V-46907
  
      describe registry_key({
        hive: 'HKLM',
        key:  'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3',
      }) do
        its('2004') { should eq 3 }
      end

# STOP_DESCRIBE V-46907

end

