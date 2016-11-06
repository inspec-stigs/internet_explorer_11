# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-09-16
# description: The Microsoft Internet Explorer 11 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil
# impacts
title 'V-46473 - Turn off Encryption Support must be enabled.'
control 'V-46473' do
  impact 0.5
  title 'Turn off Encryption Support must be enabled.'
  desc 'This parameter ensures only DoD-approved ciphers and algorithms are enabled for use by the web browser by allowing you to turn on/off support for TLS and SSL. TLS is a protocol for protecting communications between the browser and the target server. When the browser attempts to set up a protected communication with the target server, the browser and server negotiate which protocol and version to use. The browser and server attempt to match each others list of supported protocols and versions and pick the most preferred match..'
  tag 'stig', 'V-46473'
  tag severity: 'medium'
  tag checkid: 'C-49683r15_chk'
  tag fixid: 'F-50263r14_fix'
  tag version: 'DTBI014-IE11'
  tag ruleid: 'SV-59337r5_rule'
  tag fixtext: 'Open Internet Explorer. From the menu bar, select "Tools". From the "Tools" drop-down menu, select "Internet Options". From the "Internet Options" window, select the "Advanced" tab, from the "Advanced" tab window scroll down to the "Security" category. Place a checkmark in "Use TLS 1.0", "Use TLS 1.1", and "Use TLS 1.2" check boxes.

Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Advanced Page >> "Turn off Encryption Support" to "Enabled", and select "Use TLS 1.0", "Use TLS 1.1", and "Use TLS 1.2" from the drop-down box.

Set the registry value for HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings?\SecureProtocols must to "2688". '
  tag checktext: 'Open Internet Explorer. From the menu bar, select "Tools". From the "Tools" drop-down menu, select "Internet Options". From the "Internet Options" window, select the "Advanced" tab, from the "Advanced" tab window scroll down to the "Security" category. Verify a checkmark is placed in "Use TLS 1.0", "Use TLS 1.1", and "Use TLS 1.2" check boxes. If there is not a check mark in "Use TLS 1.0", "Use TLS 1.1", or "Use TLS 1.2" check boxes, this is a finding.

The policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Advanced Page >> "Turn off Encryption Support" must be "Enabled" and ensure the options selected are "Use TLS 1.0", "Use TLS 1.1", and "Use TLS 1.2" from the drop-down box.

The registry value for HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings?\SecureProtocols must be "2688".  If the "SecureProtocols" DWORD value is not "2688", this is a finding.'

# START_DESCRIBE V-46473
      describe file('') do
      it "is a pending example"
    end

# STOP_DESCRIBE V-46473

end

