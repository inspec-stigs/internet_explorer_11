# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-09-16
# description: The Microsoft Internet Explorer 11 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil
# impacts
title 'V-46613 - Participation in the Customer Experience Improvement Program must be disallowed.'
control 'V-46613' do
  impact 0.5
  title 'Participation in the Customer Experience Improvement Program must be disallowed.'
  desc 'This setting controls whether users can participate in the Microsoft Customer Experience Improvement Program to help improve Microsoft applications. When users choose to participate in the Customer Experience Improvement Program (CEIP), applications automatically send information to Microsoft about how the applications are used. This information is combined with other CEIP data to help Microsoft solve problems and to improve the products and features customers use most often. This feature does not collect users names, addresses, or any other identifying information except the IP address that is used to send the data. By default, users have the opportunity to opt into participation in the CEIP the first time they run an application. If an organization has policies that govern the use of external resources such as the CEIP, allowing users to opt in to the program might cause them to violate these policies.'
  tag 'stig', 'V-46613'
  tag severity: 'medium'
  tag checkid: 'C-49779r2_chk'
  tag fixid: 'F-50383r1_fix'
  tag version: 'DTBI315-IE11'
  tag ruleid: 'SV-59477r1_rule'
  tag fixtext: 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Prevent participation in the Customer Experience Improvement Program to Enabled.   '
  tag checktext: 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Prevent participation in the Customer Experience Improvement Program must be Enabled. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\SQM Criteria: If the value "DisableCustomerImprovementProgram" is REG_DWORD = 0, this is not a finding.'

# START_DESCRIBE V-46613
  
      describe registry_key({
        hive: 'HKLM',
        key:  'Software\Policies\Microsoft\Internet Explorer\SQM',
      }) do
        its('DisableCustomerImprovementProgram') { should eq 0 }
      end

# STOP_DESCRIBE V-46613

end

