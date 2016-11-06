#!/usr/bin/env ruby

# Example:
# ./gen_checks_from_xml.rb -i assets/U_Microsoft_IE11_V1R10_Manual-xccdf.xml -d ./controls
require 'nokogiri'
require 'optparse'


# Most of these checks look like this:
# The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page Turn on certificate address mismatch warning must be Enabled. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings Criteria: If the value "WarnOnBadCertRecving" is REG_DWORD = 1, this is not a finding.'

def inspec_check(text:, parse_reg:true, id:nil)
  if text.match(/Procedure: /) then
    begin
      hivepath = text.match /Procedure: Use the Windows Registry Editor to navigate to the following keys?: (H[A-Z]{3})\\([\S ]+)\s+Criteria/ || "nil"
      hive = hivepath.captures[0]
      key  = hivepath.captures[1]

      # Criteria: If the value "WarnOnBadCertRecving" is REG_DWORD = 1
      criteria = text.match /Criteria: If the value .*"([0-9A-z\.\(\)]+)" is ([A-Z_]+) ?= ?([\S+]+)/ || "nil"
      name = criteria.captures[0]
      registry_value_type = criteria.captures[1]
      value = criteria.captures[2].chomp(',')

      return <<-REGISTRY_DOC

      describe registry_key({
        hive: '#{hive}',
        key:  '#{key.strip.chomp('.')}',
      }) do
        its('#{name}') { should eq #{value} }
      end
      REGISTRY_DOC
    rescue NoMethodError
      p "=============\n"
      p text, id.value
      p "=============\n"
      return <<-ERROR_DOC
    describe file('') do
      it "is a pending example as input could not be parsed"
    end
      ERROR_DOC
    end
  else
    return <<-CHECKDOC
    describe file('') do
      it "is a pending example"
    end
    CHECKDOC
  end

end

# Gather inputs from CLI for input and destination files
OptionParser.new do |o|
  o.on('-i FILENAME') { |i| $input = i }
  o.on('-d FILENAME') { |d| $dest = d }
  o.on('-r') { |r| $registry = true }
  o.on('-h') { puts o; exit }
  o.parse!
end

# Set input to a parsable attribute
doc = File.open($input) { |f| Nokogiri::XML(f) }

# Get date from XML
dates = doc.css('//status')
date = dates[0]['date']

# Get description from XML
stigdesc = doc.css('//description')[0]

# Get all groups from XML
groups = doc.css('//Group')

# Parse groups
xml  = Nokogiri::XML(groups.to_s)

# Parse and write each field to a file.
groups.each do |group|
  xml_doc  = Nokogiri::XML(group)
  xml  = Nokogiri::XML(group.to_s)
  id = xml.css('@id')[0]
  title1 = xml.css('title').first
  title2 = xml.css('title').last
  sevprep = xml.css('Rule')
  impact = sevprep[0]['severity']
  case impact
  when 'low'
    sev = '0.1'
  when 'medium'
    sev = '0.5'
  when 'high'
    sev = '1.0'
  else
    puts 'There was an issue getting the severity'
  end
  ctrldesc = xml.css('description')[1]
  cd = Nokogiri::XML(ctrldesc)
  cdesc = cd.css('VulnDiscussion')
  checkident = xml.css('check')
  checkid = checkident[0]['system']
  fixident = xml.css('fixtext')
  fixid = fixident[0]['fixref']
  vers = xml.css('version')
  ruleid = sevprep[0]['id']
  checktxt = xml.css('check-content')
  output = <<-HEREDOC
# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: #{date}
# description: #{stigdesc.text.gsub("\n", " ")}
# impacts
title '#{id} - #{title2.text}'
control '#{id}' do
  impact #{sev}
  title '#{title2.text}'
  desc '#{cdesc.text.gsub("\n", " ").gsub("'", "")}'
  tag 'stig', '#{id}'
  tag severity: '#{impact}'
  tag checkid: '#{checkid}'
  tag fixid: '#{fixid}'
  tag version: '#{vers.text}'
  tag ruleid: '#{ruleid}'
  tag fixtext: '#{fixident.text.gsub("'", "")}'
  tag checktext: '#{checktxt.text.gsub("'", "")}'

# START_DESCRIBE #{id}
  #{inspec_check(text: checktxt.text, id: id)}
# STOP_DESCRIBE #{id}

end

  HEREDOC
  File.write("#{$dest}/#{id}.rb", output)
end
