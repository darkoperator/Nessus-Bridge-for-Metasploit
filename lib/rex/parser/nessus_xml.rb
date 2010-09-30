require 'rexml/document'

module Rex
module Parser


class NessusXMLStreamParser

	attr_accessor :on_found_host

	def initialize(&block)
		reset_state
		on_found_host = block if block
	end

	def reset_state
		@host = {
				'hname'             => nil,
				'addr'              => nil,
				'mac'               => nil,
				'os'                => nil,
				'ports'             => [ 'port' => {    'port'              	=> nil,
									'svc_name'              => nil,
									'proto'              	=> nil,
									'severity'              => nil,
									'nasl'              	=> nil,
									'description'           => nil,
									'cve'                   => [],
									'bid'                   => [],
									'xref'                  => []
								}
							]
		}
		@state = :generic_state
	end

	def tag_start(name, attributes)
		case name
		when "tag"
			if attributes['name'] == "mac-address"
				@state = :is_mac
			end
			if attributes['name'] == "host-fqdn"
				@state = :is_fqdn
			end
			if attributes['name'] == "ip-addr"
				@state = :is_ip
			end
			if attributes['name'] == "operating-system"
				@state = :is_os
			end
		when "ReportHost"
			@host['hname'] = attributes['name']
			puts(@host['hname'])
		#when "HostProperties"
			
		when "ReportItem"
			@x = Hash.new
			@x['nasl'] = attributes['pluginID']
			@x['port'] = attributes['port']
			@x['proto'] = attributes['protocol']
			@x['svc_name'] = attributes['svc_name']
			@x['severity'] = attributes['severity']
			
		when "description"
			@state = :is_desc
			#description = elements['plugin_output']
		when "cve"
			@state = :is_cve
			#cve = item.elements['cve']
		when "bid"
			@state = :is_bid
			#bid = item.elements['bid']
		when "xref"
			@state = :is_xref
			#xref = item.elements['xref']
		when "solution"
			@state = :is_solution
		end
	end
	
	def text(str)
		case @state
		when :is_fqdn
			@host['hname'] = str
		when :is_ip
			@host['addr'] = str
		when :is_os
			@host['os'] = str
		when :is_mac
			@host['mac'] = str
		when :is_desc
			@x['description'] = str
		when :is_cve
			@x['cve'] = str
		when :is_bid
			@x['bid'] = str
		when :is_xref
			@x['xref'] = str
		end
	end

	def tag_end(name)
		case name
		when "ReportHost"
			on_found_host.call(@host) if on_found_host
			reset_state
		when "ReportItem"
			@host['ports'].push @x
		end
		@state = :generic_state
	end

	# We don't need these methods, but they're necessary to keep REXML happy
	#
	def xmldecl(version, encoding, standalone); end
	def cdata; end
	def comment(str); end
	def instruction(name, instruction); end
	def attlist; end
end

end
end

#begin
#				addr = host.elements["HostProperties/tag[@name='host-ip']"].text
#			rescue
#				addr = host.attribute("name").value
#			end
#
#			next unless ipv4_validator(addr) # Catches SCAN-ERROR, among others.
#			if bl.include? addr
#				next
#			else
#				yield(:address,addr) if block
#			end
#
#			os = host.elements["HostProperties/tag[@name='operating-system']"]
#			if os
#				report_note(
#					:workspace => wspace,
#					:host => addr,
#					:type => 'host.os.nessus_fingerprint',
#					:data => {
#						:os => os.text.to_s.strip
#					}
#				)
#			end
#
#			hname = host.elements["HostProperties/tag[@name='host-fqdn']"]
#			if hname
#				report_host(
#					:workspace => wspace,
#					:host => addr,
#					:name => hname.text.to_s.strip
#				)
#			end
#
#			mac = host.elements["HostProperties/tag[@name='mac-address']"]
#			if mac
#				report_host(
#					:workspace => wspace,
#					:host => addr,
#					:mac  => mac.text.to_s.strip.upcase
#				)
#			end
#
#			host.elements.each('ReportItem') do |item|
#				nasl = item.attribute('pluginID').value
#				port = item.attribute('port').value
#				proto = item.attribute('protocol').value
#				name = item.attribute('svc_name').value
#				severity = item.attribute('severity').value
#				description = item.elements['plugin_output']
#				cve = item.elements['cve']
#				bid = item.elements['bid']
#				xref = item.elements['xref']
#
#				handle_nessus_v2(wspace, addr, port, proto, name, nasl, severity, description, cve, bid, xref)
#
#			end

