module Rex
module Parser

class NessusXMLStreamParser

	attr_accessor :callback

	def initialize(callback = nil)
		reset_state
		self.callback = callback if callback
	end

	def reset_state
		@state = :generic_state
		@host = { "status" => nil, "endpoints" => [], "names" => [], "vulns" => {} }
		@vuln = { "refs" => [] }
	end

	def tag_start(name, attributes)
		case name
		when "node"
			@host["hardware-address"] = attributes["hardware-address"]
			@host["addr"] = attributes["address"]
			@host["status"] = attributes["status"]
		when "os"
			# Take only the highest certainty
			if not @host["os_certainty"] or (@host["os_certainty"].to_f < attributes["certainty"].to_f)
				@host["os_vendor"]    = attributes["vendor"]
				@host["os_family"]    = attributes["family"]
				@host["os_product"]   = attributes["product"]
				@host["arch"]         = attributes["arch"]
				@host["os_certainty"] = attributes["certainty"]
			end
		when "name"
			#@host["names"].push attributes["name"]
			@state = :in_name
		when "endpoint"
			# This is a port in NeXpose parlance
			@host["endpoints"].push(attributes)
		when "service"
			@state = :in_service
			# Store any service info with the associated port.  There shouldn't
			# be any collisions on attribute names here, so just merge them.
			@host["endpoints"].last.merge!(attributes)
		when "fingerprint"
			if @state == :in_service
				@host["endpoints"].last.merge!(attributes)
			end
		when "test"
			if attributes["status"] == "vulnerable-exploited" or attributes["status"] == "vulnerable-version"
				@host["vulns"][attributes["id"]] = attributes.dup
			end
		when "vulnerability"
			@vuln.merge! attributes
		when "reference"
			@state = :in_reference
			@vuln["refs"].push attributes
		end
	end

	def text(str)
		case @state
		when :in_name
			@host["names"].push str
		when :in_reference
			@vuln["refs"].last["value"] = str
		end
	end

	def tag_end(name)
		case name
		when "node"
			callback.call(:host, @host) if callback
			reset_state
		when "vulnerability"
			callback.call(:vuln, @vuln) if callback
			reset_state
		when "service","reference"
			@state = :generic_state
		end
	end

	# We don't need these methods, but they're necessary to keep REXML happy
	def xmldecl(version, encoding, standalone); end
	def cdata; end
	def comment(str); end
	def instruction(name, instruction); end
	def attlist; end
end
end
end

__END__



