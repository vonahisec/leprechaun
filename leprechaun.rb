#!/usr/bin/env ruby
#
# This tool was intended to be used during post-exploitation.
# Essentially, once you have elevated privileges, you can run a recursive netstat
# using tools such as winexe, smbexec, psexec, whatever., and parse it here.
#
# See the GitHub or blog page for more information.
#
# Author; Alton Johnson (@altonjx)
# Company: Vonahi Security (@vonahi_security)
# Created: 05/22/2019
# Version: 1.0
#

['securerandom','terminal-table','getopt/std'].each(&method(:require))

def help
	puts "\n " + "-" * 61
	puts " \e[1;34mLeprechaun v1.0 - Alton Johnson (@altonjx)\e[0;00m"
	puts " " + "-" * 61
	puts "\n  Usage: #{$0} -f /path/to/netstat_results.txt -p <port>"
	puts "\n  -f\tFile containing the output of netstat results."
	puts "  -p\tPort you're interested in. E.g., 80. Specify \"all\" to see all traffic or \"common\" for common ports."
	puts "\n  Example: #{$0} -f netstat_output.txt -p 80"
	puts "  Example: #{$0} -f netstat_output.txt -p all"
	puts "  Example: #{$0} -f netstat_output.txt -p common"
	puts "\n"
	exit
end

class Leprechaun
	def initialize(netstat_results, port)
		@servers = {}
		@clients = {}
		@dport_mappings = []
		@sport_mappings = []

		@data = File.open(netstat_results).read.split("\n")
		@port = port

		@digraph = "digraph {\n"
		@digraph += "\toverlap = false;\n\n"
		@digraph_headers = "\t# Servers and clients are defined here.\n"
		@digraph_data = "\t# Connections are defined here.\n"
	end

	def parse_data
		@data.each do |line|
			routes = line.scan(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:\d+\b/)
			next unless !routes.empty?
			sip = routes[0].split(":")[0] # source IP address
			sport = routes[0].split(":")[1] # source port
			dip = routes[1].split(":")[0] # destination IP address
			dport = routes[1].split(":")[1] # destination port

			next if dip == "0.0.0.0"

			if line.include? "TCP"
				protocol = "tcp"
			else
				protocol = "udp"
			end

			if dport != @port and @port != "all" and @port != "common"
				next
			end

			dip.gsub! "10.", "192."
			sip.gsub! "10.", "192."
			dip.gsub! "126", "12"
			sip.gsub! "126", "12"

			well_known = [17,21,22,23,25,53,69,80,81,86,110,123,135,139,143,161,389,443,445,587,636,1311,1433,1434,1720,2301,2381,3306,3389,4443,47001,5060,5061,5432,5500,5900,5901,5985,5986,7080,8080,8081,8082,8089,8000,8180,8443]

			if @port == "common"
				next unless well_known.include? dport.to_i
			end

			if @servers[dip].nil?  # avoid adding duplicates
				server_hex = SecureRandom.hex(2) # reference this in the dot digraph
				@servers[dip] = {:hex => "", :ports => {}, :client_count => 0}
				@servers[dip][:hex] = "s#{server_hex}"
				@digraph_headers += "\t#{@servers[dip][:hex]} [label = < <b>#{dip}</b> >, fillcolor=firebrick3, fontcolor=white, style=filled, shape=egg];\n"
			end
			if @servers[dip][:ports]["#{dport}/#{protocol}"].nil?
				@servers[dip][:ports]["#{dport}/#{protocol}"] = {:clients => [], :client_count => 0}
			end

			unless @servers[dip][:ports]["#{dport}/#{protocol}"][:clients].include? sip
				@servers[dip][:ports]["#{dport}/#{protocol}"][:clients] << sip # add source IP
				@servers[dip][:ports]["#{dport}/#{protocol}"][:client_count] += 1
				@servers[dip][:client_count] += 1
			end

			if @clients[sip].nil? # avoid adding duplicates
				client_hex = SecureRandom.hex(2)
				@clients[sip] = "c#{client_hex}"
				@digraph_headers += "\t#{@clients[sip]} [label = \"#{sip}\", fillcolor=chartreuse, style=filled];\n"
			end

			if @dport_mappings.include? [dip, "#{dport}/#{protocol}"]
				unless @sport_mappings.include? [sip, "#{dport}/#{protocol}"]
					@digraph_data += "\t\"#{@clients[sip]}\" -> \"#{dport}/#{protocol}\";\n"
					@sport_mappings << [sip, "#{dport}/#{protocol}"]
				end
			else
				@dport_mappings << [dip, "#{dport}/#{protocol}"]
				@sport_mappings << [sip, "#{dport}/#{protocol}"]
				@digraph_data += "\t\"#{@clients[sip]}\" -> \"#{dport}/#{protocol}\" -> #{@servers[dip][:hex]};\n"
			end
		end

		@digraph += "#{@digraph_headers}\n #{@digraph_data}"
		@digraph += "}"
	end

	def print_table
		# Most connected clients.
		headers = ['Server','Number of connected clients','Highest traffic destination port']
		data = [] # server IP address, connected clients, connected ports
		@servers.each do |ip, server_values|
			connected_clients = server_values[:client_count]
			ports = [] # port, # of connected clients
			server_values[:ports].each do |port, port_values|
				ports << [port, port_values[:client_count]]
			end
			ports.sort {|a,b| a[1] <=> b[1]}
			data << [ip, connected_clients, ports[0]]
		end
		data = data.sort {|a,b| a[1] <=> b[1]}.reverse

		table = Terminal::Table.new do |t|
			t.add_row headers
			t.add_separator
			data.each do |line|
				t.add_row [line[0], line[1], "#{line[2][0]} (#{line[2][1]} connections)"]
			end
		end

		puts table
	end

	def write_to_file
		File.open("data.dot", "w") {|f| f.write(@digraph)}
		`sfdp -Tpng data.dot -o data.png -Grankdir=LR`
	end
end

if $0 == __FILE__
	if ARGV.length == 0
		help
	end

	opt = Getopt::Std.getopts("f:p:")
	fail "Please specify a netstat output file (-f) as well as a port (-p)." unless opt['f'] and opt['p']

	lep = Leprechaun.new(opt['f'], opt['p'])
	lep.parse_data
	lep.write_to_file
	lep.print_table
end