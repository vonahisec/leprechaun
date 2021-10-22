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
# Created: Octgober 22, 2021
# Version: 1.1
#

begin
  ['securerandom', 'terminal-table', 'getopt/std', 'ipaddr'].each(&method(:require))
rescue StandardError
  puts ' [*] Looks like a few gems are missing. Installing the gems.'
  `gem install getopt terminal-table ipaddr`
  puts ' [*] Finished. Please re-run this script.'
end
def help
  puts "\n " + '-' * 61
  puts " \e[1;34mLeprechaun v1.1 - Alton Johnson (@altonjx)\e[0;00m"
  puts ' ' + '-' * 61
  puts "\n  Usage: #{$0} -f /path/to/netstat_results.txt -p <port>"
  puts "\n  -f\tFile containing the output of netstat results."
  puts "  -p\tPort you're interested in. e.g., 80. Specify \"all\", \"common\", or separate ports with commas"
  puts "  -t\tThe type of destination IP addresses you want to see connections to (e.g. external/internal/all)."
  puts "\n  Example: #{$0} -f netstat_output.txt -p 80"
  puts "  Example: #{$0} -f netstat_output.txt -p all"
  puts "  Example: #{$0} -f netstat_output.txt -p common"
  puts "  Example: #{$0} -f netstat_output.txt -p 80,443 -t external"
  puts "\n"
  exit
end
PRIVATE_IPS = [
  IPAddr.new('10.0.0.0/8'),
  IPAddr.new('172.16.0.0/12'),
  IPAddr.new('192.168.0.0/16')
].freeze
class Leprechaun
  def initialize(netstat_results, ports, ip_type)
    @servers = {}
    @clients = {}
    @dest_port_mappings = []
    @source_port_mappings = []
    @ip_type = ip_type
    @data = File.open(netstat_results).read.split("\n")
    @ports = if ports.include? ','
               ports.split(',')
             else
               ports
             end
    @digraph = "digraph {\n"
    @digraph += "\toverlap = false;\n\n"
    @digraph_headers = "\t# Servers and clients are defined here.\n"
    @digraph_data = "\t# Connections are defined here.\n"
  end

  def private_ip?(ip_address)
    ip_address = IPAddr.new(ip_address) if ip_address.is_a?(String)
    PRIVATE_IPS.any? { |private_ip| private_ip.include?(ip_address) }
  end

  def parse_data
    @data.each do |line|
      routes = line.scan(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:\d+\b/)
      next if routes.empty? || routes.nil?

      begin
        source_ip = routes[0].split(':')[0] # source IP address
        source_port = routes[0].split(':')[1] # source port
        dest_ip = routes[1].split(':')[0] # destination IP address
        dest_port = routes[1].split(':')[1] # destination port
      rescue StandardError
        next
      end
      next if dest_ip == '0.0.0.0'
      next unless line.include? 'ESTABLISHED'

      # Skip depending on type of traffic the user wants.
      if @ip_type == 'internal'
        next unless private_ip? dest_ip
      elsif @ip_type == 'external'
        next if private_ip? dest_ip
      end
      protocol = (line.downcase.include?('tcp') ? 'tcp' : 'udp')
      well_known = [17, 21, 22, 23, 25, 53, 69, 80, 81, 86, 110, 123, 135, 139, 143, 161, 389, 443, 445, 587, 636, 1311, 1433, 1434, 1720, 2301,
                    2381, 3306, 3389, 4443, 47_001, 5060, 5061, 5432, 5500, 5900, 5901, 5985, 5986, 7080, 8080, 8081, 8082, 8089, 8000, 8180, 8443]
      next if @ports.include?('common') && !(well_known.include? dest_port.to_i)
      next if !@ports.include?('all') && !@ports.include?('common') && !(@ports.include? dest_port)

      if @servers[dest_ip].nil? # avoid adding duplicate connections
        server_hex = SecureRandom.hex(2)
        @servers[dest_ip] = { hex: '', ports: {}, client_count: 0 }
        @servers[dest_ip][:hex] = "s#{server_hex}"
        @digraph_headers += "\t#{@servers[dest_ip][:hex]} [label = < <b>#{dest_ip}</b> >, fillcolor=gold3, fontcolor=white, style=filled, shape=egg];\n"
      end
      if @servers[dest_ip][:ports]["#{dest_port}/#{protocol}"].nil?
        port_hex = SecureRandom.hex(2)
        @servers[dest_ip][:ports]["#{dest_port}/#{protocol}"] = { clients: [], client_count: 0, hex: "p#{port_hex}" }
        @digraph_headers += "\tp#{port_hex} [label = \"#{dest_port}/#{protocol}\"];\n"
      end
      unless @servers[dest_ip][:ports]["#{dest_port}/#{protocol}"][:clients].include? source_ip
        @servers[dest_ip][:ports]["#{dest_port}/#{protocol}"][:clients] << source_ip # add source IP
        @servers[dest_ip][:ports]["#{dest_port}/#{protocol}"][:client_count] += 1
        @servers[dest_ip][:client_count] += 1
      end
      if @clients[source_ip].nil? # avoid adding duplicate connections
        client_hex = SecureRandom.hex(2)
        @clients[source_ip] = "c#{client_hex}"
        @digraph_headers += "\t#{@clients[source_ip]} [label = \"#{source_ip}\", fillcolor=green3, style=filled];\n"
      end
      if @dest_port_mappings.include? [dest_ip, "#{dest_port}/#{protocol}"]
        unless @source_port_mappings.include? [source_ip, "#{dest_port}/#{protocol}"]
          @digraph_data += "\t#{@clients[source_ip]} -> \"#{@servers[dest_ip][:ports]["#{dest_port}/#{protocol}"][:hex]}\";\n"
          @source_port_mappings << [source_ip, "#{dest_port}/#{protocol}"]
        end
      else
        @dest_port_mappings << [dest_ip, "#{dest_port}/#{protocol}"]
        @source_port_mappings << [source_ip, "#{dest_port}/#{protocol}"]
        @digraph_data += "\t#{@clients[source_ip]} -> \"#{@servers[dest_ip][:ports]["#{dest_port}/#{protocol}"][:hex]}\" -> #{@servers[dest_ip][:hex]};\n"
      end
    end
    @digraph += "#{@digraph_headers}\n #{@digraph_data}"
    @digraph += '}'
  end

  def print_table
    # Most connected clients.
    headers = ['Server', 'Number of connected clients', 'Highest traffic destination port']
    data = [] # server IP address, connected clients, connected ports
    @servers.each do |ip, server_values|
      connected_clients = server_values[:client_count]
      ports = [] # port, # of connected clients
      server_values[:ports].each do |port, port_values|
        ports << [port, port_values[:client_count]]
      end
      ports.sort { |a, b| a[1] <=> b[1] }
      data << [ip, connected_clients, ports[0]]
    end
    data = data.sort { |a, b| a[1] <=> b[1] }.reverse
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
    File.open('data.dot', 'w') { |f| f.write(@digraph) }
    tmp_file = SecureRandom.hex(6)
    `sfdp -Tpng data.dot -o leprechaun_#{tmp_file}.png -Grankdir=LR; rm data.dot`
    puts "\n [*] Completed! Graph output file located at: ./leprechaun_#{tmp_file}.png\n\n"
  end
end
if $0 == __FILE__
  help if ARGV.length == 0
  opt = Getopt::Std.getopts('f:p:t:')
  raise 'Please specify a netstat output file (-f) as well as a port (-p).' unless opt['f'] && opt['p']

  opt['t'] = 'all' if opt['t'].nil?

  # Check if file exists first.
  raise 'The file provided with -f does not exist. Please select a valid file.' unless File.exist? opt['f']

  lep = Leprechaun.new(opt['f'], opt['p'], opt['t'])
  lep.parse_data
  lep.write_to_file
  lep.print_table
end
