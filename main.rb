#CONFIGURATION###############################
$log = "secure"     #log to watch for events
$rcfg = "rules.cfg" #rules config file location
#DO NOT EDIT BELOW, MAIN CODE BODY###########

require 'rb-inotify'
require 'date'
#####GLOBAL INSTANCES##################################################################
$rules = Array.new					# => Holds the IDS rules
$users = Hash.new 					# => Holds the user attempt list
$ip_parse = /\d+\.\d+\.\d+\.\d+/	# => Used to parse for user IP addresses
# Function: intialize(ip)
	# => ip 	: the ip address of this specific user
	# Author: 	Ramzi Chennafi
	# Date: 	Febuary 28 2015
	# Returns: Nothing
	# Description
	# Constructor for user. Creates the attempt array and sets user IP.
def get_time
	hours = DateTime.now.strftime("%H").to_i
	minutes = DateTime.now.strftime("%M").to_i
	return (hours * 60) + minutes
end
#####END GLOBAL INSTANCES###############################################################
########################################################################################
# Class User
# Author:   	Ramzi Chennafi
# Date: 		Febuary 28 2015
# Functions: 
# => intialize(ip)
# => add_service_attempt(service)
# 
# Description
# User class defines a single user. Holds the failed attempts made on specific services.
########################################################################################
class User
	attr_accessor :ip, :attempts, :last_attempt
	# Function: intialize(ip)
	# => ip 	: the ip address of this specific user
	# Author: 	Ramzi Chennafi
	# Date: 	Febuary 28 2015
	# Returns: Nothing
	# Description
	# Constructor for user. Creates the attempt array and sets user IP.
	def initialize(ip)
		@ip = ip
		@attempts = Hash.new
		@last_attempt = Hash.new(Hash.new)
	end
	# Function: intialize(ip)
	# => ip 	: the ip address of this specific user
	# Author: 	Ramzi Chennafi
	# Date: 	Febuary 28 2015
	# Returns: Nothing
	# Description
	# Constructor for user. Creates the attempt array and sets user IP.
	def add_service_attempt(service)
		@attempts[service] = 1
		@last_attempt[service]["time"] = get_time
		@last_attempt[service]["date"] = DateTime.now.strftime("%Y%m%d")
	end
	# Function: intialize(ip)
	# => ip 	: the ip address of this specific user
	# Author: 	Ramzi Chennafi
	# Date: 	Febuary 28 2015
	# Returns: Nothing
	# Description
	# Constructor for user. Creates the attempt array and sets user IP.
	def check_time(attempt_time, service) #############FIX THIS IN ACTUAL TESTING#####################
		#if ((get_time.to_i - last_attempt[service]['time'].to_i) <= attempt_time) && last_attempt[service]['date'] == DateTime.now.strftime("%Y%m%d")
		#	return true
		#else
		#	return false
			return true
	end
end
########################################################################################
# Class Rule
# Author:   	Ramzi Chennafi
# Date: 		Febuary 28 2015
# Functions: 
# => intialize(ip)
# => add_service_attempt(service)
# 
# Description
# User class defines a single user. Holds the failed attempts made on specific services.
########################################################################################
class Rule
	attr_accessor :service, :event, :response, :attempt_time, :attempts, :time_ban, :unban_response
	# Function: intialize(ip)
	# => ip 	: the ip address of this specific user
	# Author: 	Ramzi Chennafi
	# Date: 	Febuary 28 2015
	# Returns: Nothing
	# Description
	# Constructor for user. Creates the attempt array and sets user IP.
	def initialize(rule)
		vars = rule.split(":")
		@service 		= vars[0]
		@event 			= vars[1]
		@response 		= vars[2]
		@attempts 		= vars[3].to_i
		@attempt_time	= vars[4].to_i
		@time_ban 		= vars[5].to_i
		@unban_response = vars[6]
	end
	# Function: intialize(ip)
	# => ip 	: the ip address of this specific user
	# Author: 	Ramzi Chennafi
	# Date: 	Febuary 28 2015
	# Returns: Nothing
	# Description
	# Constructor for user. Creates the attempt array and sets user IP.
	def print_rule()
		puts service + " will ban after " + attempts.to_s + " attempts at event: " + event + ", for " + time_ban.to_s + " minutes."
	end
end
########################################################################################
# Class Manager
# Author:   	Ramzi Chennafi
# Date: 		Febuary 28 2015
# Functions: 
# => intialize(ip)
# => add_service_attempt(service)
# 
# Description
# User class defines a single user. Holds the failed attempts made on specific services.
########################################################################################
class Manager
	# Function: intialize(ip)
	# => ip 	: the ip address of this specific user
	# Author: 	Ramzi Chennafi
	# Date: 	Febuary 28 2015
	# Returns: Nothing
	# Description
	# Constructor for user. Creates the attempt array and sets user IP.
	def initialize()
		setup_iptables
		File.open($rcfg, "r") do |aFile|
			aFile.each_line("\n") do |line|
				if line.start_with?("#")
					next
				else
					temp = Rule.new(line)
					$rules.push(temp)
					temp.print_rule
				end
			end
		end
	end
	# Function: intialize(ip)
	# => ip 	: the ip address of this specific user
	# Author: 	Ramzi Chennafi
	# Date: 	Febuary 28 2015
	# Returns: Nothing
	# Description
	# Constructor for user. Creates the attempt array and sets user IP.
	def setup_iptables()
		system("sudo iptables -X lxIDS")
		system("sudo iptables -D INPUT -j lxIDS")
		system("sudo iptables -D OUTPUT -j lxIDS")
		system("sudo iptables -N lxIDS")
		system("sudo iptables -A INPUT -j lxIDS")
		system("sudo iptables -A OUTPUT -j lxIDS")
	end
	# Function: intialize(ip)
	# => ip 	: the ip address of this specific user
	# Author: 	Ramzi Chennafi
	# Returns: Nothing
	# Date: 	Febuary 28 2015
	# Description
	# Constructor for user. Creates the attempt array and sets user IP.
	def call_rule(line)
		$rules.each do |rule|
			if line.include?("#{rule.service}") && line.include?("#{rule.event}")
				ip_addr = line[$ip_parse]
				if !$users.has_key?(ip_addr)
					$users[ip_addr] = User.new(ip_addr)
					$users[ip_addr].add_service_attempt(rule.service)
				else
					if $users[ip_addr].attempts[rule.service] == 0
						$users[ip_addr].add_service_attempt(rule.service)
						puts "Failed attempt #" + $users[ip_addr].attempts[rule.service].to_s + " on " + rule.service + " by " + ip_addr
					
					elsif (($users[ip_addr].attempts[rule.service] + 1) == rule.attempts) && $users[ip_addr].check_time(rule.attempt_time, rule.service)
						system("#{rule.response}".sub!('%IP%', ip_addr))
						puts "Added ban for " + ip_addr + " on service " + rule.service
						$users[ip_addr].attempts[rule.service] = 0
						
						if(rule.time_ban > 0)
							system('(crontab -l ; echo "0 4 * * * ' + "#{rule.unban_response}".sub!('%IP%', ip_addr) + ')| crontab -')
						end

					elsif (($users[ip_addr].attempts[rule.service] + 1) < rule.attempts) && $users[ip_addr].check_time(rule.attempt_time, rule.service)
						puts "Failed attempt #" + $users[ip_addr].attempts[rule.service].to_s + " on " + rule.service + " by " + ip_addr
						$users[ip_addr].attempts[rule.service] += 1
					
					end
				end
			end
		end
	end
	# Function: intialize(ip)
	# => ip 	: the ip address of this specific user
	# Author: 	Ramzi Chennafi
	# Date: 	Febuary 28 2015
	# Returns: Nothing
	# Description
	# Constructor for user. Creates the attempt array and sets user IP.
	def check_rules
		File.open($log, "r") do |aFile|
			aFile.each_line("\n") do |line|
				call_rule(line)
			end
		end
	end
end

#####################################################################################
###Central Body of the Program#######################################################
#####################################################################################
## Description
## Sets up the log notifier and intiates the rule listing. The log notifier
## will be activated whenever a change in the log file is detected. Once the notifier
## is set, the program will continue to run until shut down.
#####################################################################################

puts "Welcome to the lxIDS"
puts "Intializing rules..."

rule_manager = Manager.new
   
queue = INotify::Notifier.new  
queue.watch($log, :modify) do
	rule_manager.check_rules # => sets this function as the callback when the log is modified
end
queue.run                      





