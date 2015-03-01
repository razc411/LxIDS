#CONFIGURATION###############################
$log = "secure"     #log to watch for events
$rcfg = "rules.cfg" #rules config file location
#DO NOT EDIT BELOW, MAIN CODE BODY###########

require 'rb-inotify'
require 'date'
#####GLOBAL INSTANCES##################################################################
$rules = Array.new					# => Holds the IDS rules
$users = Array.new 					# => Holds the user attempt list
$ip_parse = /\d+\.\d+\.\d+\.\d+/	# => Used to parse for user IP addresses
# Function: intialize(ip)
	# => ip 	: the ip address of this specific user
	# Author: 	Ramzi Chennafi
	# Date: 	Febuary 28 2015
	# Returns: Nothing
	# Description
	# Constructor for user. Creates the attempt array and sets user IP.
def get_time
	hours = DateTime.now.strftime("%H")
	minutes = DateTime.now.strftime("%M")
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
	attr_reader :ip :attempts :last_attempt
	# Function: intialize(ip)
	# => ip 	: the ip address of this specific user
	# Author: 	Ramzi Chennafi
	# Date: 	Febuary 28 2015
	# Returns: Nothing
	# Description
	# Constructor for user. Creates the attempt array and sets user IP.
	def intialize(ip)
		@ip = ip
		@attempts = Array.new
		@last_attempt = Array.new
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
		@last_attempt[service][time] = get_time
		@last_attempt[service][date] = DateTime.now.strftime("%Y%m%d")
	end
	# Function: intialize(ip)
	# => ip 	: the ip address of this specific user
	# Author: 	Ramzi Chennafi
	# Date: 	Febuary 28 2015
	# Returns: Nothing
	# Description
	# Constructor for user. Creates the attempt array and sets user IP.
	def check_time(attempt_time, service)
		if get_time - last_attempt[service][time] >= attempt_time && last_attempt[service][date] == DateTime.now.strftime("%Y%m%d")
			return true
		else
			return false
		end
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
	attr_reader :service :event :response :attempt_time :attempts :time_ban :unban_response
	# Function: intialize(ip)
	# => ip 	: the ip address of this specific user
	# Author: 	Ramzi Chennafi
	# Date: 	Febuary 28 2015
	# Returns: Nothing
	# Description
	# Constructor for user. Creates the attempt array and sets user IP.
	def intialize(rule)
		vars = rule.split(":")
		@service 		= vars[0]
		@event 			= vars[1]
		@response 		= vars[2]
		@attempt_time   = vars[3]
		@attempts 		= vars[4]
		@time_ban 		= vars[5]
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
		puts service + " will ban after " + attempts " attempts at :" + event + ", for " + timeBan + " minutes."
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
	def intialize()
		File.open($rcfg, "r") do |aFile|
			aFile.each_line("\n") do |line|
				if line.start_with?("#")
					next
				else
					temp = Rule.new(line)
					rules.push(temp)
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
			if line.includes?(rule.service) and line.includes?(rule.event)
				create_new = 0
				$users.each do |user|
					if user.ip == line[$ip_parse] && !user.attempts[rule.service]
						user.add_service_attempt(rule.service)
						puts "Failed attempt #" + user.attempts[rule.service] + " on " + rule.service + " by " + user.ip
					
					elsif user.ip == line[$ip_parse] && user.attempts[rule.service] + 1 == rule.attempts && user.check_time(rule.attempt_time, rule.service)
						system(rule.response.sub!('%IP%', user.ip))
						puts "Added ban for " + user.ip + "on service " + rule.service
						user.attempts[rule.service] = 0
						
						if(rule.time_ban > 0)
							system(rule.unban_response.sub!('%IP%', user.ip))
						end

					elsif user.ip == line[$ip_parse] && user.attempts[rule.service] += 1 < rule.attempts && user.check_time(rule.attempt_time, rule.service)
						puts "Failed attempt #" + user.attempts[rule.service] + " on " + rule.service + " by " + user.ip
					end

					if (create_new += 1) == users.length
						temp = User.new(line[$ip_parse])
						$users.push(temp)
						temp.add_service_attempt(rule.service)
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
				self.call_rule(line)
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
rule_manager.setup_iptables
   
queue = INotify::Notifier.new  
queue.watch($log, :modify) do
	rule_manager.check_rules # => sets this function as the callback when the log is modified
end
queue.run                      





