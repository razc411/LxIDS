$log = Array.new
#CONFIGURATION###############################
$log.push("/var/log/auth.log")     #log to watch for events
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
	attr_accessor :ip, :attempts, :last_attempt, :status, :last_banned, :time_to_unban
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
		@status = "VALID"
		@last_banned = 0
		@time_to_unban = 0
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
		`sudo iptables -X lxIDS 2> /dev/null`
		`sudo iptables -D INPUT -j lxIDS 2> /dev/null`
		`sudo iptables -D OUTPUT -j lxIDS 2> /dev/null`
		`sudo iptables -N lxIDS`
		`sudo iptables -A INPUT -j lxIDS`
		`sudo iptables -A OUTPUT -j lxIDS`
	end
	# Function: intialize(ip)
	# => ip 	: the ip address of this specific user
	# Author: 	Ramzi Chennafi
	# Returns: Nothing
	# Date: 	Febuary 28 2015
	# Description
	# Constructor for user. Creates the attempt array and sets user IP.
	def add_new_user(ip, rule)
		$users[ip] = User.new(ip)
		$users[ip].add_service_attempt(rule.service)
		puts "Failed attempt #" + $users[ip].attempts[rule.service].to_s + " on " + rule.service + " by " + ip
	end
	# Function: intialize(ip)
	# => ip 	: the ip address of this specific user
	# Author: 	Ramzi Chennafi
	# Returns: Nothing
	# Date: 	Febuary 28 2015
	# Description
	# Constructor for user. Creates the attempt array and sets user IP.
	def ban_user(ip, rule)
		system("#{rule.response}".sub!('%IP%', ip))
		puts "Added ban for " + ip + " on service " + rule.service
		$users[ip].attempts[rule.service] = 0
		$users[ip].status = "BANNED"
		$users[ip].last_banned = get_time
		$users[ip].time_to_unban = get_time + rule.time_ban

		if(rule.time_ban > 0)
			minutes = $users[ip].time_to_unban % 60
			hours = $users[ip].time_to_unban / 60
			ub_response = "#{rule.unban_response}".sub!('%IP%', ip)
			`(crontab -l ; echo "#{minutes} #{hours} * * * #{ub_response}")| crontab -`
		end
	end
	# Function: intialize(ip)
	# => ip 	: the ip address of this specific user
	# Author: 	Ramzi Chennafi
	# Returns: Nothing
	# Date: 	Febuary 28 2015
	# Description
	# Constructor for user. Creates the attempt array and sets user IP.
	def is_user_banned(ip, rule)
		if $users[ip].status == "BANNED" && get_time >= $users[ip].time_to_unban
			$users[ip].time_to_unban = 0
			$users[ip].last_banned = 0
			$users[ip].status = "VALID"
			return false
		elsif $users[ip].status == "VALID"
			return false
		end 

		return true
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
				
				if $users.has_key?(ip_addr) 
					if is_user_banned(ip_addr, rule)
						next
					end
				end

				if !$users.has_key?(ip_addr)
					add_new_user(ip_addr, rule)
				else
					case $users[ip_addr].attempts[rule.service]
						when 0
							$users[ip_addr].add_service_attempt(rule.service)
							puts "Failed attempt #" + $users[ip_addr].attempts[rule.service].to_s + " on " + rule.service + " by " + ip_addr
						
						when (rule.attempts - 1)
							if $users[ip_addr].check_time(rule.attempt_time, rule.service)
								ban_user(ip_addr, rule)
							end

						when 1..(rule.attempts - 2)
							if $users[ip_addr].check_time(rule.attempt_time, rule.service)
								$users[ip_addr].attempts[rule.service] += 1
								puts "Failed attempt #" + $users[ip_addr].attempts[rule.service].to_s + " on " + rule.service + " by " + ip_addr
							end
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
	def check_rules(aFile)
		aFile.each_line("\n") do |line|
			call_rule(line)
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

queue = Array.new
$log.each do |logfile|
	File.open(logfile) do |aFile|
		aFile.seek(0, IO::SEEK_END)
		temp = INotify::Notifier.new  
		queue.push(temp)  
		temp.watch(logfile, :modify) do
			rule_manager.check_rules(aFile) # => sets this function as the callback when the log is modified
		end
		temp.run
	end
end
               