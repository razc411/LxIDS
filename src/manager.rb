########################################################################################
# Class Manager
# Author 	: Ramzi Chennafi
# Date		: Febuary 28 2015
# Functions: 
# => void intialize(ip)
# => void add_service_attempt(service)
# => void setup_iptables()
# => void add_new_user(ip, rule)
# => void ban_user(ip, rule)
# => boolean is_user_banned(ip, rule)
# => void call_rule(line)
# => void check_rules(aFile)
# 
# Description
# Responsible for the managing of the IPS. Watches both the rules and users and responds
# to events. Includes setting of default IPTABLES arguments
########################################################################################
class Manager
	@@rules = Array.new					# => Holds the IDS @@rules
	@@users = Hash.new 					# => Holds the user attempt list
	# Function 	: intialize()
	# Author	: Ramzi Chennafi
	# Date		: Febuary 28 2015
	# Returns	: Nothing
	#
	# Description
	# Constructor for the Manager. Sets up the iptables entries and
	# opens the config file to grab the rules.
	def initialize()
		setup_iptables
		File.open($rcfg, "r") do |aFile|
			aFile.each_line("\n") do |line|
				if line.start_with?("#")
					next
				else
					temp = Rule.new(line)
					@@rules.push(temp)
					temp.print_rule
				end
			end
		end
	end
	# Function 	: setup_iptables()
	# Author	: Ramzi Chennafi
	# Date		: Febuary 28 2015
	# Returns	: Nothing
	#
	# Description
	# Sets up the LxIDS iptables entries.
	def setup_iptables()
		`sudo iptables -X lxIDS 2> /dev/null`
		`sudo iptables -D INPUT -j lxIDS 2> /dev/null`
		`sudo iptables -D OUTPUT -j lxIDS 2> /dev/null`
		`sudo iptables -N lxIDS`
		`sudo iptables -A INPUT -j lxIDS`
	end
	# Function 	: add_new_user(ip, rule)
	# => ip 	: the ip address of the user to add
	# => rule 	: the rule to add the user an infraction on
	# Author	: Ramzi Chennafi
	# Date		: Febuary 28 2015
	# Returns	: Nothing
	#
	# Description
	# Adds a new user to the users hash. Sets the attempt made which caused this user to be added.
	def add_new_user(ip, rule)
		@@users[ip] = User.new(ip)
		@@users[ip].add_service_attempt(rule.service)
	end
	# Function 	: ban_user(ip, rule)
	# => ip 	: the ip address of this specific user
	# => rule 	: rule to check for banning 
	# Author	: Ramzi Chennafi
	# Date		: Febuary 28 2015
	# Returns	: Nothing
	#
	# Description
	# Bans a user for a specified infraction, will establish a cronjob for ban removal
	# if the rule response is a timeban.
	def ban_user(ip, rule)
		system("#{rule.response}".sub!('%IP%', ip))
		@@users[ip].attempts[rule.service] 		= 0
		@@users[ip].status 				= "BANNED"
		@@users[ip].last_banned 			= User.get_time
		@@users[ip].time_to_unban 			= User.get_time + rule.time_ban
		
		if(rule.time_ban > 0)
			unban_thread = Thread.new{unban_user(rule, ip)}
			puts "Added ban for " + ip + " on service " + rule.service + " for " + rule.time_ban.to_s + " minutes."
		else
			puts "Added infinite ban for " + ip + " on service " + rule.service + "."
		end 
	end
	# Function 	: unban_user(ip, rule)
	# => ip 	: the ip address of this specific user
	# => rule 	: rule to check for banning 
	# Author	: Ramzi Chennafi
	# Date		: Febuary 28 2015
	# Returns	: Nothing
	#
	# Description
	# Bans a user for a specified infraction, will establish a cronjob for ban removal
	# if the rule response is a timeban.
	def unban_user(rule, ip)
		sleep(rule.time_ban * 60)
		user.time_to_unban 	= 0
		user.last_banned 	= 0
		user.status 		= "VALID"
		ub_response = "#{rule.unban_response}".sub!('%IP%', ip)
		`#{ub_response}`
	end
	# Function 	: call_rule(line)
	# => line 	: line from the log file to process
	# Author	: Ramzi Chennafi
	# Date		: Febuary 28 2015
	# Returns	: Nothing
	#
	# Description
	# Calls each rule on the specified log line.
	def call_rule(line)
		@@rules.each do |rule|
			if line.include?("#{rule.service}") && line.include?("#{rule.event}")
				ip_addr = line[/\d+\.\d+\.\d+\.\d+/]

				if !@@users.has_key?(ip_addr)
					add_new_user(ip_addr, rule)

				elsif @@users[ip].status == "VALID"
					
					case @@users[ip_addr].attempts[rule.service]
						when nil
							@@users[ip_addr].add_service_attempt(rule.service)
						
						when (rule.attempts - 1)
							if @@users[ip_addr].check_time(rule.attempt_time, rule.service)
								ban_user(ip_addr, rule)
							end

						when 1..(rule.attempts - 2)
							if @@users[ip_addr].check_time(rule.attempt_time, rule.service)
								@@users[ip_addr].attempts[rule.service] += 1
								@@users[ip_addr].print_attempt(rule.service)
							end
					end
				end 
			end
		end
	end
	# Function 	: check_rules(aFile)
	# => aFile	: the log file to check rules against
	# Author 	: Ramzi Chennafi
	# Date 		: Febuary 28 2015
	# Returns 	: Nothing
	#
	# Description
	# Checks the rules against a specified log file.
	def check_rules(aFile)
		aFile.each_line("\n") do |line|
			call_rule(line)
		end
	end
end
