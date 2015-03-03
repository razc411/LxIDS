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
		`sudo iptables -A OUTPUT -j lxIDS`
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
		puts "Failed attempt #" + @@users[ip].attempts[rule.service].to_s + " on " + rule.service + " by " + ip
		@@users[ip].set_time_attempt(rule.service)
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
		puts "Added ban for " + ip + " on service " + rule.service
		@@users[ip].attempts[rule.service] 	= 0
		@@users[ip].status 					= "BANNED"
		@@users[ip].last_banned 			= User.get_time
		@@users[ip].time_to_unban 			= User.get_time + rule.time_ban

		if(rule.time_ban > 0)
			minutes 	= @@users[ip].time_to_unban % 60
			hours 		= @@users[ip].time_to_unban / 60
			ub_response = "#{rule.unban_response}".sub!('%IP%', ip)
			`(crontab -l ; echo "#{minutes} #{hours} * * * #{ub_response}")| crontab -`
		end
	end
	# Function 	: is_user_banned(ip, rule)
	# => ip 	: the ip address of the user to check
	# => rule 	: the rule to check for a ban entry
	# Author	: Ramzi Chennafi
	# Date		: Febuary 28 2015
	# Returns	: Boolean, Returns false if not banned, true if.
	#
	# Description
	# Checks if the specified user is banned.
	def is_user_banned(ip, rule)
		if @@users[ip].status == "BANNED" && User.get_time >= @@users[ip].time_to_unban
			@@users[ip].time_to_unban 	= 0
			@@users[ip].last_banned 	= 0
			@@users[ip].status 			= "VALID"
			return false
		elsif @@users[ip].status == "VALID"
			return false
		end 

		return true
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

				elsif !is_user_banned(ip_addr, rule)
					
					case @@users[ip_addr].attempts[rule.service]
						when 0
							@@users[ip_addr].add_service_attempt(rule.service)
							@@users[ip_addr].print_attempt(service)
						
						when (rule.attempts - 1)
							if @@users[ip_addr].check_time(rule.attempt_time, rule.service)
								ban_user(ip_addr, rule)
							end

						when 1..(rule.attempts - 2)
							if @@users[ip_addr].check_time(rule.attempt_time, rule.service)
								@@users[ip_addr].attempts[rule.service] += 1
								@@users[ip_addr].print_attempt(service)
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
