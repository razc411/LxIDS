#CONFIGURATION###############################
$log = "secure"     #log to watch for events
$rcfg = "rules.cfg" #rules config file location
#DO NOT EDIT BELOW, MAIN CODE BODY###########
require 'rb-inotify'

$rules = Array.new
$users = Array.new
$ip_parse = "/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/"

class User
	
	def intialize(ip)
		@ip = ip
		@attempts = 0
	end

end

class Rule
	
	attr_writer : service, event, response, attempts, time_ban, unban_response
	
	def intialize(rule)
		vars = rule.split(":")
		@service 		= vars[0]
		@event 			= vars[1]
		@response 		= vars[2]
		@attempts 		= vars[3]
		@time_ban 		= vars[4]
		@unban_response = vars[5]
	end

	def print_rule()
		puts service + " " + event + " will ban after " + attempts + " for " + timeBan + " minutes."
	end

end

class Manager
	
	def intialize()
		setup_iptables

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

	def setup_iptables()
		system("iptables -X lxIDS")
		system("iptables -D INPUT -j lxIDS")
		system("iptables -D OUTPUT -j lxIDS")
		system("iptables -N lxIDS")
		system("iptables -A INPUT -j lxIDS")
		system("iptables -A OUTPUT -j lxIDS")
	end

	def check_rules
		File.open($log, "r") do |aFile|
			aFile.each_line("\n") do |line|
				call_rule
			end
		end
	end

	def call_rule
		$rules.each do |rule|
			if line.includes?(rule.service) and line.includes?(rule.event)
				$users.each do |user|
					if user.ip == line[$ip_parse] && user.attempts + 1 == rule.attempts
						system(rule.response.sub!('%IP%', user.ip))
						user.attempts = 0
						if(rule.time_ban > 0)
							system(rule.unban_response.sub!('%IP%', user.ip))
						elsif user.ip == line[$ip_parse] && user.attempts += 1 < rule.attempts
							next
						end
					end
				end
			end
		end
	end

end

###############################
###Central Body of the Program#
###############################
puts "Welcome to the lxIDS"
puts "Intializing rules..."

rule_manager = Manager.new

File.open($log) do |file|
	file.seek(0, IO::SEEK_END)     
	queue = INotify::Notifier.new  
	queue.watch($log, :modify) do
		rule_manager.check_rules          		 # this is a callback block
	end
	queue.run                      
end




