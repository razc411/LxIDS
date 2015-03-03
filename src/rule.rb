########################################################################################
# Class Rule
# Author:   	Ramzi Chennafi
# Date: 		Febuary 28 2015
# Functions: 
# => void intialize(rule)
# => void print_rule()
# 
# Description
# Rule class, defines a single IPS rule.
########################################################################################
class Rule
	attr_accessor :service, :event, :response, :attempt_time, :attempts, :time_ban, :unban_response
	# Function 	: initialize(rule)
	# => rule 	: line from the config file which a rule will be created from.
	# Author	: Ramzi Chennafi
	# Date		: Febuary 28 2015
	# Returns	: Nothing
	#
	# Description
	# Constructs a rule according to the line given.
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
	# Function 	: print_rule()
	# Author	: Ramzi Chennafi
	# Date		: Febuary 28 2015
	# Returns	: Nothing
	#
	# Description
	# Prints out an instance of this object's information.
	def print_rule()
		puts service + " will ban after " + attempts.to_s + " attempts at event: " + event + ", for " + time_ban.to_s + " minutes."
	end
end