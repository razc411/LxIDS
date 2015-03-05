########################################################################################
# Class User
# Author:   	Ramzi Chennafi
# Date: 		Febuary 28 2015
# Functions: 
# => void intialize(ip)
# => void add_service_attempt(service)
# => void set_time_attempt(service)
# => boolean check_time(attempt_time, service) 
# => void self.get_time 						#STATIC METHOD

# User class defines a single user. Holds the failed attempts made on specific services.
########################################################################################
class User
	attr_accessor :ip, :attempts, :last_attempt, :status, :last_banned, :time_to_unban
	# Function 	: initialize(ip)
	# => ip 	: ip of the user to be created
	# Author	: Ramzi Chennafi
	# Date		: Febuary 28 2015
	# Returns	: Nothing
	#
	# Description
	# Constructs a user according to the given IP.
	def initialize(ip)
		@ip 			= ip
		@attempts 		= Hash.new
		@last_attempt 	= Hash.new(Hash.new)
		@status 		= "VALID"
		@last_banned 	= 0
		@time_to_unban 	= 0
	end
	# Function 	: add_service_attempt(service)
	# => service : the service to add an attempt for
	# Author	: Ramzi Chennafi
	# Date		: Febuary 28 2015
	# Returns	: Nothing
	#
	# Description
	# Adds an intial attempt on a service. Also sets the time of this attempt.
	def add_service_attempt(service)
		@attempts[service] = 1
		set_time_attempt(service)
		self.print_attempt(service)
	end
	# Function 	: set_time_attempt(service)
	# => service : the service to set the time of the last attempt for
	# Author	: Ramzi Chennafi
	# Date		: Febuary 28 2015
	# Returns	: Nothing
	#
	# Description
	# Sets the date and time of the last attempt on a specific service.
	def set_time_attempt(service)
		@last_attempt[service]["time"] = User.get_time
	end
	# Function 	: check_time(attempt_time, service) 
	# => attempt_time : the time of a recent rule infraction
	# => service 	  : the rule to check the time for
	# Author	: Ramzi Chennafi
	# Date		: Febuary 28 2015
	# Returns	: Boolean, true if the time between attempts is within the limit, false otherwise.
	#
	# Description
	# Checks if a recent attempt is within the the time limit of the previous attempt according to
	# service rules.
	def check_time(attempt_time, service) 
		if ((User.get_time - last_attempt[service]['time'].to_i) >= attempt_time)
			self.add_service_attempt(service)			
			return false
		end
		return true
	end
	# Function 	: print_attempt(service)
	#=> service	: the service to be printed about
	# Author	: Ramzi Chennafi
	# Date		: Febuary 28 2015
	# Returns	: Nothing
	#
	# Description
	# Prints data on a service attempt.
	def print_attempt(service)
		puts "Failed attempt #" + attempts[service].to_s + " on " + service + " by " + ip + " at " + DateTime.now.to_s
	end
	# Function 	: self.get_time
	# Author	: Ramzi Chennafi
	# Date		: Febuary 28 2015
	# Returns	: Nothing
	#
	# Description
	# Static method for getting the current time in a useful format
	def self.get_time
		current_time = Time.now.to_i
		return current_time
	end
end
