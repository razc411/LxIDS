#CONFIGURATION#########################################################################
$log = [
	"/var/log/secure",
	"/var/log/tempt.t"
]			# => Logs to watch for events
$rcfg = "rules.cfg" 		# => rules config file location
#DO NOT EDIT BELOW, MAIN CODE BODY#####################################################
#DO NOT EDIT BELOW, MAIN CODE BODY#####################################################
#DO NOT EDIT BELOW, MAIN CODE BODY(unless you know what you're doing)##################
require 'rb-inotify'
require 'date'
load 'src/user.rb'
load 'src/rule.rb'
load 'src/manager.rb'
#####Central Body######################################################################
# Welcome to the LxIPS Ruby Application!
# => A simple, customizable intrusion prevention system for linux.
# => Please refer to the readme for more information.
# Classes
# => User 	 - src/user.rb
# => Manager - src/manager.rb
# => Rule 	 - src/rule.rb
#
# Called at program start. Prints welcome message, creates the rule manager
# and adds a callback for rule checking on every specified log file.
#######################################################################################
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
               
