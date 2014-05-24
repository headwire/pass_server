require './pass_server'

# Used to implement HTTP PUT and DELETE with HTTP POST and _method
use Rack::MethodOverride

# Pass Server Settings
PassServer.set :hostname, "107.170.50.205"
PassServer.set :port, 8080
PassServer.set :pass_type_identifier, "pass.co.iveew"
PassServer.set :team_identifier, "TH6A6P"

# Ask user for certificate password
#puts "Please enter your certificate password: "
#password_input = gets.chomp
#PassServer.set :certificate_password, password_input

# OR set predefined:
PassServer.set :certificate_password, "CegthCathjbl"

run PassServer
