require 'byebug'
require 'logger'

require 'sinatra/base'
require 'sequel'
require 'sqlite3'
#require 'yaml'
require 'json'
#require 'socket'

require 'securerandom'
#require File.dirname(File.expand_path(__FILE__)) + '/lib/apns.rb'
require File.expand_path('../lib/apns.rb', __FILE__)
require File.expand_path('../lib/sign_pass.rb', __FILE__)

# DataMapper
require "data_mapper"
require_relative "lib/passes_json"
require "dm-serializer"
require 'json-schema'
require 'rake'

# helper for compare single var against multiple values
class Object
  def in? container
    container.include? self
  end
end


class PassServer < Sinatra::Base
  attr_accessor :db, :users, :passes, :registrations

  ::Logger.class_eval { alias :write :'<<' }
  access_logger = ::Logger.new( ::File.new("log/pass_server.access.log", "a+") )
  error_logger = ::File.new("log/pass_server.error.log", "a+")
  error_logger.sync = true

  configure :production, :development do
    # Register MIME type for pass files
    mime_type :pkpass, 'application/vnd.apple.pkpass'

    enable :logging, :dump_errors
    # should add Rack::ShowExceptions here !!!
    # !!! but only for development mode !!!
    set :raise_errors, true
    # This is needed for testing, otherwise the default
    # error handler kicks in:
    #set :show_exceptions, false

    use ::Rack::CommonLogger, access_logger
    # enabling encrypted, cookie-based sessions
    #set :sessions, true
    set :root, File.dirname(__FILE__)

    # setting DB mapper and connection
    # ??? or all ORM goes to *_ctl* server ???
    # DataMapper setup
    DataMapper::Logger.new($stdout, :debug)
    json_db_file = File.expand_path("#{Dir.pwd}/data/passes_json.sqlite3")
    # Create an empty database file
    if !File.exists?(json_db_file)
      File.open(json_db_file, "w"){}
    end

    # to raise errors vs true/false returns:
    # DataMapper::Model.raise_on_save_failure = true  # globally across all models
    #
    # possible DataMapper exceptions:
    # rescue DataMapper::SaveFailureError => e
    # # => DataMapper::UpdateConflictError: Zoo#update cannot be called on a dirty resource
    #
    DataMapper.setup(:default, "sqlite3://#{json_db_file}")
    DataMapper.finalize.auto_upgrade!

    # !!! FOR DEVELOPMENT ONLY !!!
    # hard-coded credentials for developer auth
    CREDENTIALS = ['dev@iveew.co', 'apideveloper']
  end

  before do
    # Load in the pass data before each request
    self.db ||= Sequel.sqlite("data/pass_server.sqlite3")
    self.users ||= self.db[:users]
    self.passes ||= self.db[:passes]
    self.registrations ||= self.db[:registrations]

    # set up default rack logger
    env["rack.errors"] =  error_logger

    # set default content_type application/json for all responses
    ### !!! production mode !!!
    #content_type :json, :charset => 'utf-8'
  end

  # Sinatra not found 'this ditty'
  not_found do
    'requested path not found'
  end
  # error handler for development
  # will output all (or just 500, for ex.) errors in json format
  # and also set a default error code
  # * The error handler is invoked any time an exception is raised from a route block or a filter
  error 500 do
    content_type :json
    status 500 # a generic server error
    # maybe we should detail it in some way

    e = env['sinatra.error']
    e.to_json
  end
  # Method Not Allowed:
  # the path exist but no HTTP verb was defined for it
  error 405 do
    status 405, 'the path exist but no HTTP verb was defined for it'
  end
  # generic error: all others
  error do
    status 500, "Wow, some generic Error was popping up: " + params['captures'].first.inspect
  end


  # Registration
  # register a device to receive push notifications for a pass
  #
  # POST /v1/devices/<deviceID>/registrations/<typeID>/<serial#>
  # Header: Authorization: ApplePass <authenticationToken>
  # JSON payload: { "pushToken" : <push token, which the server needs to send push notifications to this device> }
  #
  # Params definition
  # :device_id      - the device's library identifier
  # :pass_type_id   - the bundle identifier for a class of passes, sometimes refered to as the pass topic, e.g. pass.com.apple.backtoschoolgift, registered with WWDR
  # :serial_number  - the pass' serial number
  # :pushToken      - the value needed for Apple Push Notification service
  #
  # server action: if the authentication token is correct, associate the given push token and device identifier with this pass
  # server response:
  # --> if registration succeeded: 201
  # --> if this serial number was already registered for this device: 304
  # --> if not authorized: 401
  #
  post '/v1/devices/:device_id/registrations/:pass_type_id/:serial_number' do

    "#<RegistrationRequest device_id: #{params[:device_id]}, pass_type_id: #{params[:pass_type_id]}, serial_number: #{params[:serial_number]}, authentication_token: #{authentication_token}, push_token: #{push_token}>"

    # Validate that the request is authorized to deal with the pass referenced
    if is_auth_token_valid?(params[:serial_number], params[:pass_type_id], authentication_token)
      puts '[ ok ] Pass and authentication token match.'

      # Validate that the device has not previously registered
      if !device_has_registration_for_serial_number?(params[:device_id], params[:serial_number])
        # No registration found, lets add the device
        puts '[ ok ] Registering device.'
        add_device_registration(params[:device_id], push_token, params[:pass_type_id], params[:serial_number])
        # this one is for development ONLY
        # device_id generated on the server side, but should be generatad on client side (!)
        #byebug
        #add_device_registration(new_device_id, push_token, params[:pass_type_id], params[:serial_number])

        # Return a 201 CREATED status
        status 201
        #headers
      else
        # The device has already registered for updates on this pass
        # Acknowledge the request with a 200 OK response
        puts '[ ok ] Device is already registered.'
        status 200
      end

    else
      # The device did not statisfy the authentication requirements
      # Return a 401 NOT AUTHORIZED response
      puts '[ fail ] Registration request is not authorized.'
      status 401
    end
  end


  # Updatable passes
  #
  # get all serial numbers for passes associated with a device (updatable passes list)
  # Optionally with a query limiter to scope the last update since DateTime
  #
  # GET /v1/devices/<deviceID>/registrations/<typeID>
  # GET /v1/devices/<deviceID>/registrations/<typeID>?passesUpdatedSince=<tag>
  #
  # server action: figure out which passes associated with this device have been modified since the supplied tag (if no tag provided, all associated serial #s)
  # server response:
  # --> if there are matching passes: 200, with JSON payload: { "lastUpdated" : <new tag>, "serialNumbers" : [ <array of serial #s> ] }
  # --> if there are no matching passes: 204
  # --> if unknown device identifier: 404
  #
  get '/v1/devices/:device_id/registrations/:pass_type_id?' do

    puts "#<UpdateRequest device_id: #{params[:device_id]}, pass_type_id: #{params[:pass_type_id]}#{", passesUpdatedSince: " + params[:passesUpdatedSince] if params[:passesUpdatedSince] && params[:passesUpdatedSince] != ""}>"

    # Check first that the device has registered with the service
    if device_has_any_registrations?(params[:device_id])
      puts '[ ok ] Device registration found.'

      # Find the registrations for the device
      # The passesUpdatedSince param is optional for scoping the update query
      updated_since = nil;
      if params[:passesUpdatedSince] && params[:passesUpdatedSince] != ""
        updated_since = DateTime.strptime(params[:passesUpdatedSince], '%s')
      end
      registered_passes = registered_passes_for_device(params[:device_id], params[:pass_type_id], updated_since)

      # Are there passes that this device should recieve updates for?
      if registered_passes.count > 0
        # Found passes that could be updated for this device
        puts '[ ok ] Found passes that could be updated for this device.'

        # Build the response object
        update_time = DateTime.now.strftime('%s')
        updatable_passes_payload = { :lastUpdated => update_time }
        updatable_passes_payload[:serialNumbers] = registered_passes.collect { |rp| rp[:serial_number] }
        updatable_passes_payload.to_json

      else
        puts '[ ok ] No passes found that could be updated for this device.'
        status 204
      end

    else
      # This device is not currently registered with the service
      puts '[ fail ] Device is not registered.'
      status 404
    end
  end


  # Unregister
  #
  # unregister a device to receive push notifications for a pass
  #
  # DELETE /v1/devices/<deviceID>/registrations/<passTypeID>/<serial#>
  # Header: Authorization: ApplePass <authenticationToken>
  #
  # server action: if the authentication token is correct, disassociate the device from this pass
  # server response:
  # --> if disassociation succeeded: 200
  # --> if not authorized: 401
  #
  delete "/v1/devices/:device_id/registrations/:pass_type_id/:serial_number" do
    puts "#<UnregistrationRequest device_id: #{params[:device_id]}, pass_type_id: #{params[:pass_type_id]}, serial_number: #{params[:serial_number]}, authentication_token: #{authentication_token}>"
    if is_auth_token_valid?(params[:serial_number], params[:pass_type_id], authentication_token)
      puts '[ ok ] Pass and authentication token match.'

      # Validate that the device has previously registered
      # Note: this is done with a composite key that is combination of the device_id and the pass serial_number
      if device_has_registration_for_serial_number?(params[:device_id], params[:serial_number])
        puts '[ ok ] Deleting registration.'
        delete_device_registration(params[:device_id], params[:serial_number])
        status 200
      else
        puts '[ fail ] Registration does not exist.'
        status 401
      end

    else
      # Not authorized
      puts '[ fail ] Not authorized.'
      status 401
    end
  end


  # Pass delivery
  # (Getting the Latest Version of a Pass)
  #
  # GET /v1/passes/<typeID>/<serial#>
  # Header: Authorization: ApplePass <authenticationToken>
  #
  # server response:
  # --> if auth token is correct: 200, with pass data payload
  # --> if auth token is incorrect: 401
  # --> MIME Type sets to application/vnd.apple.pkpass
  ## **
  # Support standard HTTP caching on this endpoint:
  # check for the If-Modified-Since header and return HTTP status code 304 if the pass has not changed.
  get '/v1/passes/:pass_type_id/:serial_number' do
    puts "#<PassDeliveryRequest pass_type_id: #{params[:pass_type_id]}, serial_number: #{params[:serial_number]}, authentication_token: #{authentication_token}>"
    # here we get pass object (i.e. table row) is serial+pass_type+applepass_token matches in some valid Pass:
    pass = is_auth_token_valid?(params[:serial_number], params[:pass_type_id], authentication_token)
    if pass
      puts '[ ok ] Pass and authentication token match.'
      # If-Modified-Since header checked
      # Load pass data from database
      last_modified pass[:updated_at] # this helper will send 304 if pass not changed

      # GET-path for pass
      # http://#{settings.hostname}:#{settings.port}/v1/passes/#{params[:pass_type_id]}/#{params[:serial_number]}
      deliver_pass(pass, false) # is user attached?
    end
  end


  # Logging/Debugging from the device
  #
  # log an error or unexpected server behavior, to help with server debugging
  # POST /v1/log
  # JSON payload: { "description" : <human-readable description of error> }
  #
  # server response: 200
  #
  post "/v1/log" do
    if request && request.body
      request.body.rewind
      json_body = JSON.parse(request.body.read)
      log_directory = File.dirname(File.expand_path(__FILE__)) + "/log"
      if !File.exists?(log_directory)
        Dir.mkdir(log_directory)
      end
      File.open(log_directory + "/devices.log", "a") do |f|
        f.write "[#{Time.now}] #{json_body}\n"
      end
    end
    status 200
  end


  ###############################
  # FOR DEVELOPMENT PURPOSES ONLY
  # These endpoints allow developers to create/edit users and download passes.
  #
  # NOTE: These endpoints are not part of the offical passbook API and do not implement
  # any authentication/authorization controls whatsoever.
  # They should only be used for development purposes.
  #

  # Display the home page
  get "/" do
    erb :'index.html'
  end

  # List of users
  #
  # GET /users
  # Header: Authorization: DevToken <dev_token>
  # Header: Accept: application/json
  #
  # server response:
  # --> list of users in JSON format: 200
  #
  # !!! CHECK FOR DEVELOPER API OAuth2 token !!!
  get "/users" do
    ordered_users = self.users.order(:name).all
    if request.accept? "text/html"
      erb :'users/index.html', :locals => { :users => ordered_users }
    elsif request.accept? "application/json"
      content_type 'application/json', :charset => 'utf-8'
      halt 200, ordered_users.to_json
    else
      puts "[ fail ] Bad Request. Unsupported HTTP_ACCEPT Header. Only text/html and application/json supported"
      status 400
    end
  end

  get "/users/new" do
    erb :'users/new.html'
  end

  # Create new user
  # expects json user object
  # request should contain valid dev_token for integrator
  #
  # POST /users
  # Header: Authorization: DevToken <dev_token>
  # JSON payload: {"user":{"name":"UserName", "email":"user@email.com", "account_balance":1111.0}}
  # server response:
  # return: { id : new_user_id, UserToken : <api_token> }
  # --> if auth token is correct: 200, with pass data payload AND new api token returned
  # --> if unsupported HTTP_ACCEPT Header provided: 400
  # --> if json was malformated: 415
  # --> if dev_token is incorrect: 401
  # --> if DB insertion error: 500
  post "/users" do
    #
    # !!! check DevToken !!!
    #
    if request.accept? "text/html"
      # this thread is for html-form post update <edit.html.erb>:
      # <form action="/users/<%= user[:id] %>" method="post">
      if params && params[:user]
        add_user_with_params(params[:user])
        redirect "/users"
      end
    elsif request.accept? "application/json"
      # expect: {"user":{"name":"UserName", "email":"user@email.com", "account_balance":1111.0}}
      # return: { :id => new_user_id, :api_token => p[:api_token] }
      # check user object (in json paylod) for user params
      if request && request.body
        request.body.rewind
        begin
        json_body = JSON.parse(request.body.read)
        # 415 Unsupported Media Type
        # OR 422 Unprocessable Entity
        # in case of wrong JSON format - exception raised
        rescue
          halt 415, 'json payload parsing error'
        end

        if json_body['user']
          # curls with json payload:
          # -d '{"user":{"name":"UserTwo", "email":"Second@user.com", "account_balance":1111.0}}'
          # { :email => email, :name => name, :account_balance => account_balance }
          # json_body["user"]["name"] - user object
          id_and_token = add_user_with_params(json_body['user'])
        end
      end

      if id_and_token
        puts "[ ok ] new user was created successfully. user_id is #{id_and_token[:id]}"
        content_type 'application/json', :charset => 'utf-8'
        halt 200, id_and_token.to_json # here goes a new user's id and api_token
      else
        puts "[ fail ] user was not created"
        content_type 'application/json', :charset => 'utf-8'
        halt 500, 'DB Error'
      end
    else
      puts "[ fail ] Bad Request. Unsupported HTTP_ACCEPT Header. Only application/json supported"
      status 400
    end
  end

  # User Resource
  # GET /users/<user_id>
  # Header: Authorization: UserToken <api_token>
  #
  # server response:
  # --> if Unsupported HTTP_ACCEPT Header: 400
  # --> if Not authorized: 401
  # --> if api token is correct and user exist: 200, User resource in JSON object
  get "/users/:user_id" do
    user = self.users.where(:id => params[:user_id]).first
    if request.accept? "text/html" #HTML requested
      erb :'users/show.html', :locals => { :user => user }
    elsif request.accept? "application/json"
      # !!! check UserToken !!!
      if is_api_token_valid?(params[:user_id], authentication_token)
        puts '[ ok ] api token is valid for given user'
      else
        halt 401, 'Invalid UserToken'
      end

      content_type 'application/json', :charset => 'utf-8'
      halt 200, user.to_json
    else
      puts "[ fail ] Bad Request. Unsupported HTTP_ACCEPT Header. Only text/html and application/json supported"
      status 400
    end
  end

  # GET User's api_token
  # here we should check developer/provider api token
  # before sending him user's api_token
  get "/users/:user_id/token/:dev_token" do
    #
    # !!! check for dev_token !!!
    # puts '[ fail ] Not authorized.'
    # status 401
    user = self.users.where(:id => params[:user_id]).first || raise(Sinatra::NotFound)
    #
    # HTTP_ACCEPT Headers curl -H 'Accept:'
    # request.accept?("text/html") #HTML requested
    # request.accept?("application/json") #JSON requested
    if request.accept? "application/json" #JSON requested
      content_type 'application/json', :charset => 'utf-8'
      user[:api_token].to_json
    else
      puts "[ fail ] Bad Request. Unsupported HTTP_ACCEPT Header. Only application/json supported"
      status 400
    end
  end

  get "/users/:user_id/edit" do
    user = self.users.where(:id => params[:user_id]).first
    erb :'users/edit.html', :locals => { :user => user }
  end

  # Update one user's details
  # expects json user object
  # request should contain valid api_token for current user
  #
  # PUT /users/<user_id>
  # Header: Authorization: UserToken <api_token>
  # JSON payload: {"user":{"name":"UserName", "email":"user@email.com", "account_balance":1111.0}}
  # server response:
  # --> if auth token is correct: 200, with pass data payload AND new api token returned
  # --> if unsupported HTTP_ACCEPT Header provided: 400
  # --> if json was malformated: 415
  # --> if api_token is incorrect: 401
  # --> if user data are the same <account_balance>: 304
  put "/users/:user_id" do
    if request.accept? "text/html"
      # this thread is for html-form post update <edit.html.erb>:
      # <form action="/users/<%= user[:id] %>" method="post">
      if params && params[:user_id] && params[:user]
        update_user_with_params(params[:user_id], params[:user])
        redirect "/users"
      end
    elsif request.accept? "application/json"
      # !!! check UserToken !!!
      if is_api_token_valid?(params[:user_id], authentication_token)
        puts '[ ok ] api token is valid for given user'
      end
      # check user object (in json paylod) for user params
      # and updating user info
      if request && request.body
        request.body.rewind
        begin
        json_body = JSON.parse(request.body.read)
        # 415 Unsupported Media Type
        # OR 422 Unprocessable Entity
        # in case of wrong JSON format - exception raised
        rescue
          halt 415, 'json payload parsing error'
        end

        if json_body['user']
          # curls with json payload:
          # -d '{"user":{"name":"UserTwo", "email":"Second@user.com", "account_balance":1111.0}}'
          # json_body["user"]["name"] - user object
          new_api_token = update_user_with_params(params[:user_id], json_body['user'])
        end
      end

      if new_api_token
        puts "[ ok ] user details for user #{params[:user_id]} was updated successfully"
        content_type 'application/json', :charset => 'utf-8'
        halt 200, { "UserToken"=> new_api_token.to_s }.to_json # here goes a new api_token, because old one was changed
      else
        puts "[ ok ] user details for user #{params[:user_id]} was NOT updated, because nothing to update"
        content_type 'application/json', :charset => 'utf-8'
        halt 304, 'nothing to update' # api_token remains old
      end
    else
      puts "[ fail ] Bad Request. Unsupported HTTP_ACCEPT Header. Only application/json supported"
      status 400
    end
  end


  # Delete a user account
  #
  # DELETE /users/<user_id>
  # Header: Authorization: UserToken <api_token>
  # server response:
  # --> if auth token is correct: 200
  # --> if api_token is incorrect: 401
  # --> if DB access error: 500
  delete "/users/:user_id" do
    if request.accept? "text/html"
      if params && params[:user_id]
        delete_user(params[:user_id])
        redirect "/users"
      end
    elsif request.accept? "application/json"
      # !!! check UserToken !!!
      if is_api_token_valid?(params[:user_id], authentication_token)
        puts '[ ok ] api token is valid for given user'
      end

      begin
        delete_user(params[:user_id])
      rescue
        halt 500, 'DB access error'
      else
        halt 200, "user #{params[:user_id]} was deleted successfully"
      end
    end

  end

  # Download one user's pass
  # (for web page/admin link)
  #
  # GET /users/<user_id>/pass.pkpass
  # server response:
  # --> if pass exist: 200 and pkpass payload
  # --> if DB access error: 500
  #
  get "/users/:user_id/pass.pkpass" do
    begin
      deliver_pass_for_user(params[:user_id])
    rescue
      halt 500, 'DB access error'
    else
      halt 200
    end
  end

  # Get User by Pass
  # Retrieve the owner of the specified pass
  # Used by the iOS app to match a pass's barcode to a user account
  get "/user_for_pass/:pass_type_id/:serial_number/:authentication_token" do
    pass = self.passes.where(:pass_type_id => params[:pass_type_id], :serial_number => params[:serial_number], :authentication_token => params[:authentication_token]).first
    if pass
      user_id = pass[:user_id]
      redirect "/users/#{user_id}"
    else
      status 404
    end
  end

  ###
  # End of development-only endpoints.
  ####################################
  # Pass Data (aka pass.json and pass url) API
  # Pass Template API

  # Get a list of all passes data
  # for web UI and development only
  get "/passes" do
    # let's check validity of provided DevToken in Authorization Header
    # and halt with 401 if it is wrong
    check_dev_token? if !request.accept? "*/*"

    content_type :json
    get_all_passes_data.to_json
  end

  # Get pass.json payload by pass serial No.
  # GET /passes/json/<pass_type_id>/<serial_number>
  # Header: Authorization: DevToken <dev_token>
  # in param:
  # :pass_type_id   - the bundle identifier for a class of passes, sometimes refered to as the pass topic, e.g. pass.com.apple.backtoschoolgift, registered with WWDR
  # out param:
  # :serial_number  - the pass serial number
  #
  # server response:
  # return: [passType: 'pass/template', passData: { <pass.json> data }]
  # --> if auth token is correct: 200, with <pass.json> data
  # --> if unsupported HTTP_ACCEPT Header provided: 400
  # --> if dev_token is incorrect: 401
  # --> if can't get pass.json data by this serial: 422 (Unprocessable Entity)
  get "/passes/json/:pass_type_id/:serial_number" do
    if !request.accept? "application/json"
      puts "[ fail ] Bad Request. Unsupported HTTP_ACCEPT Header. Only application/json supported"
      halt 400, "Bad HTTP_ACCEPT Header. Only application/json supported"
    end

    # let's check validity of provided DevToken in Authorization Header
    # and halt with 401 if it is wrong
    check_dev_token?

    # check for valid pass_type_id
    # passes in passes_json and passes tables should match!
    begin
      pass_serial = self.passes.where(:pass_type_id => params[:pass_type_id], :serial_number => params[:serial_number]).select(:serial_number).first
    rescue Sequel::Error => e
      halt 500, e.message
    else
      pass_json = PassJson.first(:serial => params[:serial_number])
      content_type :json

      # Pass
      if pass_serial && pass_json && pass_json["serial"] == pass_serial[:serial_number]
        # pass.json exist and there is a serial in passes table
        halt 200, "[passType: 'pass', passData: #{pass_json[:json_data]}]"
      elsif pass_json # Template
        # there is NO pass in passes table with that serial,
        # let's take it from PassJson - it is a template
        halt 200, "[passType: 'template', passData: #{pass_json[:json_data]}]"
      else # 422 Unprocessable Entity
        halt 422, "there is no pass.json with [#{params[:serial_number]}] serial"
      end
    end
  end

  # Create new Pass Data Template (pass.json data)
  # expects json to create a new PassJson object
  # request should contain valid dev_token for integrator
  #
  # POST /passes/json/<pass_type_id>/<pass_type>
  # Header: Authorization: DevToken <dev_token>
  # JSON payload: ** see a pass.json sample file **
  # in param:
  # :pass_type_id   - the bundle identifier for a class of passes, sometimes refered to as the pass topic, e.g. pass.com.apple.backtoschoolgift, registered with WWDR
  # :pass_type - type of received data: 'pass' or 'template'
  # * 'pass' type triggers pass signing, packing, saving to DB for access via API and triggers APNS update
  # out param:
  # :serial_number  - the pass serial number
  #
  # server response:
  # return: { id : new_pass_id, type: '<pass_or_template>', serial : <pass_serial_number>, url : <pass_access_url> }
  # --> if auth token is correct: 200, with pass id, serial no. and pass url
  # --> if unsupported HTTP_ACCEPT Header provided: 400
  # --> if json or other data was malformated: 415
  # --> if dev_token is incorrect: 401
  # --> if DB insertion error: 500
  post "/passes/json/:pass_type_id/:pass_type" do
    #
    # !!! no need in DevToken for web/dev mode !!!
    #
    halt 415, 'wrong pass type' unless params[:pass_type].in? ['pass', 'template']

    if request.accept? "text/html"
      # this thread is for html-form post update <edit.html.erb>:
      # <form action="/passes/<%= pass[:id] %>" method="post">
      if params && params[:pass]
        #byebug
        #add_pass_template_with_params(params[:pass])
        redirect "/passes"
      end
    elsif request.accept? "application/json"
      # let's check validity of provided DevToken in Authorization Header
      # and halt with 401 if it is wrong
      check_dev_token?

      # expect: {json} in pass.json format
      # return: { :id => new_pass_id, :serial => p[:serial], :url => p[:url], :created_at => p[:created_at], :updated_at => p[:updated_at] }
      # check pass.json object (inbound json paylod)
      if request && request.body
        request.body.rewind
        begin
          ########
          # ******
          # DEV MODE !!!
          # change to JSON.parse(request.body.read)
          # ******
          #template_pass = File.dirname(File.expand_path(__FILE__)) + "/data/passes/template/pass.json"
          #pass_json = JSON.parse(File.read(template_pass))
          pass_json = JSON.parse(request.body.read)

          # 415 Unsupported Media Type
          # OR 422 Unprocessable Entity
          # in case of wrong JSON format - exception raised

          # loading pass.json schema to validate against
          pass_schema_path = File.dirname(File.expand_path(__FILE__)) + "/data/pass_schema.json"
          pass_schema = JSON.parse(File.read(pass_schema_path))
        rescue
          halt 415, 'json payload parsing and validating error'
        end

        # here we validate json data against pass_schema.json
        begin
          JSON::Validator.validate!(pass_schema, pass_json)
        rescue JSON::Schema::ValidationError
          halt 415, $!.message
        end

        # here we check/select pass type - 'storeCard'
        # !!! aslo should check: locations, relevantDate, and other params !!!
        if pass_json['storeCard'] && params[:pass_type_id]
          # pass type is 'storeCard'
          # and we finally could save the pass to passes_json resource table
          @new_serial = new_serial_number
          ########
          # ******
          # ADD SSL = httpS:// !!!
          # ******
          @pass_json = PassJson.create(
            :serial      => @new_serial,
            :url       => "http://#{settings.hostname}:#{settings.port}/v1/passes/#{params[:pass_type_id]}/#{@new_serial}",
            :json_data  => pass_json.to_json,
            :created_at => Time.now,
            :updated_at => Time.now
          )
          # adding the same data to passes table
          # user_id == nil means a pass was created via APIs, not weird web-interface
          # that is because :user_id column is a foreign key !!! in passes table
          # thus we set it to NULL
          @new_authentication_token = new_authentication_token
          @new_pass_id = add_pass(@new_serial, @new_authentication_token, params[:pass_type_id], nil, params[:pass_type])

          # save as a Pass =>> returns new_pass_id
          # save as a Template =>> new pass_json_id
          # return: { :id => new_pass_id, type: 'params[:pass_type]', :serial => p[:serial], :url => p[:url], :created_at => p[:created_at], :updated_at => p[:updated_at] }
          @pass_id = params[:pass_type] == 'pass' ? @new_pass_id : @pass_json[:id]

          ###
          # sign and generate a new pass package
          # and store it by GET-url in DB
          # for 'pass' type only
          ###
          # "http://#{settings.hostname}:#{settings.port}/v1/passes/#{params[:pass_type_id]}/#{@new_serial}"
          # GET by: @pass_json[:url]
          if params[:pass_type] == 'pass'
            new_pass_path = create_pkpass(@new_serial, params[:pass_type_id], @new_authentication_token)
            # pushes should be sent only for registered devices - thus only in Update Pass
          end

          json_response = "{id: #{@pass_id}, type: '#{params[:pass_type]}', serial: '#{@new_serial}', url: '#{@pass_json[:url]}', created_at: #{@pass_json[:created_at]}, updated_at: #{@pass_json[:updated_at]}}"
        end
      end

      if json_response
        puts "[ ok ] new pass template was created successfully. pass serial is: #{@new_serial}"
        content_type 'application/json', :charset => 'utf-8'
        halt 200, json_response # here goes response json
      else
        puts "[ fail ] pass template was not created because of DB Error"
        content_type 'application/json', :charset => 'utf-8'
        halt 500, 'DB Error'
      end
    else
      puts "[ fail ] Bad Request. Unsupported HTTP_ACCEPT Header. Only application/json supported"
      status 400
    end
  end


  # Update Pass Data Template (pass.json data)
  # expects json to update a PassJson object
  # request should contain valid dev_token for integrator
  #
  # PUT /passes/json/<pass_serial>
  # Header: Authorization: DevToken <dev_token>
  # JSON payload: ** see a pass.json sample file **
  # in param:
  # <pass_serial> - the pass serial number
  #
  # server response:
  # return: { id : new_pass_id, type: '<pass_or_template>', serial : <pass_serial_number>, url : <pass_access_url> }
  # --> if auth token is correct: 200, with updated pass id
  # --> if unsupported HTTP_ACCEPT Header provided: 400
  # --> if json or other data was malformated: 415
  # --> if dev_token is incorrect: 401
  # --> if pass_serial is wrong: 404
  # --> if DB insertion error: 500
  put "/passes/json/:pass_serial" do
    if request.accept? "text/html"
      # this thread is for html-form post update <edit.html.erb>:
      # <form action="/passes/<%= pass[:id] %>" method="post">
      if params && params[:pass]
        #byebug
        #add_pass_template_with_params(params[:pass])
        redirect "/"
      end
    elsif request.accept? "application/json"
      # let's check validity of provided DevToken in Authorization Header
      # and halt with 401 if it is wrong
      check_dev_token?

      # do we have a pass with that serial?
      halt 404, 'this pass serial was not found' unless params[:pass_serial] && PassJson.first(:serial => params[:pass_serial])

      # expect: {json} in pass.json format
      # check pass.json object (inbound json paylod)
      halt 400, 'empty body' unless request && request.body
        request.body.rewind
        begin
          ########
          # ******
          # DEV MODE !!!
          # change to JSON.parse(request.body.read)
          # ******
          #test_pass = File.dirname(File.expand_path(__FILE__)) + "/data/passes/1/pass.json"
          #pass_json = JSON.parse(File.read(test_pass))
          pass_json = JSON.parse(request.body.read)

          # 415 Unsupported Media Type
          # OR 422 Unprocessable Entity
          # in case of wrong JSON format - exception raised

          # loading pass.json schema to validate against
          pass_schema_path = File.dirname(File.expand_path(__FILE__)) + "/data/pass_schema.json"
          pass_schema = JSON.parse(File.read(pass_schema_path))
        rescue
          halt 415, 'json payload parsing and validating error'
        end

        # here we validate json data against pass_schema.json
        begin
          JSON::Validator.validate!(pass_schema, pass_json)
        rescue JSON::Schema::ValidationError
          halt 415, $!.message
        end

        # here we check/select pass type - 'storeCard'
        # !!! aslo should check: locations, relevantDate, and other params !!!
        #if pass_json['storeCard'] && params[:pass_type_id]
          # pass data is correct
          # and we finally could update the pass to passes_json resource table
          ########
          # ******
          # ADD SSL = httpS:// !!!
          # ******
          pass_json_obj = PassJson.first(:serial => params[:pass_serial])
          update_result = pass_json_obj.update(
            :json_data  => pass_json,
            :updated_at => Time.now
          )
        #end
        ###
        # sign and generate a new pass package
        # and store it by GET-url in DB
        # for 'pass' type only
        ###
        # if there is a Pass in pass table
        # it means it is a 'pass'-type => re-pack and send a push update
        pass = self.passes.where(:serial_number => params[:pass_serial]).first || halt(404) #, 'cannot find pass with specified serial'
        if pass
          new_pass_path = create_pkpass(params[:pass_serial], pass[:pass_type_id], pass[:authentication_token])
          push_update_for_pass(@new_pass_id) if new_pass_path # was created sucessfully
          # pushes should be sent only for registered devices - thus only in Update Pass
          # and only if there is a registered device for that pass serial
        end

      if update_result
        puts "[ ok ] pass data was updated successfully for pass serial: [#{params[:pass_serial]}]"
        content_type 'application/json', :charset => 'utf-8'
        halt 200, "[ ok ] pass data was updated successfully for pass serial: [#{params[:pass_serial]}]"
      else
        puts "[ fail ] pass data was not updated because of DB Error"
        content_type 'application/json', :charset => 'utf-8'
        halt 500, 'DB Error'
      end
    else
      puts "[ fail ] Bad Request. Unsupported HTTP_ACCEPT Header. Only application/json supported"
      status 400
    end
  end


  # Delete a Pass or Json Data Template
  #
  # DELETE /passes/<pass_serial>/<pass_type>
  # Header: Authorization: DevToken <dev_token>
  # in param:
  # <pass_serial> - the pass serial number
  # <pass_type> - the pass type: 'pass' or 'template'

  #
  # server response:
  # --> if sucessfully deleted: 200
  # --> if unsupported HTTP_ACCEPT Header provided: 400
  # --> if pass_serial is wrong: 404
  # --> if pass_type is wrong: 415
  # --> if dev_token is incorrect: 401
  # --> if DB deletion error: 500
  delete "/passes/:pass_serial/:pass_type" do
    halt 400, "[ fail ] Bad Request. Unsupported HTTP_ACCEPT Header. Only application/json supported" unless request.accept? "application/json"
    halt 415, '[ fail ] wrong pass type' unless params[:pass_type].in? ['pass', 'template']
    # let's check validity of provided DevToken in Authorization Header
    # and halt with 401 if it is wrong
    check_dev_token?

    begin
    pass = self.passes.where(:serial_number => params[:pass_serial], :pass_type => params[:pass_type]).first
    # do we have a pass with that serial?
    halt 404, 'there is no pass with that serial and type' unless params[:pass_serial] &&
          params[:pass_serial] && pass

    self.passes.where(:id => pass[:id]).delete
    PassJson.first(:serial => params[:pass_serial]).destroy

      puts "[ ok ] pass data was updated successfully for pass serial: [#{params[:pass_serial]}]"
      content_type 'application/json', :charset => 'utf-8'
      halt 200, "[ ok ] pass data was updated successfully for pass serial: [#{params[:pass_serial]}]"
    rescue
      puts "[ fail ] pass data was not updated because of DB Error"
      content_type 'application/json', :charset => 'utf-8'
      halt 500, 'DB Error'
    end
  end


  # End of Pass Data (pass.json data_mapper)
  ####################################


  private

  #######################
  # pass.json templates

  def get_all_passes_data
    PassJson.all(:order => :id)
  end

  #
  ########################

  def add_user(email, name, account_balance)
    p = { :email => email, :name => name, :account_balance => account_balance }
    add_user_with_params(p)
  end

  def add_user_with_params(p)
    now = DateTime.now
    p[:created_at] = now
    p[:updated_at] = now
    ##
    # FOR DEVELOPMENT ONLY
    ##
    # device_id = user's device
    # should be updated later
    # !!!
    p[:device_id] = 'nil';
    p[:api_token] = new_authentication_token
    new_user_id = self.users.insert(p)
    # Also create a pass for the new user
    # for testing/dev only
    add_pass_for_user(new_user_id)

    return { :id => new_user_id, :api_token => p[:api_token] }
  end

  def update_user_with_params(user_id, p)
    now = DateTime.now
    user_is_dirty = false
    p[:updated_at] = now
    p[:api_token] = new_authentication_token
    begin
      user = self.users.where(:id => user_id) || raise(Sinatra::NotFound)
      unless user.first[:account_balance] == p["account_balance"]
        user.update(p)
        user_is_dirty = true
      end
    rescue
      halt 415, 'json paylod for user data is malformed or DB update error'
    end

    # Send push notification
    # ONLY IF DATA FIELD (pass json paylod) have changed
    # :account_balance
    if user_is_dirty
      # Also update updated_at field of user's pass
      pass = self.passes.where(:user_id => user_id)
      pass.update(:updated_at => now)

      pass_id = pass.first[:id]
      push_update_for_pass(pass_id)
      # updaing user info causes new api token generation, for security reasons
      p[:api_token]
    end
  end

  def delete_user(user_id)
    self.users.where(:id => user_id).delete
  end

  def add_pass_for_user(user_id)
    serial_number = new_serial_number
    auth_token = new_authentication_token
    add_pass(serial_number, auth_token, settings.pass_type_identifier, user_id, 'pass')
  end

  def add_pass(serial_number, authentication_token, pass_type_id, user_id, pass_type)
    now = DateTime.now
    self.passes.insert(:user_id => user_id, :serial_number => serial_number, :authentication_token => authentication_token, :pass_type_id => pass_type_id, :pass_type => pass_type, :created_at => now, :updated_at => now)
  end

  def add_device_registration(device_id, push_token, pass_type_identifier, serial_number)
    now = DateTime.now
    uuid = registration_uuid_for_device(device_id, serial_number)
    self.registrations.insert(:uuid => uuid, :device_id => device_id, :pass_type_id => pass_type_identifier, :push_token => push_token, :serial_number => serial_number, :created_at => now, :updated_at => now)
  end

  def delete_device_registration(device_id, serial_number)
    uuid = registration_uuid_for_device(device_id, serial_number)
    self.registrations.where(:uuid => uuid).delete
  end

  # Validate that the request is authorized to deal with the pass referenced
  def is_auth_token_valid?(serial_number, pass_type_identifier, auth_token)
    begin
      pass = self.passes.where(:serial_number => serial_number, :pass_type_id => pass_type_identifier, :authentication_token => auth_token).first || raise(Sinatra::NotFound)
    rescue => e
      halt 500, 'DB access error'
    end

    if pass
      return pass
    else
      halt 401, 'ApplePass token for Pass is incorrect'
    end
  end

  # Validate that the request has valid api_token
  def is_api_token_valid?(user_id, user_token)
    user = self.users.where(:id => user_id, :api_token => user_token).first
    if user
      return true
    else
      halt 401, 'api_token is incorrect'
    end
  end

  # Check validity of DevToken in Authorization Header
  def check_dev_token?
    dev_token = self.users.where(:api_token => authentication_token).select(:api_token).first
    if dev_token
      return true
    else
      halt 401, 'DevToken is incorrect'
    end
  end

  # Check if a device is already registered
  def device_has_any_registrations?(device_id)
    registration_count = self.registrations.where(:device_id => device_id).count
    if registration_count > 0
      return true
    else
      return false
    end
  end

  def device_has_registration_for_serial_number?(device_id, serial_number)
    uuid = registration_uuid_for_device(device_id, serial_number)
    if self.registrations.where(:uuid => uuid).count > 0
      return true
    else
      return false
    end
  end

  def registration_uuid_for_device(device_id, serial_number)
    # Note: UUID is a composite key that is combination of the device_id and the pass serial_number
    raise "device_id must not be nil" if device_id.nil?
    raise "serial_number must not be nil" if serial_number.nil?
    return device_id + "-" + serial_number
  end

  def registered_passes_for_device(device_id, pass_type_identifier, updated_since)
    registered_serial_numbers = self.registrations.where(:device_id => device_id, :pass_type_id => pass_type_identifier).collect { |r| r[:serial_number] }

    if updated_since
      registered_passes = self.passes.where(:serial_number => registered_serial_numbers).filter('updated_at IS NULL OR updated_at >= ?', updated_since)
    else
      registered_passes = self.passes.where(:serial_number => registered_serial_numbers)
    end
    return registered_passes
  end

  def deliver_pass_for_user(user_id)
    user = self.users.where(:id => params[:user_id]).first
    pass = self.passes.where(:user_id => user[:id]).first || halt(404) # cannot find pass for that user
    # or
    # pass = self.passes.where(:serial_number => serial_number, :pass_type_id => pass_type_identifier).first || halt(404) #, 'cannot find pass with specified serial and type'
    # ??
    deliver_pass(pass) # is user attached?
  end

  # this one is an old routine
  # for giving away a pass by web/admin link (in user's profile)
  def deliver_pass(pass, is_user_attached=true)
    pass_id = pass[:id]
    user_id = pass[:user_id] if is_user_attached
    if is_user_attached && user_id
      user = self.users.where(:id => user_id).first || halt(404) #, 'cannot find user with specified identifier'
    end

    # Configure folder paths
    passes_folder_path = File.dirname(File.expand_path(__FILE__)) + "/data/passes"
    template_folder_path = passes_folder_path + "/template"
    target_folder_path = passes_folder_path + "/#{pass_id}"

    # Delete pass folder if it already exists
    if (File.exists?(target_folder_path))
      puts "[ ok ] Deleting existing pass data."
      FileUtils.remove_dir(target_folder_path)
    end

    # Copy pass files from template folder
    puts "[ ok ] Creating pass data from template."
    FileUtils.cp_r template_folder_path + "/.", target_folder_path


    ######################
    # here should be 'get json pass template/payload from DB'
    ######################
    #********************************************************
    # Modify the pass json
    puts "[ ok ] Updating pass data."
    json_file_path = target_folder_path + "/pass.json"
    pass_json = JSON.parse(File.read(json_file_path))
    pass_json["passTypeIdentifier"] = settings.pass_type_identifier
    pass_json["teamIdentifier"] = settings.team_identifier
    pass_json["serialNumber"] = pass[:serial_number]
    pass_json["authenticationToken"] = pass[:authentication_token]
    pass_json["webServiceURL"] = "http://#{settings.hostname}:#{settings.port}/"
    pass_json["barcode"]["message"] = barcode_string_for_pass(pass)
    if user
      pass_json["storeCard"]["primaryFields"][0]["value"] = user[:account_balance]
      pass_json["storeCard"]["secondaryFields"][0]["value"] = user[:name]
    else
      pass_json["storeCard"]["primaryFields"][0]["value"] = 1000000 # just a demo value
      pass_json["storeCard"]["secondaryFields"][0]["value"] = "John Doe" # a demo value
    end
    #********************************************************

    # Write out the updated JSON
    ############################
    # => to DB
    # **************************
    File.open(json_file_path, "w") do |f|
      f.write JSON.pretty_generate(pass_json)
    end

    # Prepare for pass signing
    pass_folder_path = target_folder_path
    pass_signing_certificate_path = get_certificate_path
    wwdr_certificate_path = get_wwdr_certificate_path
    pass_output_path = passes_folder_path + "/#{pass_id}.pkpass"

    # Remove the old pass if it exists
    if File.exists?(pass_output_path)
      File.delete(pass_output_path)
    end

    # Generate and sign the new pass
    ############################
    # => to DB
    # **************************
    pass_signer = SignPass.new(pass_folder_path, pass_signing_certificate_path, settings.certificate_password, wwdr_certificate_path, pass_output_path)
    pass_signer.sign_pass!
    # **************************
    # Send the pass file
    puts '[ ok ] Sending pass file.'
    send_file(pass_output_path, :type => :pkpass)
  end

  # create and sign a new pkpass package
  def create_pkpass(serial_number, pass_type_identifier, pass_auth_token)
    # Load pass data from database
    # !!! add DB connection error !!!
    pass = self.passes.where(:serial_number => serial_number, :pass_type_id => pass_type_identifier).first || halt(404) #, 'cannot find pass with specified serial and type'

    # this id is from passes db !!!
    # NOT from passes_json
    pass_id = pass[:id]
    # no need in User Balance - it is a generic pass
    #user_id = pass[:user_id]
    #user = self.users.where(:id => user_id).first || halt(404) #, 'cannot find user with specified identifier'

    # Configure folder paths
    passes_folder_path = File.dirname(File.expand_path(__FILE__)) + "/data/passes"
    template_folder_path = passes_folder_path + "/template"
    target_folder_path = passes_folder_path + "/#{pass_id}"

    # Delete pass folder if it already exists
    # we're storig BLOBs/files on disk for speed concern (not in sqlite)
    if (File.exists?(target_folder_path))
      puts "[ ok ] Deleting existing pass data."
      FileUtils.remove_dir(target_folder_path)
    else
      FileUtils.mkdir_p(target_folder_path)
    end

    # Copy pass files from template folder
    # except pass.json
    puts "[ ok ] Creating pass data from template."
    # copy all pkpass resources into new folder for archiving
    # excluding pass.json - because it is a tempalte file, the real json payload data comes from PassJson
    list_of_resources = FileList[template_folder_path + "/*"].exclude(/pass.json$/)
    FileUtils.cp_r(list_of_resources, target_folder_path)
    #the FileUtils class mimics a bash shell's file utilities, so "mv" is "move" and "cp" is "copy".


    ######################
    # here should be 'get json pass template/payload from DB'
    ######################
    #********************************************************
    # Modify the pass json
    puts "[ ok ] Updating pass data."
    json_file_path = target_folder_path + "/pass.json"
    #pass_json = JSON.parse(File.read(json_file_path))
    begin #raise $!, "You fool! Look what you have done! #{$!}", $!.backtrace
      pass_json_string = PassJson.first(:serial => serial_number, :fields => [:json_data])[:json_data] || raise($!, "wrong or empty json_data")
      pass_json = JSON.parse(pass_json_string) || raise($!, "json parsing error")
    rescue => e # =StandardError
      # to allow global 500 error-helper rescue we should re-raise:
      raise $!, e.message, $!.backtrace
    end

    ##
    # this check should be a level higher
    ##
    pass_json["passTypeIdentifier"] = settings.pass_type_identifier if pass_json["passTypeIdentifier"] == "---"
    pass_json["teamIdentifier"] = settings.team_identifier if pass_json["teamIdentifier"] == "---"
    # this one already should be the same as pass[:serial_number]
    # because create_pkpass creating new pass (in json and pass tables)
    pass_json["serialNumber"] = serial_number
    pass_json["authenticationToken"] = pass_auth_token
    pass_json["webServiceURL"] = "http://#{settings.hostname}:#{settings.port}/" if pass_json["webServiceURL"] == "---"

    ##
    # here should be some Hashie for Redeem State
    ##
    # this fields are specific
    # they should be updated in separate biz routine - Redeem State + Biz Rules Editor
    # !!!
    pass_json["barcode"]["message"] = barcode_string_for_pass(pass_json)
    #pass_json["storeCard"]["primaryFields"][0]["value"] = user[:account_balance]
    #pass_json["storeCard"]["secondaryFields"][0]["value"] = user[:name]
    pass_json["storeCard"]["primaryFields"][0]["value"] = 1000000
    pass_json["storeCard"]["secondaryFields"][0]["value"] = 'Test User'
    #********************************************************

    # Write out the updated JSON
    ############################
    # => to DB (NOT a good idea for SQLite...)
    # **************************
    File.open(json_file_path, "w") do |f|
      f.write JSON.pretty_generate(pass_json)
    end

    # Prepare for pass signing
    pass_folder_path = target_folder_path
    pass_signing_certificate_path = get_certificate_path
    wwdr_certificate_path = get_wwdr_certificate_path
    pass_output_path = passes_folder_path + "/#{pass_id}.pkpass"

    # Remove the old pass if it exists
    if File.exists?(pass_output_path)
      File.delete(pass_output_path)
    end

    # Generate and sign the new pass
    ############################
    # => to DB (NOT a good idea for SQLite...)
    # **************************
    pass_signer = SignPass.new(pass_folder_path, pass_signing_certificate_path, settings.certificate_password, wwdr_certificate_path, pass_output_path)
    pass_signer.sign_pass!

    # a full path to created pkpass
    pass_output_path
  end

  def push_update_for_pass(pass_id)
    APNS.certificate_password = settings.certificate_password
    APNS.instance.open_connection("production")
    puts "Opening connection to APNS."
    # Get the list of registered devices and send a push notification
    pass = self.passes.where(:id => pass_id).first
    push_tokens = self.registrations.where(:serial_number => pass[:serial_number]).collect{|r| r[:push_token]}.uniq
    push_tokens.each do |push_token|
      puts "Sending a notification to #{push_token}"
      APNS.instance.deliver(push_token, "{}")
    end

    APNS.instance.close_connection
    puts "APNS connection closed."
  end

  def barcode_string_for_pass(pass)
    barcode_string = {
      "pass_type_id" => pass[:pass_type_id],
      "serial_number" => pass[:serial_number],
      "authentication_token" => pass[:authentication_token]
    }
    barcode_string.to_json
  end

  def barcode_string_for_json(json)
    barcode_string = {
      "pass_type_id" => json[:pass_type_id],
      "serial_number" => json[:serial_number],
      "authentication_token" => json[:authentication_token]
    }
    barcode_string.to_json
  end

  def new_serial_number
    return SecureRandom.hex
  end

  def new_authentication_token
    return SecureRandom.hex
  end

  def get_certificate_path
    certDirectory = File.dirname(File.expand_path(__FILE__)) + "/data/Certificate"
    certs = Dir.glob("#{certDirectory}/*.p12")
    if  certs.count == 0
      puts "Couldn't find a certificate at #{certDirectory}"
      puts "Exiting"
      Process.exit
    else
      certificate_path = certs[0]
    end
  end

  def get_wwdr_certificate_path
      certDirectory = File.dirname(File.expand_path(__FILE__)) + "/data/Certificate"
      certs = Dir.glob("#{certDirectory}/*.pem")
      if  certs.count == 0
        puts "Couldn't find a certificate at #{certDirectory}"
        puts "Exiting"
        Process.exit
      else
        certificate_path = certs[0]
      end
  end

  # Convenience method for parsing the authorization token header
  def authentication_token
    if env && env['HTTP_AUTHORIZATION']
      env['HTTP_AUTHORIZATION'].split(" ").last
    end
  end

  # Convenience method for parsing the pushToken out of a JSON POST body
  def push_token
    if request && request.body
      request.body.rewind
      json_body = JSON.parse(request.body.read)
      if json_body['pushToken']
        json_body['pushToken']
      end
    end
  end

  ##########################
  # Generating new device_id for newly registered device, for given user
  def new_device_id #(user_id)
    new_device_id = SecureRandom.hex

    # update user with newly generated device_id
    # ONLY FOR DEVELOPMENT
    #if add_device_id_for_user(user_id, new_device_id)
    #  new_device_id
    #else
    #  raise "Can\'t add new_device_id for user with id: #{user_id}"
    #end
  end

  def add_device_id_for_user(user_id, device_id)
    begin
      # update user with newly generated device_id
      user = self.users.where(:user_id => user_id)
      user.update(:device_id => device_id)
    rescue => e # =StandardError
      # we just ingest all errors
      puts "Exception in add_device_id_for_user #{$!}"
      err = true
    else
      err = false
    end
  end
  ##########################

end
