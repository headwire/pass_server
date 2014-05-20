# Pass Resource
##
# Pass object will become HTP Resource with data_mapper support
##
require "data_mapper"

class PassJson
  include DataMapper::Resource

  storage_names[:default] = "passes_json"

  property :id, Serial, :key => true	# An auto-increment integer key
  property :serial, String # A varchar type string, for short strings
  property :url, String, :length => 100	# Do we need more for URL ???
  property :json_data, Text # A text block, for longer string data.
  property :created_at, DateTime
  property :updated_at, DateTime

end
