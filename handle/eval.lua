local fan = require "fan"
local utils = require "fan.utils"

local config = require "config"
local shared = require "shared"
local service = require "service"

local json = require "cjson"

local print = print
local string = string
local ipairs = ipairs
local pairs = pairs
local assert = assert
local collectgarbage = collectgarbage

local connkey_index = 0

local function onPost(req, resp)
  local script = req.body
  local f,msg = loadstring(script)
  if not f then
    resp:reply(400, "Exception", msg)
  else
    local st,msg = pcall(f, resp)
    if not st then
      return resp:reply(500, "Error", msg)
    else
      return resp:reply(200, "OK")
    end
  end
end

return {
  route = "/eval",
  onPost = onPost,
}
