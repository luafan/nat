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
    local params = json.decode(req.body)
    for k, v in pairs(params) do
        config[k] = v
    end
    return resp:reply(200, "OK")
end

return {
    route = "/setting",
    onPost = onPost
}
