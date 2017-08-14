local fan = require "fan"
local utils = require "fan.utils"

local config = require "config"
local shared = require "shared"
local service = require "service"

local json = require "cjson"

local nat = service.get("nat")

local function _bind(params, resp)
    local st, msg = nat.bind(params)
    return resp:reply(200, "OK", msg)
end

local function _unbind(params, resp)
    local st, msg = nat.unbind(params)
    return resp:reply(200, "OK", msg)
end

local action_map = {
    ["bind"] = _bind,
    ["unbind"] = _unbind
}

local function onPost(req, resp)
    local params = json.decode(req.body)
    local action = params.action

    local f = action_map[action]
    if f then
        return f(params, resp)
    else
        return resp:reply(400, "Bad")
    end
end

return {
    route = "/bind",
    onPost = onPost
}
