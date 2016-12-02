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
  local port = tonumber(params.port)
  if shared.bind_map[port] then
    return resp:reply(200, "OK", "bind already.")
  end

  local peer = nil
  for k,v in pairs(shared.peer_map) do
    if k:find(params.clientkey) == 1 then
      peer = v
      break
    end
  end
  if not peer then
    return resp:reply(200, "OK", "NAT not completed.")
  end

  local t
  t = {
    port = port,
    peer = peer,
    remote_host = params.remote_host,
    remote_port = params.remote_port,

    serv = tcpd.bind{
      port = port,
      onaccept = function(apt)
        local d = {
          input_queue = {},
          apt = apt,
          bind_port = port,
          peer = peer,
          host = peer.host,
          port = peer.port,
          forward_index = nil,
          auto_index = 0,
          connected = true,
        }

        connkey_index = connkey_index + 1
        d.connkey = connkey_index
        peer.ppclient_connection_map[d.connkey] = d

        local nat = service.get("nat")

        nat.send(peer.apt, {
            type = "ppconnect",
            connkey = d.connkey,
            host = params.remote_host,
            port = params.remote_port
          })

        apt:bind{
          onread = function(buf)
            table.insert(d.input_queue, buf)
            nat.sync_port()
          end,
          ondisconnected = function(msg)
            if config.debug then
              print("client disconnected", msg)
            end

            d.connected = nil
            d.apt = nil
            d.need_send_disconnect = true
            d = nil
          end
        }
      end
    }
  }

  if t.serv then
    shared.bind_map[port] = t
    return resp:reply(200, "OK", "submitted.")
  else
    return resp:reply(200, "OK", string.format("can't not bind to %d.", port))
  end

end

return {
  route = "/bind",
  onPost = onPost,
}
