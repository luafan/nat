-- name = "test"
status = "n/a"

local require = require
local setmetatable = setmetatable
local table = table
local string = string
local pairs = pairs
local ipairs = ipairs
local coroutine = coroutine

local fan = require "fan"
local config = require "config"
local connector = require "fan.connector"
local objectbuf = require "fan.objectbuf"
local utils = require "fan.utils"
local upnp = require "fan.upnp"

local cjson = require "cjson"
require "compat53"

local shared = require "shared"

local sym = objectbuf.symbol(require "nat_dic")

shared.peer_map = {}
shared.bind_map = {}
shared.allowed_map = {}

local sync_port_running = nil

local command_map = {}

local clientkey = string.format("%s-%s", config.name, utils.random_string(utils.LETTERS_W, 8))

local function _sync_port()
  if sync_port_running then
    coroutine.resume(sync_port_running)
  end
end

local function _get_peer(apt)
  for k,v in pairs(shared.peer_map) do
    if v.apt == apt then
      return v
    end
  end
end

local function _send(apt, msg)
  msg.clientkey = clientkey
  if config.debug then
    print(apt.host, apt.port, "send", cjson.encode(msg))
  end
  return apt:send(objectbuf.encode(msg, sym))
end

local function send_any(apt, msg, ...)
  msg.clientkey = clientkey
  if config.debug then
    print("send", cjson.encode(msg))
  end
  return apt:send(objectbuf.encode(msg, sym), ...)
end

function command_map.list(apt, host, port, msg)
  if not shared.internal_port then
    shared.internal_port = shared.bindserv.serv:getPort()
    local obj = upnp.new(1)
    obj:AddPortMapping(shared.internal_host, string.format("%d", shared.internal_port), string.format("%d", shared.internal_port), "udp")
  end

  for i,v in ipairs(msg.data) do
    local t = shared.allowed_map[v.host]
    if not t then
      t = {}
      shared.allowed_map[v.host] = t
    end
    t[v.port] = utils.gettime()

    if v.internal_host and v.internal_port then
      local t = shared.allowed_map[v.internal_host]
      if not t then
        t = {}
        shared.allowed_map[v.internal_host] = t
      end
      t[v.internal_port] = utils.gettime()
    end
  end

  for i,v in ipairs(msg.data) do
    if config.debug then
      print("list", i, cjson.encode(v))
    end
    local peer = shared.peer_map[v.clientkey]
    if peer then
      local output_index = _send(peer.apt, {type = "ppkeepalive"})
      peer.apt.ppkeepalive_map[output_index] = true
    else
      local apt = shared.bindserv.getapt(v.host, v.port)
      local output_index = send_any(apt, {type = "ppkeepalive"}, v.host, v.port)
      apt.ppkeepalive_map[output_index] = true

      if v.internal_host and v.internal_port then
        local apt = shared.bindserv.getapt(v.internal_host, v.internal_port)
        local output_index = send_any(apt, {type = "ppkeepalive"}, v.internal_host, v.internal_port)
        apt.ppkeepalive_map[output_index] = true
      end

      if v.data then
        for i,v in ipairs(v.data) do
          if v.host and v.port then
            local apt = shared.bindserv.getapt(v.host, v.port)
            local output_index = send_any(apt, {type = "ppkeepalive"}, v.host, v.port)
            apt.ppkeepalive_map[output_index] = true
          end
        end
      end
    end
    -- if not peer then
    -- print("send ppkeepalive", v.host, v.port)
    -- else
    -- print("ignore nat", v.clientkey, peer)
    -- end
  end
end

function command_map.ppconnect(apt, host, port, msg)
  local peer = shared.peer_map[msg.clientkey]
  local obj

  if config.debug then
    print(host, port, cjson.encode(msg))
  end

  obj = {
    connkey = msg.connkey,
    host = host,
    port = port,
    forward_index = nil,
    auto_index = 0,
    input_queue = {},
    conn = tcpd.connect{
      host = msg.host,
      port = msg.port,
      onconnected = function()
        if config.debug then
          print("onconnected")
        end
        obj.connected = true
        _send(apt, {type = "ppconnected", connkey = msg.connkey})
      end,
      onread = function(buf)
        table.insert(obj.input_queue, buf)
        _sync_port()
      end,
      ondisconnected = function(msgstr)
        obj.connected = nil
        obj.conn = nil
        if config.debug then
          print("remote disconnected", msgstr)
        end
        obj.need_send_disconnect = true
        -- _send(apt, {type = "ppdisconnectedmaster", connkey = msg.connkey})
      end
    }
  }

  peer.ppservice_connection_map[msg.connkey] = obj
end

function command_map.ppconnected(apt, host, port, msg)
  if config.debug then
    print(host, port, cjson.encode(msg))
  end
  local peer = _get_peer(apt)
  local obj = peer.ppclient_connection_map[msg.connkey]
  obj.connected = true

  _sync_port()
end

function command_map.ppdisconnectedmaster(apt, host, port, msg)
  if config.debug then
    print(host, port, cjson.encode(msg))
  end
  local peer = _get_peer(apt)
  local obj = peer.ppclient_connection_map[msg.connkey]
  peer.ppclient_connection_map[msg.connkey] = nil
  -- clean up client apt.
  if obj then
    obj.connected = nil
    if obj.apt then
      obj.apt:close()
      obj.apt = nil
    end
  end
end

function command_map.ppdisconnectedclient(apt, host, port, msg)
  if config.debug then
    print(host, port, cjson.encode(msg))
  end
  local peer = _get_peer(apt)
  local obj = peer.ppservice_connection_map[msg.connkey]
  -- clean up server conn.
  if obj then
    obj.connected = nil
    peer.ppservice_connection_map[msg.connkey] = nil
    if obj.conn then
      obj.conn:close()
      obj.conn = nil
    end
  end
end

function command_map.ppdata_req(apt, host, port, msg)
  local peer = _get_peer(apt)
  local obj = peer.ppservice_connection_map[msg.connkey]
  if obj then
    obj.conn:send(msg.data)
  end

  -- msg.data = nil
  -- print(os.date("%X"), host, port, cjson.encode(msg))
end

function command_map.ppdata_resp(apt, host, port, msg)
  local peer = _get_peer(apt)
  local obj = peer.ppclient_connection_map[msg.connkey]
  if obj and obj.connected then
    obj.apt:send(msg.data)
  end

  -- local len = #(msg.data)
  -- msg.data = nil
  -- print(os.date("%X"), host, port, cjson.encode(msg), len)
end

local function ppkeepalive(apt, host, port, msg)
  local peer = shared.peer_map[msg.clientkey]
  if not peer then
    peer = {
      apt = apt,
      host = host,
      port = port,
      clientkey = msg.clientkey,
      ppservice_connection_map = {},
      ppclient_connection_map = {},
    }

    shared.peer_map[msg.clientkey] = peer
  else
    peer.host = host
    peer.port = port
  end
end

local function list_peers(bindserv)
  while not bindserv.stop do
    local data = {}
    for clientkey,peer in pairs(shared.peer_map) do
      data[clientkey] = {
        host = peer.apt.host,
        port = peer.apt.port,
      }
    end

    send_any(shared.remote_serv, {
        type = "list",
        internal_host = shared.internal_host,
        internal_port = shared.internal_port,
        internal_netmask = shared.internal_netmask,
        data = data,
      }, config.remote_host, config.remote_port)
    -- send{type = "keepalive"}
    fan.sleep(3)
  end
end

local function keepalive_peers(bindserv)
  while not bindserv.stop do
    _sync_port()
    for k,peer in pairs(shared.peer_map) do
      if utils.gettime() - peer.apt.last_keepalive > config.keepalive_delay then
        local output_index = _send(peer.apt, {type = "ppkeepalive"})
        peer.apt.ppkeepalive_map[output_index] = true
      end
    end

    local live_peers = {}
    for k,peer in pairs(shared.peer_map) do
      if utils.gettime() - peer.apt.last_keepalive > config.peer_timeout then
        peer.apt:cleanup()
        if config.debug then
          print(k, "keepalive timeout.")
        end
        for connkey,obj in pairs(peer.ppclient_connection_map) do
          obj.apt:close()
          obj.apt = nil
        end

        shared.peer_map[k] = nil

        for k,apt in pairs(shared.bindserv.clientmap) do
          if apt == peer.apt then
            shared.bindserv.clientmap[k] = nil
            break
          end
        end
      else
        live_peers[peer] = k
      end
    end

    for port,t in pairs(shared.bind_map) do
      if not live_peers[t.peer] then
        if t.serv then
          t.serv:close()
          t.serv = nil
        end
        shared.bind_map[port] = nil
      end
    end

    for key,apt in pairs(bindserv.clientmap) do
      if utils.gettime() - apt.last_keepalive > 20 and apt ~= shared.remote_serv then
        apt:cleanup(apt.host, apt.port)
        if config.debug then
          print(key, "keepalive timeout.")
        end
      end
    end

    fan.sleep(5)
  end
end

local function sync_port_buffers(bindserv)
  while not bindserv.stop do
    local count = 0
    for ckey,peer in pairs(shared.peer_map) do
      for connkey,obj in pairs(peer.ppservice_connection_map) do
        if #(obj.input_queue) > 0 then
          if not obj.forward_index then
            local data = table.remove(obj.input_queue, 1)
            -- obj.input_queue = {}
            local auto_index = obj.auto_index + 1
            obj.auto_index = auto_index
            obj.forward_index = _send(peer.apt, {
                type = "ppdata_resp",
                connkey = connkey,
                data = data,
                index = auto_index
              })
            if config.debug then
              print("forwarding to client", obj.forward_index, auto_index)
            end
            peer.apt.index_conn_map[obj.forward_index] = obj
            count = count + 1
          end
        elseif obj.need_send_disconnect then
          obj.need_send_disconnect = nil
          peer.ppservice_connection_map[connkey] = nil
          _send(peer.apt, {type = "ppdisconnectedmaster", connkey = connkey})
        end
      end
    end

    for k,peer in pairs(shared.peer_map) do
      for connkey,obj in pairs(peer.ppclient_connection_map) do
        -- print(obj, obj.connected, obj.forward_index, #(obj.input_queue))
        if #(obj.input_queue) > 0 then
          if not obj.forward_index then
            local data = table.remove(obj.input_queue, 1)
            -- obj.input_queue = {}
            local auto_index = obj.auto_index + 1
            obj.auto_index = auto_index
            obj.forward_index = _send(peer.apt, {
                type = "ppdata_req",
                connkey = connkey,
                data = data,
                index = auto_index
              })
            if config.debug then
              print("forwarding to server", obj.forward_index, auto_index)
            end
            peer.apt.index_conn_map[obj.forward_index] = obj
            count = count + 1
          end
        elseif obj.need_send_disconnect then
          obj.need_send_disconnect = nil
          peer.ppclient_connection_map[connkey] = nil
          _send(peer.apt, {type = "ppdisconnectedclient", connkey = connkey})
        end
      end
    end

    sync_port_running = coroutine.running()
    coroutine.yield()
    sync_port_running = nil
  end
end

local function allowed_map_cleanup(bindserv)
  while not bindserv.stop do
    for host,t in pairs(shared.allowed_map) do
      for port,last_alive in pairs(t) do
        if utils.gettime() - last_alive > 30 then
          t[port] = nil
        end
      end
      if not next(t) then
        shared.allowed_map[host] = nil
      end
    end
    fan.sleep(1)
  end
end

local function bind_apt(apt)
  apt.ppkeepalive_map = {}
  apt.index_conn_map = {}
  setmetatable(apt.index_conn_map, {__mode = "v"})

  apt.last_keepalive = utils.gettime()

  apt.onread = function(body, host, port)
    local msg = objectbuf.decode(body, sym)
    if not msg then
      print("decode failed", host, port, #(body))
    end

    local t = shared.allowed_map[host]
    if not t then
      t = {}
      shared.allowed_map[host] = t
    end
    t[port] = utils.gettime()

    if config.debug then
      print(os.date("%X"), host, port, cjson.encode(msg))
    end

    apt.last_keepalive = utils.gettime()
    if msg.clientkey then
      ppkeepalive(apt, host, port, msg)
    end

    local command = command_map[msg.type]
    if command then
      command(apt, host, port, msg)
    end
  end

  apt.onsent = function(index)
    -- print("onsent", apt)
    apt.last_keepalive = utils.gettime()
    local obj = apt.index_conn_map[index]

    if obj then
      obj.forward_index = nil
      _sync_port()
    elseif apt.ppkeepalive_map[index] then
      apt.ppkeepalive_map[index] = nil
    end
  end

  apt.ontimeout = function(package, host, port)
    if host and port then
      local alive = shared.allowed_map[host] and shared.allowed_map[host][port]
      if not alive then
        if config.debug then
          print("timeout, drop", #(package), host, port)
        end
        return false
      else
        local output_index = string.unpack("<I2", package)
        if apt.ppkeepalive_map[output_index] then
          apt.ppkeepalive_map[output_index] = nil
          if config.debug then
            print("drop ppkeepalive")
          end
          return false
        end
      end
    else
      return true
    end

    return true
  end
end

function onStart()
  if not config.client_enabled then
    return
  end
  status = "running"

  for i,v in ipairs(fan.getinterfaces()) do
    if v.type == "inet" then
      print(cjson.encode(v))
      if v.name == "wlp3s0" or v.name == "en0" or v.name == "eth0" then
        shared.internal_host = v.host
        shared.internal_netmask = v.netmask
      end
    end
  end

  shared.bindserv = connector.bind("udp://0.0.0.0:0")
  shared.remote_serv = shared.bindserv.getapt(config.remote_host, config.remote_port)
  bind_apt(shared.remote_serv)

  shared.bindserv.onaccept = function(apt)
    bind_apt(apt)
  end

  coroutine.wrap(list_peers)(shared.bindserv)
  coroutine.wrap(keepalive_peers)(shared.bindserv)
  coroutine.wrap(sync_port_buffers)(shared.bindserv)
  coroutine.wrap(allowed_map_cleanup)(shared.bindserv)
end

function onStop()
  if shared.bindserv then
    shared.bindserv.stop = true
    shared.bindserv.close()
    shared.bindserv = nil
  end

  status = "stopped"
end

function getStatus()
  return string.format("%s", status)
end

function send(...)
  return _send(...)
end

function sync_port()
  _sync_port()
end

function get_peer(...)
  return _get_peer(...)
end
