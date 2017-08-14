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

local MAX_OUTGOING_INPUT_COUNT = config.max_outgoing_input_count or 10

local MAX_INPUT_QUEUE_SIZE = config.max_input_queue_size or 1000

local sync_port_running = nil

local command_map = {}

local clientkey = string.format("%s-%s", config.name, utils.random_string(utils.LETTERS_W, 8))

local function _sync_port()
  if sync_port_running then
    assert(coroutine.resume(sync_port_running))
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
    local clientkey = v.clientkey
    local peer = shared.peer_map[clientkey]
    if peer then
      local output_index = _send(peer.apt, {type = "ppkeepalive"})
      peer.apt.ppkeepalive_map[output_index] = true
    else
      local apt = shared.bindserv.getapt(v.host, v.port, nil, string.format("%s:%d", v.host, v.port))
      apt.peer_key = clientkey
      local output_index = _send(apt, {type = "ppkeepalive"})
      apt.ppkeepalive_map[output_index] = true

      if v.internal_host and v.internal_port then
        local apt = shared.bindserv.getapt(v.internal_host, v.internal_port, nil, string.format("%s:%d", v.internal_host, v.internal_port))
        apt.peer_key = clientkey
        local output_index = _send(apt, {type = "ppkeepalive"})
        apt.ppkeepalive_map[output_index] = true
      end

      if v.data then
        for i,v in ipairs(v.data) do
          if v.host and v.port then
            local apt = shared.bindserv.getapt(v.host, v.port, nil, string.format("%s:%d", v.host, v.port))
            apt.peer_key = clientkey
            local output_index = _send(apt, {type = "ppkeepalive"})
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
  if config.debug then
    print(host, port, cjson.encode(msg))
  end

  local connkey = msg.connkey
  local clientkey = msg.clientkey

  local connection_map = shared.peer_map[clientkey].ppservice_connection_map

  if connection_map[connkey] then
    return
  end

  local obj = {
    connkey = connkey,
    host = host,
    port = port,
    incoming_cache = {},
    incoming_index = nil,
    incoming_count = 0,
    outgoing_cache = {},
    outgoing_count = 0,
    auto_index = 1,
    input_queue = {},
  }

  connection_map[connkey] = obj

  local weak_obj = utils.weakify_object(obj)

  obj.conn = tcpd.connect{
    host = msg.host,
    port = msg.port,
    onconnected = function()
      local obj = weak_obj
      if config.debug then
        print("onconnected")
      end
      obj.connected = true
      _send(apt, {type = "ppconnected", connkey = connkey})
    end,
    onread = function(buf)
      local obj = weak_obj
      table.insert(obj.input_queue, buf)

      if #(obj.input_queue) > MAX_INPUT_QUEUE_SIZE then
        obj.conn:pause_read()
        obj.pause_read = obj.conn
      end
      _sync_port()
    end,
    onsendready = function()
      local obj = weak_obj
      obj.sending = false
      if obj.need_close_service then
        pp_close_service(clientkey, connkey)
      end
    end,
    ondisconnected = function(msgstr)
      local obj = weak_obj
      obj.connected = nil
      obj.conn = nil
      if config.debug then
        print("remote disconnected", msgstr)
      end
      obj.need_send_disconnect = true
      -- _send(apt, {type = "ppdisconnectedmaster", connkey = msg.connkey})
    end
  }

  config.weaktable[string.format("ppconnect_%d", connkey)] = obj.conn
end

function command_map.ppconnected(apt, host, port, msg)
  if config.debug then
    print(host, port, cjson.encode(msg))
  end
  local peer = _get_peer(apt)
  local obj = peer.ppclient_connection_map[msg.connkey]
  if obj then
    obj.connected = true
  end

  _sync_port()
end

local function pp_close_client(obj, connkey)
  obj.peer.ppclient_connection_map[connkey] = nil
  if obj.apt then
    obj.apt:close()
    obj.apt = nil
  end
end

function command_map.ppdisconnectedmaster(apt, host, port, msg)
  if config.debug then
    print(host, port, cjson.encode(msg))
  end
  local peer = _get_peer(apt)
  local obj = peer.ppclient_connection_map[msg.connkey]
  -- clean up client apt.
  if obj then
    obj.connected = nil
    obj.need_close_client = true
    if not obj.sending then
      pp_close_client(obj, msg.connkey)
    end
  end
end

local function pp_close_service(clientkey, connkey)
  local connection_map = shared.peer_map[clientkey].ppservice_connection_map
  local obj = connection_map[connkey]
  connection_map[connkey] = nil

  if obj and obj.conn then
    obj.conn:close()
    obj.conn = nil
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
    obj.need_close_service = true
    if not obj.sending then
      pp_close_service(msg.clientkey, msg.connkey)
    end
  end
end

function command_map.ppdata_req(apt, host, port, msg)
  local peer = _get_peer(apt)
  local obj = peer.ppservice_connection_map[msg.connkey]
  if obj then
    obj.incoming_cache[msg.index] = msg.data
    obj.incoming_count = obj.incoming_count + 1
  end

  _sync_port()
  -- msg.data = nil
  -- print(os.date("%X"), host, port, cjson.encode(msg))
end

function command_map.ppdata_resp(apt, host, port, msg)
  local peer = _get_peer(apt)
  local obj = peer.ppclient_connection_map[msg.connkey]
  if obj and obj.connected then
    obj.incoming_cache[msg.index] = msg.data
    obj.incoming_count = obj.incoming_count + 1
  end

  _sync_port()
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

    _send(shared.remote_serv, {
        type = "list",
        internal_host = shared.internal_host,
        internal_port = shared.internal_port,
        internal_netmask = shared.internal_netmask,
        data = data,
      })
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
        if peer.apt then
          peer.apt:cleanup()
        end
        if config.debug then
          print(utils.gettime(), k, "keepalive timeout.")
        end
        for connkey,obj in pairs(peer.ppclient_connection_map) do
          if obj.apt then
            obj.apt:close()
            obj.apt = nil
          end
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
        t:unbind()
      end
    end

    for key,apt in pairs(bindserv.clientmap) do
      local need_cleanup = false
      if apt.peer_key then
        local peer = shared.peer_map[apt.peer_key]
        if peer and peer.apt ~= apt then
          need_cleanup = true
        end
      end

      if not need_cleanup and utils.gettime() - apt.last_keepalive > config.peer_timeout and apt ~= shared.remote_serv then
        need_cleanup = true
      end
      
      if need_cleanup then
        apt:cleanup()
        if config.debug then
          print(utils.gettime(), key, "keepalive timeout.")
        end
      end
    end

    fan.sleep(5)
  end
end

local function _flush_connection_map(peer, conn_key, map_key, flush_type, disconnect_type)
  for connkey,obj in pairs(peer[map_key]) do
    if obj.incoming_count > 0 then
      local found
      repeat
        found = false
        for k,v in pairs(obj.incoming_cache) do
          if not obj.incoming_index
          or k == (obj.incoming_index < config.auto_index_max and obj.incoming_index + 1 or 1) then
            obj.incoming_index = k
            obj.incoming_cache[k] = nil
            obj.incoming_count = obj.incoming_count - 1
            if obj[conn_key] then
              obj[conn_key]:send(v)
              obj.sending = true
            end
            found = true
            break
          end
        end
      until obj.incoming_count == 0 or not found
    end

    if #(obj.input_queue) > 0 then
      if obj.outgoing_count < config.outgoing_count_max then
        -- local data = table.remove(obj.input_queue, 1)

        -- local data = table.concat(obj.input_queue)
        -- obj.input_queue = {}

        local data
        if #(obj.input_queue) > MAX_OUTGOING_INPUT_COUNT then
          local tmp = {}
          data = table.concat(obj.input_queue, nil, 1, MAX_OUTGOING_INPUT_COUNT)
          table.move(obj.input_queue, MAX_OUTGOING_INPUT_COUNT + 1, #(obj.input_queue), 1, tmp)
          obj.input_queue = tmp
        else
          data = table.concat(obj.input_queue)
          obj.input_queue = {}
        end

        local auto_index = obj.auto_index
        obj.auto_index = auto_index < config.auto_index_max and auto_index + 1 or 1
        local forward_index = _send(peer.apt, {
            type = flush_type,
            connkey = connkey,
            data = data,
            index = auto_index
          })

        obj.outgoing_cache[forward_index] = true
        obj.outgoing_count = obj.outgoing_count + 1

        if config.debug then
          print(map_key, "forward", forward_index, auto_index)
        end
        peer.apt.index_conn_map[forward_index] = obj
      end
    elseif obj.need_send_disconnect and obj.outgoing_count == 0 then
      obj.need_send_disconnect = nil
      peer[map_key][connkey] = nil
      _send(peer.apt, {type = disconnect_type, connkey = connkey})
    end
  end
end

local function sync_port_buffers(bindserv)
  while not bindserv.stop do
    for ckey,peer in pairs(shared.peer_map) do
      _flush_connection_map(peer, "conn", "ppservice_connection_map", "ppdata_resp", "ppdisconnectedmaster")
      _flush_connection_map(peer, "apt", "ppclient_connection_map", "ppdata_req", "ppdisconnectedclient")
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
        if utils.gettime() - last_alive > config.peer_timeout then
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

  config.weaktable[string.format("bind_apt_%s:%d", apt.host, apt.port)] = apt

  apt.last_keepalive = utils.gettime()

  local host = apt.host
  local port = apt.port

  apt.onread = function(body)
    local msg = objectbuf.decode(body, sym)
    if not msg then
      print("decode failed.", host, port, #(body))
      return
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
      obj.outgoing_count = obj.outgoing_count - 1
      obj.outgoing_cache[index] = nil
      apt.index_conn_map[index] = nil

      if obj.pause_read and #(obj.input_queue) < MAX_INPUT_QUEUE_SIZE/2 then
        obj.pause_read:resume_read()
        obj.pause_read = nil
      end

      _sync_port()
    elseif apt.ppkeepalive_map[index] then
      apt.ppkeepalive_map[index] = nil
    end
  end

  apt.ontimeout = function(package)
    local alive = shared.allowed_map[host] and shared.allowed_map[host][port]
    if not alive then
      if config.debug then
        print("timeout, drop", #(package), host, port)
      end
      return false
    else
      local output_index = string.unpack("<I4", package)
      if apt.ppkeepalive_map[output_index] then
        apt.ppkeepalive_map[output_index] = nil
        if config.debug then
          print("drop ppkeepalive")
        end
        return false
      end
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
  shared.remote_serv = shared.bindserv.getapt(config.remote_host, config.remote_port,
    nil, string.format("%s:%d", config.remote_host, config.remote_port))

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

local bind_service_mt = {}
bind_service_mt.__index = bind_service_mt

local connkey_index = 1

function bind_service_mt:bind()
  if self.serv then
    return
  end

  local port = self.port
  local peer = self.peer

  self.serv = tcpd.bind{
    port = port,
    onaccept = function(apt)
      local connkey = connkey_index
      connkey_index = connkey_index + 1

      local obj = {
        connkey = connkey,
        input_queue = {},
        incoming_cache = {},
        incoming_index = nil,
        incoming_count = 0,
        outgoing_cache = {},
        outgoing_count = 0,
        apt = apt,
        bind_port = port,
        peer = peer,
        host = peer.host,
        port = peer.port,
        auto_index = 1,
        connected = true,
      }

      peer.ppclient_connection_map[connkey] = obj

      local weak_obj = utils.weakify_object(obj)

      _send(peer.apt, {
          type = "ppconnect",
          connkey = connkey,
          host = self.remote_host,
          port = self.remote_port
        })

      apt:bind{
        onread = function(buf)
          local obj = weak_obj
          table.insert(obj.input_queue, buf)

          if #(obj.input_queue) > MAX_INPUT_QUEUE_SIZE then
            obj.apt:pause_read()
            obj.pause_read = obj.apt
          end

          _sync_port()
        end,
        onsendready = function()
          local obj = weak_obj
          obj.sending = false
          if obj.need_close_client then
            pp_close_client(obj, connkey)
          end
        end,
        ondisconnected = function(msg)
          if config.debug then
            print("client disconnected", msg)
          end

          local obj = weak_obj
          obj.connected = nil
          obj.apt = nil
          obj.need_send_disconnect = true
        end
      }

      config.weaktable[string.format("conn_apt_%d", connkey)] = apt
      config.weaktable[string.format("conn_obj_%d", connkey)] = obj
    end
  }

  if self.serv then
    config.weaktable[string.format("bind_%d", port)] = self.serv
    shared.bind_map[port] = self
    return true, "submitted."
  else
    return false, string.format("can't not bind to %d.", port)
  end
end

function bind_service_mt:unbind()
  if self.serv then
    shared.bind_map[self.port] = nil
    self.serv:close()
    self.serv = nil

    return true, "unbinded."
  else
    return false, "invaild."
  end
end

function unbind(params)
  local port = tonumber(params.port)
  if shared.bind_map[port] then
    return shared.bind_map[port]:unbind()
  else
    return false, "not bind."
  end
end

function bind(params)
  local port = tonumber(params.port)
  if shared.bind_map[port] then
    return false, "bind already."
  end

  local list = {}
  for k,v in pairs(shared.peer_map) do
    if k:find(params.clientkey) == 1 then
      table.insert(list, v)
    end
  end
  
  if #(list) == 0 then
    return false, "NAT not completed."
  end

  table.sort(list, function(a, b)
    return a.apt.last_keepalive > b.apt.last_keepalive
  end)

  local peer = list[1]

  local t
  t = {
    port = port,
    peer = peer,
    remote_host = params.remote_host,
    remote_port = params.remote_port,
  }

  setmetatable(t, bind_service_mt)

  return t:bind()
end

function getStatus()
  return string.format("%s", status)
end

function get_peer(...)
  return _get_peer(...)
end
