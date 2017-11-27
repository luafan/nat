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
local tcpd = require "fan.tcpd"
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
shared.weak_apt_peer_map = {}
setmetatable(shared.weak_apt_peer_map, {__mode = "kv"})
shared.bind_map = {}

local allowed_map = {}
shared.allowed_map = allowed_map

shared.allowed_map_touch = function(host, port)
    local t = allowed_map[host]
    if not t then
        t = {}
        allowed_map[host] = t
    end
    t[port] = utils.gettime()
end

shared.allowed_map_test = function(host, port)
    return allowed_map[host] and allowed_map[host][port]
end

shared.allowed_map_shrink = function()
    for host, t in pairs(allowed_map) do
        for port, last_alive in pairs(t) do
            if utils.gettime() - last_alive > config.peer_timeout then
                t[port] = nil
            end
        end
        if not next(t) then
            allowed_map[host] = nil
        end
    end
end

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

function command_map.list(apt, host, port, msg)
    if not shared.internal_port then
        shared.internal_port = shared.bindserv.serv:getPort()
        local obj = upnp.new(1)
        obj:AddPortMapping(
            shared.internal_host,
            string.format("%d", shared.internal_port),
            string.format("%d", shared.internal_port),
            "udp"
        )
    end

    for i, v in ipairs(msg.data) do
        shared.allowed_map_touch(v.host, v.port)

        if v.internal_host and v.internal_port then
            shared.allowed_map_touch(v.internal_host, v.internal_port)
        end
    end

    for i, v in ipairs(msg.data) do
        if config.debug then
            print("list", i, cjson.encode(v))
        end
        local clientkey = v.clientkey
        local peer = shared.peer_map[clientkey]
        if not peer or utils.gettime() - peer.apt.last_incoming_time > config.peer_timeout / 2 then
            local apt = shared.bindserv.getapt(v.host, v.port, nil, string.format("%s:%d", v.host, v.port))
            apt.peer_key = clientkey
            apt:send_keepalive()

            if v.internal_host and v.internal_port then
                local apt =
                    shared.bindserv.getapt(
                    v.internal_host,
                    v.internal_port,
                    nil,
                    string.format("%s:%d", v.internal_host, v.internal_port)
                )
                apt.peer_key = clientkey
                apt:send_keepalive()
            end

            if v.data then
                for i, v in ipairs(v.data) do
                    if v.host and v.port then
                        local apt = shared.bindserv.getapt(v.host, v.port, nil, string.format("%s:%d", v.host, v.port))
                        apt.peer_key = clientkey
                        apt:send_keepalive()
                    end
                end
            end
        end
    end
end

local function pp_close_service(peer, connkey)
    local connection_map = peer.ppservice_connection_map
    local obj = connection_map[connkey]
    connection_map[connkey] = nil

    if obj and obj.conn then
        obj.conn:close()
        obj.conn = nil
    end
end

local function pp_close_client(obj, connkey)
    obj.peer.ppclient_connection_map[connkey] = nil
    if obj.apt then
        obj.apt:close()
        obj.apt = nil
    end
end

function command_map.ppconnect(apt, host, port, msg)
    if config.debug then
        print(host, port, cjson.encode(msg))
    end

    local connkey = msg.connkey

    local connection_map = shared.weak_apt_peer_map[apt].ppservice_connection_map

    if connection_map[connkey] then
        return
    end

    local obj = {
        connkey = connkey,
        host = host,
        port = port,
        incoming_cache = {},
        incoming_index = 0,
        incoming_count = 0,
        outgoing_count = 0,
        auto_index = 1,
        input_queue = {}
    }

    connection_map[connkey] = obj

    local weak_obj = utils.weakify_object(obj)

    obj.conn =
        tcpd.connect {
        host = msg.host,
        port = msg.port,
        onconnected = function()
            local obj = weak_obj
            if config.debug then
                print("onconnected")
            end
            obj.connected = true
            apt:send_msg {type = "ppconnected", connkey = connkey}
        end,
        onread = function(buf)
            local obj = weak_obj
            
            if not obj.input_queue then
                return
            end
            
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
                pp_close_service(shared.weak_apt_peer_map[apt], connkey)
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
        end
    }

    config.weaktable[string.format("ppconnect_%d", connkey)] = obj.conn
end

function command_map.ppconnected(apt, host, port, msg)
    if config.debug then
        print(host, port, cjson.encode(msg))
    end
    local peer = shared.weak_apt_peer_map[apt]
    if peer then
        local obj = peer.ppclient_connection_map[msg.connkey]
        if obj then
            obj.connected = true
        end
    end

    _sync_port()
end

function command_map.ppdisconnectedmaster(apt, host, port, msg)
    if config.debug then
        print(host, port, cjson.encode(msg))
    end
    local peer = shared.weak_apt_peer_map[apt]
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

function command_map.ppdisconnectedclient(apt, host, port, msg)
    if config.debug then
        print(host, port, cjson.encode(msg))
    end
    local peer = shared.weak_apt_peer_map[apt]
    local obj = peer.ppservice_connection_map[msg.connkey]
    -- clean up server conn.
    if obj then
        obj.connected = nil
        obj.need_close_service = true
        if not obj.sending then
            pp_close_service(peer, msg.connkey)
        end
    end
end

function command_map.ppdata_req(apt, host, port, msg)
    local peer = shared.weak_apt_peer_map[apt]
    if peer then
        local obj = peer.ppservice_connection_map[msg.connkey]
        if obj and not obj.incoming_cache[msg.index] then
            obj.incoming_cache[msg.index] = msg.data
            obj.incoming_count = obj.incoming_count + 1
        end
    end

    _sync_port()
    -- msg.data = nil
    -- print(os.date("%X"), host, port, cjson.encode(msg))
end

function command_map.ppdata_resp(apt, host, port, msg)
    local peer = shared.weak_apt_peer_map[apt]
    local obj = peer.ppclient_connection_map[msg.connkey]
    if obj and obj.connected and not obj.incoming_cache[msg.index] then
        obj.incoming_cache[msg.index] = msg.data
        obj.incoming_count = obj.incoming_count + 1
    end

    _sync_port()
    -- local len = #(msg.data)
    -- msg.data = nil
    -- print(os.date("%X"), host, port, cjson.encode(msg), len)
end

local function create_or_update_peer(apt, host, port, msg)
    local peer = shared.peer_map[msg.clientkey]
    if not peer then
        peer = {
            apt = apt,
            host = host,
            port = port,
            created = utils.gettime(),
            clientkey = msg.clientkey,
            ppservice_connection_map = {},
            ppclient_connection_map = {}
        }

        shared.peer_map[msg.clientkey] = peer
        shared.weak_apt_peer_map[apt] = peer
    else
        peer.apt = apt
        peer.host = host
        peer.port = port
    end
end

local function list_peers(bindserv)
    while not bindserv.stop do
        local data = {}
        for clientkey, peer in pairs(shared.peer_map) do
            data[clientkey] = {
                host = peer.apt.host,
                port = peer.apt.port
            }
        end

        if shared.internal_port and fan.getinterfaces then
            for i, v in ipairs(fan.getinterfaces()) do
                if v.type == "inet" then
                    if v.host ~= "127.0.0.1" then
                        data[clientkey] = {
                            host = v.host,
                            port = shared.internal_port
                        }
                    end
                end
            end
        end

        shared.remote_serv:send_msg {
            type = "list",
            data = data
        }
        fan.sleep(3)
    end
end

local function keepalive_peers(bindserv)
    while not bindserv.stop do
        _sync_port()

        local live_peers = {}
        for k, peer in pairs(shared.peer_map) do
            -- cleanup timeout peer
            if utils.gettime() - peer.apt.last_incoming_time > config.peer_timeout then
                peer.apt:cleanup()
                -- if config.debug then
                print(utils.gettime(), k, "peer keepalive timeout.")
                -- end
                for connkey, obj in pairs(peer.ppclient_connection_map) do
                    if obj.apt then
                        obj.apt:close()
                        obj.apt = nil
                    end
                end

                shared.peer_map[k] = nil
            else
                live_peers[peer] = k

                -- keep alive peer
                if utils.gettime() - peer.apt.last_outgoing_time > config.keepalive_delay then
                    peer.apt:send_keepalive()
                end
            end
        end

        -- cleanup peer's binding service
        for port, t in pairs(shared.bind_map) do
            if not live_peers[t.peer] then
                t:unbind()
            end
        end

        for key, apt in pairs(bindserv.clientmap) do
            local need_cleanup = false
            if apt.peer_key then
                local peer = shared.peer_map[apt.peer_key]
                if peer and peer.apt ~= apt then
                    -- cleanup on peer tunnel has been changed to another udp apt.
                    need_cleanup = true
                end
            end

            -- ignore client to remote nat server
            if not need_cleanup and apt ~= shared.remote_serv then
                -- cleanup timeout client.
                local timeout = apt.latency and config.peer_timeout or config.none_peer_timeout
                if utils.gettime() - apt.last_incoming_time > timeout then
                    need_cleanup = true
                    local peer = shared.weak_apt_peer_map[apt]
                    if peer then
                        for k,v in pairs(shared.peer_map) do
                            if v == peer then
                                shared.peer_map[k] = nil
                                break
                            end
                        end
                    end
                end
            end

            if need_cleanup then
                apt:cleanup()
                -- if config.debug then
                print(utils.gettime(), key, "client keepalive timeout.")
            -- end
            end
        end

        fan.sleep(5)
    end
end

local function _flush_connection_map(peer, conn_key, map_key, flush_type, disconnect_type)
    for connkey, obj in pairs(peer[map_key]) do
        if obj.incoming_count > 0 then
            -- flush data from buffer to endpoint connection in sequence.
            repeat
                local next_incoming_index = obj.incoming_index < config.auto_index_max and obj.incoming_index + 1 or 1
                local data = obj.incoming_cache[next_incoming_index]
                if data then
                    obj.incoming_index = next_incoming_index
                    obj.incoming_cache[next_incoming_index] = nil
                    obj.incoming_count = obj.incoming_count - 1
                    if obj[conn_key] then
                        obj[conn_key]:send(data)
                        obj.sending = true
                    end
                else
                    break
                end
            until obj.incoming_count == 0
        end

        if #(obj.input_queue) > 0 then
            -- flush data from endpoint connection to peer tunnel.
            if obj.outgoing_count < config.outgoing_count_max then
                -- concat buffer with max flush limit.
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
                local forward_index =
                    peer.apt:send_msg {
                    type = flush_type,
                    connkey = connkey,
                    data = data,
                    index = auto_index
                }

                obj.outgoing_count = obj.outgoing_count + 1

                if config.debug then
                    print(map_key, "forward", forward_index, auto_index)
                end
                peer.apt.index_conn_map[forward_index] = obj
            end
        elseif obj.need_send_disconnect and obj.outgoing_count == 0 then
            -- send disconnect command to remote peer until all data have been flushed to it.
            obj.need_send_disconnect = nil
            peer[map_key][connkey] = nil
            peer.apt:send_msg {type = disconnect_type, connkey = connkey}
        end
    end
end

local function sync_port_buffers(bindserv)
    while not bindserv.stop do
        for ckey, peer in pairs(shared.peer_map) do
            -- peer, conn_key, map_key, flush_type, disconnect_type
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
        shared.allowed_map_shrink()
        fan.sleep(1)
    end
end

local function bind_apt(apt)
    apt.ppkeepalive_output_index_map = {}
    apt.index_conn_map = {}
    setmetatable(apt.index_conn_map, {__mode = "v"})

    config.weaktable[string.format("bind_apt_%s:%d", apt.host, apt.port)] = apt

    apt.last_incoming_time = utils.gettime()
    apt.last_outgoing_time = utils.gettime()

    local host = apt.host
    local port = apt.port

    apt.onread = function(body)
        local msg = objectbuf.decode(body, sym)
        if not msg then
            print("decode failed.", host, port, #(body))
            return
        end

        shared.allowed_map_touch(host, port)

        if config.debug then
            print(os.date("%X"), host, port, cjson.encode(msg))
        end

        apt.last_incoming_time = utils.gettime()
        if msg.clientkey then
            create_or_update_peer(apt, host, port, msg)
        end

        local command = command_map[msg.type]
        if command then
            command(apt, host, port, msg)
        end
    end

    apt.onsent = function(index)
        -- print("onsent", apt)
        local obj = apt.index_conn_map[index]

        if obj then
            obj.outgoing_count = obj.outgoing_count - 1
            apt.index_conn_map[index] = nil

            if obj.pause_read and #(obj.input_queue) < MAX_INPUT_QUEUE_SIZE / 2 then
                obj.pause_read:resume_read()
                obj.pause_read = nil
            end

            _sync_port()
        elseif apt.ppkeepalive_output_index_map[index] then
            apt.ppkeepalive_output_index_map[index] = nil
        end
    end

    apt.ontimeout = function(package)
        local alive = shared.allowed_map_test(host, port)
        if not alive then
            if config.debug then
                print("not alive, drop", #(package), host, port)
            end
            -- drop dead client's packet.
            return false
        else
            local output_index = string.unpack("<I4", package)
            if apt.ppkeepalive_output_index_map[output_index] then
                apt.ppkeepalive_output_index_map[output_index] = nil

                -- drop keepalive packet.
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

    if fan.getinterfaces then
        for i, v in ipairs(fan.getinterfaces()) do
            if v.type == "inet" then
                print(cjson.encode(v))
                if v.name == "wlp3s0" or v.name == "en0" or v.name == "eth0" then
                    shared.internal_host = v.host
                    shared.internal_netmask = v.netmask
                end
            end
        end
    end

    shared.bindserv = connector.bind("udp://0.0.0.0:0")
    shared.remote_serv =
        shared.bindserv.getapt(
        config.remote_host,
        config.remote_port,
        nil,
        string.format("%s:%d", config.remote_host, config.remote_port)
    )

    local apt_mt = getmetatable(shared.remote_serv)

    apt_mt.send_msg = function(apt, msg)
        msg.clientkey = clientkey
        if config.debug then
            print(apt.host, apt.port, "send", cjson.encode(msg))
        end
        apt.last_outgoing_time = utils.gettime()
        return apt:send(objectbuf.encode(msg, sym))
    end

    apt_mt.send_keepalive = function(apt)
        local output_index = apt:send_msg {type = "ppkeepalive"}
        apt.ppkeepalive_output_index_map[output_index] = true
    end

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

    self.serv =
        tcpd.bind {
        port = port,
        onaccept = function(apt)
            local connkey = connkey_index
            connkey_index = connkey_index + 1

            local obj = {
                connkey = connkey,
                input_queue = {},
                incoming_cache = {},
                incoming_index = 0,
                incoming_count = 0,
                outgoing_count = 0,
                apt = apt,
                bind_port = port,
                peer = peer,
                host = peer.host,
                port = peer.port,
                auto_index = 1,
                connected = true
            }

            peer.ppclient_connection_map[connkey] = obj

            local weak_obj = utils.weakify_object(obj)

            peer.apt:send_msg {
                type = "ppconnect",
                connkey = connkey,
                host = self.remote_host,
                port = self.remote_port
            }

            apt:bind {
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
    for k, v in pairs(shared.peer_map) do
        if k:find(params.clientkey) == 1 then
            table.insert(list, v)
        end
    end

    if #(list) == 0 then
        return false, "NAT not completed."
    end

    table.sort(
        list,
        function(a, b)
            return a.apt.last_incoming_time > b.apt.last_incoming_time
        end
    )

    local peer = list[1]

    local t
    t = {
        port = port,
        peer = peer,
        remote_host = params.remote_host,
        remote_port = params.remote_port
    }

    setmetatable(t, bind_service_mt)

    return t:bind()
end

function getStatus()
    return string.format("%s", status)
end
