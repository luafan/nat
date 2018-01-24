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

shared.clientkey_apt_map = {}
shared.weak_apt_peer_map = {}
-- setmetatable(shared.weak_apt_peer_map, {__mode = "kv"})
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
        if config.debug_nat then
            print("list", i, cjson.encode(v))
        end
        local clientkey = v.clientkey
        local apt = shared.clientkey_apt_map[clientkey]
        local peer = apt and shared.weak_apt_peer_map[apt] or nil
        if not peer then
            local apt = shared.bindserv.getapt(v.host, v.port, nil, string.format("%s:%d", v.host, v.port))
            apt:send_keepalive()

            if v.internal_host and v.internal_port then
                local apt =
                    shared.bindserv.getapt(
                    v.internal_host,
                    v.internal_port,
                    nil,
                    string.format("%s:%d", v.internal_host, v.internal_port)
                )
                apt:send_keepalive()
            end

            if v.data then
                for i, v in ipairs(v.data) do
                    if v.host and v.port then
                        local apt = shared.bindserv.getapt(v.host, v.port, nil, string.format("%s:%d", v.host, v.port))
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
    if config.debug_nat then
        print(host, port, cjson.encode(msg))
    end

    local connkey = msg.connkey

    local peer = shared.weak_apt_peer_map[apt]
    local connection_map = peer.ppservice_connection_map

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
            if config.debug_nat then
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
            if config.debug_nat then
                print("remote disconnected", msgstr)
            end
            obj.need_send_disconnect = true
        end
    }

    config.weaktable[string.format("ppconnect_conn_%s_%d", peer.clientkey, connkey)] = obj.conn
    config.weaktable[string.format("ppconnect_obj_%s_%d", peer.clientkey, connkey)] = obj
end

function command_map.ppconnected(apt, host, port, msg)
    if config.debug_nat then
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
    if config.debug_nat then
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
    if config.debug_nat then
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
    local peer = shared.weak_apt_peer_map[apt]
    if not peer then
        peer = {
            host = host,
            port = port,
            created = utils.gettime(),
            clientkey = msg.clientkey,
            ppservice_connection_map = {},
            ppclient_connection_map = {}
        }

        config.weaktable[string.format("peer_%s_%s", msg.clientkey, peer)] = peer
    else
        peer.host = host
        peer.port = port
    end

    apt.peer_key = msg.clientkey

    shared.clientkey_apt_map[msg.clientkey] = apt
    shared.weak_apt_peer_map[apt] = peer
end

local function list_peers(bindserv)
    while not bindserv.stop do
        local data = {}
        for apt, peer in pairs(shared.weak_apt_peer_map) do
            data[apt.peer_key] = {
                host = apt.host,
                port = apt.port
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
        for apt, peer in pairs(shared.weak_apt_peer_map) do
            -- cleanup timeout peer
            if utils.gettime() - apt.last_incoming_time > config.peer_timeout then
                apt:cleanup()
                -- if config.debug then
                print(utils.gettime(), apt.peer_key, "peer keepalive timeout.")
                -- end
                for connkey, obj in pairs(peer.ppclient_connection_map) do
                    if obj.apt then
                        obj.apt:close()
                        obj.apt = nil
                    end
                end

                shared.clientkey_apt_map[apt.peer_key] = nil
                shared.weak_apt_peer_map[apt] = nil
            else
                live_peers[apt] = apt.peer_key

                -- keep alive peer
                if utils.gettime() - apt.last_keepalive > config.keepalive_delay then
                    apt:send_keepalive()
                end
            end
        end

        -- cleanup peer's binding service
        for port, t in pairs(shared.bind_map) do
            if not live_peers[t.tunnel_apt] then
                t:unbind()
            end
        end

        for key, apt in pairs(bindserv.clientmap) do
            -- cleanup timeout client.
            local timeout = apt.peer_key and config.peer_timeout or config.none_peer_timeout
            if utils.gettime() - apt.last_incoming_time > timeout then
                shared.weak_apt_peer_map[apt] = nil

                -- ignore client to remote nat server
                if apt.peer_key and shared.clientkey_apt_map[apt.peer_key] == apt then
                    shared.clientkey_apt_map[apt.peer_key] = nil
                end

                apt.peer_key = nil
                apt:cleanup()

                if config.debug then
                    print(utils.gettime(), key, "client has been cleaned up.")
                end
            end
        end

        fan.sleep(5)
    end
end

local function _flush_connection_map(tunnel_apt, peer, conn_key, map_key, flush_type, disconnect_type)
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
                    tunnel_apt:send_msg {
                    type = flush_type,
                    connkey = connkey,
                    data = data,
                    index = auto_index
                }

                obj.outgoing_count = obj.outgoing_count + 1

                if config.debug_nat then
                    print(map_key, "forward", forward_index, auto_index)
                end
                tunnel_apt.index_conn_map[forward_index] = obj
            end
        elseif obj.need_send_disconnect and obj.outgoing_count == 0 then
            -- send disconnect command to remote peer until all data have been flushed to it.
            obj.need_send_disconnect = nil
            peer[map_key][connkey] = nil
            tunnel_apt:send_msg {type = disconnect_type, connkey = connkey}
        end
    end
end

local function sync_port_buffers(bindserv)
    while not bindserv.stop do
        for apt, peer in pairs(shared.weak_apt_peer_map) do
            -- peer, conn_key, map_key, flush_type, disconnect_type
            _flush_connection_map(apt, peer, "conn", "ppservice_connection_map", "ppdata_resp", "ppdisconnectedmaster")
            _flush_connection_map(apt, peer, "apt", "ppclient_connection_map", "ppdata_req", "ppdisconnectedclient")
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
    apt.last_keepalive = utils.gettime()
    apt.index_conn_map = {}
    setmetatable(apt.index_conn_map, {__mode = "v"})

    config.weaktable[string.format("bind_apt_%s:%d", apt.host, apt.port)] = apt

    local host = apt.host
    local port = apt.port

    apt.onread = function(apt, body)
        local msg = objectbuf.decode(body, sym)
        if not msg then
            print("decode failed.", host, port, #(body))
            return
        end

        shared.allowed_map_touch(host, port)

        if config.debug_nat then
            print(os.date("%X"), host, port, cjson.encode(msg))
        end

        if msg.clientkey then
            create_or_update_peer(apt, host, port, msg)
        end

        local command = command_map[msg.type]
        if command then
            command(apt, host, port, msg)
        end
    end

    apt.onsent = function(apt, package)
        -- print("onsent", apt)
        local obj = apt.index_conn_map[package.output_index]

        if obj then
            obj.outgoing_count = obj.outgoing_count - 1
            apt.index_conn_map[package.output_index] = nil

            if obj.pause_read and #(obj.input_queue) < MAX_INPUT_QUEUE_SIZE / 2 then
                obj.pause_read:resume_read()
                obj.pause_read = nil
            end

            _sync_port()
        elseif apt.ppkeepalive_output_index_map[package.output_index] then
            apt.ppkeepalive_output_index_map[package.output_index] = nil
        end
    end

    apt.ontimeout =
        function(apt, package)
        local alive = shared.allowed_map_test(host, port)
        if not alive then
            if config.debug_nat then
                print(
                    "not alive, drop",
                    package.body and #(package.body) or (package.body_end - package.body_begin + 1),
                    host,
                    port
                )
            end
            -- drop dead client's packet.
            return false
        else
            local output_index = package.output_index
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
        if config.debug_nat then
            print(apt.host, apt.port, "send", cjson.encode(msg))
        end
        return apt:send(objectbuf.encode(msg, sym))
    end

    apt_mt.send_keepalive = function(apt)
        if apt._output_chain.size < 10 then
            apt.last_keepalive = utils.gettime()
            local output_index = apt:send_msg {type = "ppkeepalive"}
            apt.ppkeepalive_output_index_map[output_index] = true
        end
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
    local peer = shared.weak_apt_peer_map[self.tunnel_apt]

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
                peer = utils.weakify_object(peer),
                host = peer.host,
                port = peer.port,
                auto_index = 1,
                connected = true
            }

            peer.ppclient_connection_map[connkey] = obj

            local weak_obj = utils.weakify_object(obj)

            self.tunnel_apt:send_msg {
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
                    if config.debug_nat then
                        print("client disconnected", msg)
                    end

                    local obj = weak_obj
                    obj.connected = nil
                    obj.apt = nil
                    obj.need_send_disconnect = true
                end
            }

            config.weaktable[string.format("service_apt_%s_%d", peer.clientkey, connkey)] = apt
            config.weaktable[string.format("service_obj_%s_%d", peer.clientkey, connkey)] = obj
        end
    }

    if self.serv then
        config.weaktable[string.format("service_%s_%d", peer.clientkey, port)] = self.serv
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
    for apt, peer in pairs(shared.weak_apt_peer_map) do
        if apt.peer_key:find(params.clientkey) == 1 then
            table.insert(list, apt)
        end
    end

    if #(list) == 0 then
        return false, "NAT not completed."
    end

    table.sort(
        list,
        function(a, b)
            return a.last_incoming_time > b.last_incoming_time
        end
    )

    local t
    t = {
        port = port,
        tunnel_apt = list[1],
        remote_host = params.remote_host,
        remote_port = params.remote_port
    }

    setmetatable(t, bind_service_mt)

    return t:bind()
end

function getStatus()
    return string.format("%s", status)
end
