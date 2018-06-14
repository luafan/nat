local shared = require "shared"
local tcpd = require "fan.tcpd"
local udpd = require "fan.udpd"
local utils = require "fan.utils"
local config = require "config"

local MAX_INPUT_QUEUE_SIZE = config.max_input_queue_size or 1000

local _sync_port = shared._sync_port

local connkey_index = 1

local conn_clientservice_mt = {}
conn_clientservice_mt.__index = conn_clientservice_mt

function conn_clientservice_mt:close_client()
    self.peer.ppclient_connection_map[self.connkey] = nil

    if self.apt then
        self.apt:close()
        self.apt = nil
    end
end

local function bind_tcp(self)
    local remote_host = self.remote_host
    local remote_port = self.remote_port
    local tunnel_apt = self.tunnel_apt
    local port = self.port
    local peer = shared.weak_apt_peer_map[self.tunnel_apt]

    return tcpd.bind {
        port = port,
        onaccept = function(apt)
            local connkey = connkey_index
            connkey_index = connkey_index + 1

            if apt.original_dst then
                local local_host, local_port = apt:getsockname()
                local original_host, original_port = apt:original_dst()
                if original_host ~= local_host and original_port ~= local_port then
                    remote_host = original_host
                    remote_port = original_port
                end
            end

            if not remote_host or not remote_port then
                return apt:close()
            end

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

            setmetatable(obj, conn_clientservice_mt)

            peer.ppclient_connection_map[connkey] = obj

            local obj = utils.weakify_object(obj)

            tunnel_apt:send_msg(
                {
                    type = "ppconnect",
                    connkey = connkey,
                    host = remote_host,
                    port = remote_port
                },
                true
            )

            apt:bind {
                onread = function(buf)
                    table.insert(obj.input_queue, buf)

                    if #(obj.input_queue) > MAX_INPUT_QUEUE_SIZE then
                        obj.apt:pause_read()
                        obj.pause_read = obj.apt
                    end

                    _sync_port()
                end,
                onsendready = function()
                    obj.sending = false
                    if obj.need_close_client then
                        obj:close_client()
                    end
                end,
                ondisconnected = function(msg)
                    if config.debug_nat then
                        print("client disconnected", msg)
                    end

                    obj.connected = nil
                    obj.apt = nil
                    obj.need_send_disconnect = true
                end
            }

            config.weaktable[string.format("service_apt_%s_%d", peer.clientkey, connkey)] = apt
            config.weaktable[string.format("service_obj_%s_%d", peer.clientkey, connkey)] = obj
        end
    }
end

local function bind_udp(self)
    local remote_host = self.remote_host
    local remote_port = self.remote_port
    local tunnel_apt = self.tunnel_apt
    local port = self.port
    local peer = shared.weak_apt_peer_map[self.tunnel_apt]

    local incoming_queue = {}

    local conn = nil
    conn = udpd.new {
        bind_port = port,
        onread = function(data, from)
            local connkey = connkey_index
            connkey_index = connkey_index + 1

            peer.ppclient_udpfrom_map[connkey] = {port = port, from = from, incoming_queue = incoming_queue}

            tunnel_apt:send_msg(
                {
                    type = "ppudpreq",
                    connkey = connkey,
                    data = data,
                    host = remote_host,
                    port = remote_port
                },
                true
            )
        end,
        onsendready = function()
            if #(incoming_queue) > 0 then
                conn:send(table.unpack(table.remove(incoming_queue, 1)))
            end
            if #(incoming_queue) > 0 then
                conn:send_req()
            end
        end
    }

    return conn
end

local bind_service_mt = {}
bind_service_mt.__index = bind_service_mt

function bind_service_mt:bind()
    local peer = shared.weak_apt_peer_map[self.tunnel_apt]

    if not self.serv_tcp and (not self.protocol or string.find(self.protocol, "tcp")) then
        self.serv_tcp = bind_tcp(self)

        if self.serv_tcp then
            config.weaktable[string.format("service_tcp_%s_%d", peer.clientkey, self.port)] = self.serv_tcp
            shared.bind_map_tcp[self.port] = self
        else
            return false, string.format("can't not bind to %d.", self.port)
        end
    end

    if not self.serv_udp and (self.protocol and string.find(self.protocol, "udp")) then
        self.serv_udp = bind_udp(self)

        if self.serv_udp then
            config.weaktable[string.format("service_udp_%s_%d", peer.clientkey, self.port)] = self.serv_udp
            shared.bind_map_udp[self.port] = self
        else
            return false, string.format("can't not bind to %d.", self.port)
        end
    end

    return true, "submitted."
end

function bind_service_mt:unbind(protocol)
    if self.serv_tcp and (not protocol or string.find(protocol, "tcp")) then
        shared.bind_map_tcp[self.port] = nil
        self.serv_tcp:close()
        self.serv_tcp = nil
    end

    if self.serv_udp and (not protocol or string.find(protocol, "udp")) then
        shared.bind_map_udp[self.port] = nil
        self.serv_udp:close()
        self.serv_udp = nil
    end
end

return bind_service_mt
