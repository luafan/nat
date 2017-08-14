status = "n/a"

local fan = require "fan"
local config = require "config"
local connector = require "fan.connector"
local objectbuf = require "fan.objectbuf"
local utils = require "fan.utils"

local cjson = require "cjson"
require "compat53"

local sym = objectbuf.symbol(require "nat_dic")

local conn_map = {}
local key_conn_map = {}

local command_map = {}
local serv = nil

function command_map.list(apt, msg)
    local conn = conn_map[apt]
    if msg.clientkey then
        conn.clientkey = msg.clientkey
    end
    if msg.internal_host and msg.internal_port then
        conn.internal_host = msg.internal_host
        conn.internal_port = msg.internal_port
        conn.internal_netmask = msg.internal_netmask
    end
    if msg.data then
        for k, v in pairs(msg.data) do
            local c = key_conn_map[k]
            if c then
                c.data[string.format("%s:%d", v.host, v.port)] = v
            end
        end
    end

    local t = {}
    local current_time = utils.gettime()

    for k, v in pairs(conn_map) do
        if k ~= apt then
            local data = {}
            for k, v in pairs(v.data) do
                table.insert(data, v)
            end
            if apt.host == k.host then
                if v.internal_host and v.internal_port then
                    table.insert(
                        t,
                        {
                            host = v.internal_host,
                            port = v.internal_port,
                            clientkey = v.clientkey,
                            data = data
                        }
                    )
                end
            else
                table.insert(
                    t,
                    {
                        host = k.host,
                        port = k.port,
                        internal_host = conn.internal_netmask == apt.internal_netmask and v.internal_host or nil,
                        internal_port = conn.internal_netmask == apt.internal_netmask and v.internal_port or nil,
                        clientkey = v.clientkey,
                        data = data
                    }
                )
            end
        end
    end

    apt:send(objectbuf.encode({type = msg.type, data = t}, sym))
end

function onStart()
    if not config.server_enabled then
        return
    end

    status = "running"
    serv = connector.bind(string.format("udp://0.0.0.0:%d", config.server_port))
    serv.onaccept = function(apt)
        print("onaccept")
        conn_map[apt] = {last_keepalive = utils.gettime(), data = {}}

        apt.onread = function(body)
            conn_map[apt].last_keepalive = utils.gettime()

            local msg = objectbuf.decode(body, sym)
            print(apt.host, apt.port, cjson.encode(msg))
            if msg.clientkey and not key_conn_map[msg.clientkey] then
                key_conn_map[msg.clientkey] = conn_map[apt]
            end

            local command = command_map[msg.type]
            if command then
                command(apt, msg)
            end
        end
    end

    coroutine.wrap(
        function()
            while serv do
                for k, v in pairs(conn_map) do
                    if utils.gettime() - v.last_keepalive > 30 then
                        print(k.dest, "keepalive timeout.")
                        k:cleanup()
                        conn_map[k] = nil
                    end
                end

                fan.sleep(1)
            end
        end
    )()
end

function onStop()
    if serv then
        serv.stop = true
        serv.close()
        serv = nil
    end

    status = "stopped"
end

function getStatus()
    return string.format("%s", status)
end
