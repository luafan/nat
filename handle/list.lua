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

local function count_table_size(t, n, level)
    if not n then
        n = 1
    end
    if not level then
        level = 1
    end

    local count = 0
    for k, v in pairs(t) do
        if n > level then
            count = count + count_table_size(v, n, level + 1)
        else
            count = count + 1
        end
    end

    return count
end

local function count_chain_size(t)
    local count = 0
    local cursor = t._head
    while cursor do
        count = count + 1
        cursor = cursor._next
    end

    return count
end

local function onGet(req, resp)
    resp:addheader("Content-Type", "application/json; charset=UTF-8")

    local blanks = {}
    local start = 0
    local regtable = debug.getregistry()
    while start do
        if regtable[start] then
            blanks[start] = true
            start = regtable[start]
        else
            break
        end
    end
    local reg_count = 0
    for k, v in pairs(debug.getregistry()) do
        if not blanks[k] then
            reg_count = reg_count + 1
        end
    end

    local map = {
        udp_send_total = config.udp_send_total,
        udp_receive_total = config.udp_receive_total,
        udp_resend_total = config.udp_resend_total,
        top = fan.gettop(),
        reg_count = reg_count,
        bind_map_count = count_table_size(shared.bind_map),
        peer_map_count = count_table_size(shared.peer_map),
        allowed_map_count = count_table_size(shared.allowed_map, 2),
        list = {}
    }

    local nat = service.get("nat")

    for key, apt in pairs(shared.bindserv.clientmap) do
        local peer = nat.get_peer(apt)
        local item = {
            key = key,
            clientkey = peer and peer.clientkey or "N/A",
            last_keepalive = utils.gettime() - apt.last_keepalive,
            output_wait_count = apt._output_wait_count,
            output_index = apt._output_index,
            output_wait_ack_count = count_table_size(apt._output_wait_ack),
            output_wait_index_map_count = count_table_size(apt._output_wait_package_parts_map),
            output_ack_package_count = count_table_size(apt._output_ack_package),
            incoming_map_count = count_table_size(apt._incoming_map, 2),
            output_chain_count = count_chain_size(apt._output_chain),
            ppclient_connection_count = peer and count_table_size(peer.ppclient_connection_map) or "N/A",
            ppservice_connection_count = peer and count_table_size(peer.ppservice_connection_map) or "N/A",
            ppkeepalive_map_count = apt.ppkeepalive_map and count_table_size(apt.ppkeepalive_map) or "N/A",
            incoming = {}
        }

        table.insert(map.list, item)

        for output_index, incoming_object in pairs(apt._incoming_map) do
            if incoming_object.done then
                table.insert(
                    item.incoming,
                    {
                        index = output_index,
                        total = incoming_object.count
                    }
                )
            else
                local count = 0
                for idx, body in pairs(incoming_object.items) do
                    if body then
                        count = count + 1
                    end
                end
                table.insert(
                    item.incoming,
                    {
                        index = output_index,
                        count = count,
                        total = incoming_object.count
                    }
                )
            end
        end

        if peer then
        -- print(key, count_table_size(peer.ppclient_connection_map))
        end
    end
    collectgarbage()
    map.memory = collectgarbage("count")

    return resp:reply(200, "OK", json.encode(map))
end

return {
    route = "/list",
    onGet = onGet
}
