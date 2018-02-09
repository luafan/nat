status = "n/a"

local fan = require "fan"
local config = require "config"
local connector = require "fan.connector"
local objectbuf = require "fan.objectbuf"
local utils = require "fan.utils"
local openssl = require "openssl"
local pkey = openssl.pkey
local base64 = require "base64"

local cjson = require "cjson"
require "compat53"

local ctxpool = require "ctxpool"

local sym = objectbuf.symbol(require "nat_dic")

local key_conn_map = {}

local command_map = {}
local serv = nil

local function create_user(ctx, publickey)
    local client_publickey = base64.encode(publickey)
    local m = ctx.user("one", "where client_publickey=?", client_publickey)
    if not m then
        local privatekey = pkey.new("rsa", 2048)
        m = ctx.user("new", {
            client_publickey = client_publickey,
            server_privatekey = base64.encode(privatekey:export("der"))
        })
        m.privkey = privatekey
    else
        m.privkey = pkey.read(base64.decode(m.server_privatekey), true)
    end

    m.pubkey = pkey.read(publickey)
    m.publickey = publickey

    return m
end

local function get_keys(ctx, uid)
    local m = ctx.user("one", "where id=?", uid)
    if m then
        m.publickey = base64.decode(m.client_publickey)
        m.privkey = pkey.read(base64.decode(m.server_privatekey), true)
        m.pubkey = pkey.read(m.publickey)
        
        return m
    end
end

local function apt_send_msg(apt, msg, plain)
    if apt.pubkey and not plain then
        local data = objectbuf.encode(msg, sym)
        local edata = objectbuf.encode({apt.pubkey:seal(data)}, sym)
        return apt:send(edata)
    else
        return apt:send(objectbuf.encode(msg, sym))
    end
end

function command_map.register(apt, msg)
    if msg.publickey then
        local m = ctxpool:safe(create_user, msg.publickey)
        local server_publickey = m.privkey:get_public():export("der")
        apt_send_msg(apt, {
            type = msg.type,
            uid = { m.pubkey:seal(m.id) },
            publickey = { m.pubkey:seal(server_publickey) },
        }, true)
        apt.pubkey = m.pubkey
        apt.privkey = m.privkey
        apt.publickey = m.publickey
    elseif msg.challenge and msg.uid then
        local m = ctxpool:safe(get_keys, msg.uid)
        local data = m.privkey:decrypt(msg.challenge)
        if data and math.abs(tonumber(data) - os.time()) < 60 then
            apt.pubkey = m.pubkey
            apt.privkey = m.privkey
            apt.publickey = m.publickey
            apt_send_msg(apt, {
                type = msg.type
            }, true)
        end
    end
end

function command_map.list(apt, msg)
    if msg.internal_host and msg.internal_port then
        apt.internal_host = msg.internal_host
        apt.internal_port = msg.internal_port
        apt.internal_netmask = msg.internal_netmask
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

    for publickey, _apt in pairs(key_conn_map) do
        if _apt ~= apt and _apt.publickey then
            local data = {}

            if _apt.host == "103.250.195.161" then
                local t = {host = "203.156.209.194", port = _apt.port}
                _apt.data[string.format("%s:%d", t.host, t.port)] = t
            elseif _apt.host == "203.156.209.194" then
                local t = {host = "103.250.195.161", port = _apt.port}
                _apt.data[string.format("%s:%d", t.host, t.port)] = t
            end

            _apt.data[string.format("%s:%d", _apt.host, _apt.port)] = nil

            for k, v in pairs(_apt.data) do
                table.insert(data, v)
            end

            local obj = {
                host = _apt.host,
                port = _apt.port,
                publickey = _apt.publickey,
                clientkey = _apt.clientkey,
                data = data
            }

            if apt.host == _apt.host then
                -- if two peers come from same ip
                if _apt.internal_host and _apt.internal_port then
                    obj.internal_host = _apt.internal_host
                    obj.internal_port = _apt.internal_port
                end
            end

            table.insert(t, obj)
        end
    end

    apt_send_msg(apt, {type = msg.type, data = t})
end

function onStart()
    if not config.server_enabled then
        return
    end

    status = "running"
    serv = connector.bind(string.format("udp://0.0.0.0:%d", config.server_port))
    serv.onaccept = function(apt)
        apt.onread = function(apt, body)
            local msg = objectbuf.decode(body, sym)

            if not msg.type and apt.privkey then
                local edata = apt.privkey:open(table.unpack(msg))
                if not edata then
                    return
                end
                msg = objectbuf.decode(edata, sym)
            end

            if msg.type == "echo" then
                apt_send_msg(apt, {type = msg.type, host = apt.host, port = apt.port})
                return
            end

            if msg.clientkey then
                apt.clientkey = msg.clientkey
            end

            apt.last_keepalive = utils.gettime()

            if not apt.data then
                apt.data = {}
            end

            -- print(apt.host, apt.port, cjson.encode(msg))

            local command = command_map[msg.type]
            if command then
                command(apt, msg)
            end

            if apt.publickey and not key_conn_map[apt.publickey] then
                key_conn_map[apt.publickey] = apt
            end
        end
    end

    coroutine.wrap(
        function()
            while serv do
                for publickey, apt in pairs(key_conn_map) do
                    if utils.gettime() - apt.last_keepalive > 30 then
                        print(apt.dest, "keepalive timeout.")
                        apt:cleanup()

                        key_conn_map[publickey] = nil
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
