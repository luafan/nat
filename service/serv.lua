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
local clientkey_conn_map = {}

local command_map = {}
local serv = nil

local function create_user(ctx, publickey)
    local client_publickey = base64.encode(publickey)
    local m = ctx.user("one", "where client_publickey=?", client_publickey)
    if not m then
        local privatekey = pkey.new("rsa", 2048)
        m =
            ctx.user(
            "new",
            {
                client_publickey = client_publickey,
                server_privatekey = base64.encode(privatekey:export("der"))
            }
        )
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
        apt_send_msg(
            apt,
            {
                type = msg.type,
                uid = {m.pubkey:seal(m.id)},
                publickey = {m.pubkey:seal(server_publickey)}
            },
            true
        )
        apt.pubkey = m.pubkey
        apt.privkey = m.privkey
        apt.publickey = m.publickey
    elseif msg.challenge and msg.uid then
        local m = ctxpool:safe(get_keys, msg.uid)
        if m then
            local data = m.privkey:decrypt(msg.challenge)
            if data and math.abs(tonumber(data) - os.time()) < 60 then
                apt.pubkey = m.pubkey
                apt.privkey = m.privkey
                apt.publickey = m.publickey
                apt_send_msg(
                    apt,
                    {
                        type = msg.type
                    },
                    true
                )
                return
            end
        end

        apt_send_msg(
            apt,
            {
                type = msg.type,
                error = "invaild challenge"
            },
            true
        )
    end
end

function command_map.list(apt, msg)
    apt.internal_addr_list = msg.internal_addr_list

    if msg.assistant_addr_map then
        for k, v in pairs(msg.assistant_addr_map) do
            local apt = clientkey_conn_map[k]
            if apt and (v.host ~= apt.host or v.port ~= apt.port) then
                apt.my_addr_map[string.format("%s:%d", v.host, v.port)] = v
            end
        end
    end

    local peer_list = {}

    for publickey, _apt in pairs(key_conn_map) do
        if _apt ~= apt and _apt.publickey then
            local addr_list = {}

            if _apt.host == "103.250.195.161" then
                local t = {host = "203.156.209.194", port = _apt.port}
                _apt.my_addr_map[string.format("%s:%d", t.host, t.port)] = t
            elseif _apt.host == "203.156.209.194" then
                local t = {host = "103.250.195.161", port = _apt.port}
                _apt.my_addr_map[string.format("%s:%d", t.host, t.port)] = t
            end

            for k, v in pairs(_apt.my_addr_map) do
                table.insert(addr_list, v)
            end

            if apt.host == _apt.host and apt.internal_addr_list and _apt.internal_addr_list then
                -- if two peers come from same ip
                for i,v in ipairs(apt.internal_addr_list) do
                    for _i,_v in ipairs(_apt.internal_addr_list) do
                        if v.netmask == _v.netmask then
                            table.insert(addr_list, _v)
                        end
                    end
                end
            end

            table.insert(peer_list, {
                host = _apt.host,
                port = _apt.port,
                publickey = _apt.publickey,
                clientkey = _apt.clientkey,
                addr_list = addr_list,
            })
        end
    end

    apt_send_msg(apt, {type = msg.type, peer_list = peer_list})
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

            if #msg == 3 then
                if apt.privkey then
                    local edata = apt.privkey:open(table.unpack(msg))
                    if not edata then
                        print(apt.dest, "decrypt failed.")
                        return
                    end
                    msg = objectbuf.decode(edata, sym)
                else
                    print(apt.dest, "receive encrypted message, but current address has not register yet.")
                    apt_send_msg(
                        apt,
                        {
                            type = "register",
                            error = "need register"
                        },
                        true
                    )            
                end
            end

            if msg.type == "echo" then
                apt_send_msg(apt, {type = msg.type, host = apt.host, port = apt.port})
                return
            end

            if msg.clientkey then
                apt.clientkey = msg.clientkey
            end

            apt.last_keepalive = utils.gettime()

            if not apt.my_addr_map then
                apt.my_addr_map = {}
            end

            local command = command_map[msg.type]
            if command then
                command(apt, msg)
            else
                print(apt.dest, "invaild msg type", msg.type)
            end

            if apt.publickey and not key_conn_map[apt.publickey] then
                key_conn_map[apt.publickey] = apt
                clientkey_conn_map[apt.clientkey] = apt
            end
        end
    end

    coroutine.wrap(
        function()
            while serv do
                for publickey, apt in pairs(key_conn_map) do
                    if utils.gettime() - apt.last_keepalive > 30 then
                        print(apt.dest, "keepalive timeout.")
                        clientkey_conn_map[apt.clientkey] = nil
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
