server_enabled = os.getenv("SERVER_ENABLED") == "true"
client_enabled = (os.getenv("CLIENT_ENABLED") or "true") == "true"
server_port = tonumber(os.getenv("SERVER_PORT") or 10000)

remote_host = os.getenv("REMOTE_HOST")
remote_port = tonumber(os.getenv("REMOTE_PORT"))

name = os.getenv("NAT_NAME")

udp_package_timeout = tonumber(os.getenv("UDP_PACKAGE_TIMEOUT") or 3)
udp_waiting_count = tonumber(os.getenv("UDP_WAITING_COUNT") or 100 * udp_package_timeout)

udp_mtu = tonumber(os.getenv("UDP_MTU") or 576)

keepalive_delay = tonumber(os.getenv("KEEPALIVE_DELAY") or 10)
peer_timeout = tonumber(os.getenv("PEER_TIMEOUT") or 600)
none_peer_timeout = tonumber(os.getenv("NONE_PEER_TIMEOUT") or 10)

auto_index_max = tonumber(os.getenv("AUTO_INDEX_MAX") or 65535)

outgoing_count_max = tonumber(os.getenv("OUTGOING_MAX") or 10)

drop_package_outside_window = os.getenv("DROP_PACKAGE_OUTSIDE_WINDOW") == "true"

session_cache = {}
