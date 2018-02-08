local orm = require  "mariadb.orm"

return {
    ["user"] = {
        ["id"] = "int(11) NOT NULL PRIMARY KEY AUTO_INCREMENT",
        ["client_publickey"] = "varchar(1024)",
        ["server_privatekey"] = "varchar(2048)",

        [orm.FIELD_ID_KEY] = "id",
    },
}
