import sys
from ldap3 import (
    Server,
    Connection,
    AUTO_BIND_TLS_BEFORE_BIND,
    AUTO_BIND_NO_TLS,
)
from ldap3.core.exceptions import LDAPInvalidCredentialsResult
from typing import List, Literal


class LdapClient:
    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        port: int = 3268,
        use_ssl: bool = False,
    ):
        self._host = host
        self._port = port
        self._use_ssl = use_ssl
        self._user = user
        self._password = password
        self.connection = self._ldap_connect()

    def _ldap_connect(self):
        ldap_server = Server(host=self._host, port=self._port, use_ssl=self._use_ssl)
        return Connection(
            server=ldap_server,
            raise_exceptions=True,
            user=self._user,
            password=self._password,
            auto_bind=(self._use_ssl and AUTO_BIND_NO_TLS or AUTO_BIND_TLS_BEFORE_BIND),
            read_only=True,
            authentication="SIMPLE",
        )

    def search(
        self,
        s_base: str,
        s_filter: str,
        s_attributes: List[str],
        s_scope: Literal["BASE", "LEVEL", "SUBTREE"] = "LEVEL",
    ):
        self.connection.search(
            search_base=s_base,
            search_filter=s_filter,
            search_scope=s_scope,
            attributes=s_attributes,
        )
        return self.connection.entries


class LdapSdk:
    base_dn: str
    users_folder: str
    groups_folder: str

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        location: str = "csin",
        port: int = 3268,
        use_ssl: bool = False,
    ):
        self._client = LdapClient(host, user, password, port, use_ssl)
        self.base_dn = f"DC={location},DC=cz"
        self.users_folder = f"OU=CSUsers,DC=cen,{self.base_dn}"

    def get_user(self, cn: str) -> dict | None:
        search_filter = "(cn={})".format(cn)
        search_result = self._client.search(
            self.users_folder,
            search_filter,
            ["sn", "givenName", "mail", "accountExpires", "msExchExtensionAttribute27"],
        )
        if len(search_result) == 0:
            return None
        return {
            "name": str(search_result[0]["sn"])
            + " "
            + str(search_result[0]["givenName"]),
            "email": (
                str(search_result[0]["mail"])
                if "mail" in search_result[0] and len(search_result[0]["mail"]) > 0
                else str(search_result[0]["msExchExtensionAttribute27"])
            ),
            "expired": "accountExpires" in search_result[0]
            and str(search_result[0]["accountExpires"]) != "0",
        }

    def get_managed_users(self, cn: str) -> list[str]:
        search_filter = "(cn={})".format(cn)
        print(f"Searching for managed users of {cn}")
        search_result = self._client.search(
            self.users_folder, search_filter, ["directReports"]
        )
        if len(search_result) == 0 or "directReports" not in search_result[0]:
            return []
        members = [
            member.split(",")[0].split("=")[1]
            for member in search_result[0]["directReports"]
        ]
        print(f"Direct reports of {cn}: {len(members)} users found.")
        for member in members:
            members.extend(self.get_managed_users(member))
        return members


def save_members(username: str, password: str, manager: str):
    ldap = LdapSdk(
        host="cen.csin.cz",
        user=f"CN={username},OU=CSUsers,DC=cen,DC=csin,DC=cz",
        password=password,
        location="csin",
        port=636,
        use_ssl=True,
    )
    user = ldap.get_user(manager)
    if user is None:
        raise ValueError(f"Manager {manager} not found in LDAP")
    print(f"Manager: {user['name']} ({user['email']})")
    members = ldap.get_managed_users(manager)
    if members is None:
        return []
    data = "\n".join(
        [
            f"{member}, {user['name']},{user['email']}"
            for member, user in zip(
                members,
                [
                    ldap.get_user(member)
                    for member in members
                    if not member.endswith("t")
                ],
            )
            if user is not None
        ]
    )
    with open("members.csv", "w") as f:
        f.write("Cen,Name,Email\n")
        f.write(data)


# get input from cli args
if len(sys.argv) != 4:
    print("Usage: script.py <username> <password> <manager>")
    sys.exit(1)

username = sys.argv[1]
password = sys.argv[2]
manager = sys.argv[3]

try:
    save_members(username, password, manager)
    print("Members saved to members.csv")
except LDAPInvalidCredentialsResult as e:
    print("Invalid username or password.")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
