"""Provide functionality for MAC address lookup using the OUI database.

Includes functions to fetch, parse, and search the database.
"""

# Standard Python Libraries
from requests.exceptions import RequestException

# Local Python Libraries (Included with Project)
from modules.constants.standalone import OUI_URL
from modules.constants.standard import RE_OUI_MAC_ADDRESS_PATTERN, RE_OUI_ENTRY_PATTERN
from modules.networking.unsafe_https import s
from modules.networking.utils import is_mac_address, get_mac_oui


OuiDatabaseType = dict[str, list[dict[str, str]]]


class OUIFetchError(Exception):
    """Raised when fetching the OUI database fails."""


class InvalidMacError(Exception):
    """Raised when an invalid MAC address is found."""


class MacLookup:
    def __init__(self, *, load_on_init: bool = False):
        """Initialize the MacLookup instance.

        :param load_on_init: If True, fetches and loads the OUI database immediately.
        """
        self.oui_database: OuiDatabaseType | None = None
        if load_on_init:
            self.refresh_oui_database()

    def refresh_oui_database(self):
        """Fetch and load the OUI database, forcing an update to the latest data."""
        self.oui_database = fetch_and_parse_oui_database()

    def lookup(self, mac_address: str):
        """Lookup the MAC address in the OUI database.

        Will load the database if it's not already loaded.
        """
        if not is_mac_address(mac_address):
            raise InvalidMacError(
                f"Invalid MAC address: {mac_address}\n"
                "A MAC address must be a 12-digit hexadecimal number long.",
            )

        # Ensure the database is loaded before performing lookup
        if self.oui_database is None:
            self.refresh_oui_database()

        if self.oui_database is None:
            return None

        oui = get_mac_oui(mac_address)
        return self.oui_database.get(oui)

    def get_mac_address_organization_name(self, mac_address: str):
        """Return the organization name for a given MAC address, if available."""
        oui_infos = self.lookup(mac_address)
        if not oui_infos:
            return None

        for oui_info in oui_infos:
            organization_name = oui_info.get("organization_name")
            if organization_name:
                return organization_name

        return None


def fetch_and_parse_oui_database():
    def strip_tuple(tuple_to_strip: tuple):
        return tuple(map(str.strip, tuple_to_strip))

    try:
        response = s.get(OUI_URL)
        response.raise_for_status()
    except RequestException as e:
        raise OUIFetchError("Failed to retrieve data from OUI URL.") from e

    oui_database: OuiDatabaseType = {}

    for match in map(strip_tuple, RE_OUI_ENTRY_PATTERN.findall(response.text)):
        oui = match[0]
        organization_name = match[1]
        company_id = match[2]
        organization_name_bis = match[3]
        address_line_1 = match[4]
        address_line_2 = match[5]
        address_country_iso_code = match[6]

        if oui.replace("-", "").casefold() != company_id.casefold():
            raise ValueError(f"OUI mismatch company ID: '{oui}' != '{company_id}'")

        if organization_name.casefold() != organization_name_bis.casefold():
            raise ValueError(f"Organization names mismatch: '{organization_name}' != '{organization_name_bis}'")

        if not RE_OUI_MAC_ADDRESS_PATTERN.fullmatch(company_id):
            raise ValueError(f"Invalid OUI format: '{company_id}'. Expected exactly 6 hexadecimal characters.")

        entry = {
            "organization_name": organization_name,
            "address_line_1": address_line_1,
            "address_line_2": address_line_2,
            "address_country_iso_code": address_country_iso_code,
        }
        if entry not in oui_database.setdefault(company_id.upper(), []):
            oui_database[company_id.upper()].append(entry)

    return oui_database
