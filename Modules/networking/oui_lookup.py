# Local Python Libraries (Included with Project)
from Modules.constants.standalone import OUI_URL
from Modules.constants.standard import RE_OUI_MAC_ADDRESS_PATTERN, RE_OUI_ENTRY_PATTERN
from Modules.networking.unsafe_https import s
from Modules.networking.utils import is_mac_address, get_mac_oui


class FetchError(Exception):
    pass

class InvalidMacError(Exception):
    pass

class MacLookup():
    def __init__(self, bypass_fetch_error=False):
        try:
            self.oui_database = fetch_and_parse_oui_database()
        except FetchError:
            if not bypass_fetch_error:
                raise
            self.oui_database = {}

    def lookup(self, mac_address: str):
        if not is_mac_address(mac_address):
            raise InvalidMacError(
                f"Invalid MAC address: {mac_address}\n"
                 "A MAC address must be 12-digit hexadecimal number long."
            )

        oui = get_mac_oui(mac_address)
        if oui in self.oui_database:
            return self.oui_database[oui]
        return None


def fetch_and_parse_oui_database():
    def strip_tuple(tuple_to_strip: tuple):
        return tuple(map(str.strip, tuple_to_strip))

    try:
        response = s.get(OUI_URL)
    except Exception as e:
        # TODO:
        raise FetchError("Failed to retrieve data from OUI URL.") from e

    oui_database: dict[str, list[dict[str, str]]] = {}

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
            "address_country_iso_code": address_country_iso_code
        }
        if entry not in oui_database.setdefault(company_id.upper(), []):
            oui_database[company_id.upper()].append(entry)

    return oui_database
