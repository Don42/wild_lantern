import struct

DHCP_MESSAGE_PARSE_STRING = '!ccccIHHIIII6s10s192s4s'

DHCP_MAGIC_BYTES = b'\x63\x82\x53\x63'

DHCP_TAG_PAD = 0x00  # 0
DHCP_TAG_END = 0xff  # 255

DHCP_TAG_SUBNET_MASK = 0x01  # 1
DHCP_TAG_ROUTER_ADDRESSES = 0x03  # 3
DHCP_TAG_DOMAIN_NAME_SERVERS = 0x06  # 6
DHCP_TAG_HOST_NAME = 0x0C  # 12
DHCP_TAG_DOMAIN_NAME = 0x0F  # 15
DHCP_TAG_INTERFACE_MTU = 0x1A  # 26
DHCP_TAG_BROADCAST_ADDRESS = 0x1C  # 28
DHCP_TAG_STATIC_ROUTE = 0x21  # 33
DHCP_TAG_NTP_SERVERS = 0x2A  # 42
DHCP_TAG_REQUESTED_IP_ADDRESS = 0x32  # 50
DHCP_TAG_IP_ADDRESS_LEASE_TIME = 0x33  # 51
DHCP_TAG_OPTION_OVERLOAD = 0x34  # 52
DHCP_TAG_OPTION_OVERLOAD_FILE = 0x01  # 1
DHCP_TAG_OPTION_OVERLOAD_SNAME = 0x02  # 2
DHCP_TAG_OPTION_OVERLOAD_BOTH = 0x03  # 3
DHCP_TAG_MESSAGE_TYPE = 0x35  # 53
DHCP_TAG_MESSAGE_TYPE_DICT = {'DHCPDISCOVER': 0x01,
                              'DHCPOFFER': 0x02,
                              'DHCPREQUEST': 0x03,
                              'DHCPDECLINE': 0x04,
                              'DHCPACK': 0x05,
                              'DHCPNAK': 0x06,
                              'DHCPRELEASE': 0x07,
                              'DHCPINFORM': 0x08}
DHCP_TAG_SERVER_IDENTIFIER = 0x36  # 54
DHCP_TAG_PARAMETER_REQUEST_LIST = 0x37  # 55
DHCP_TAG_MAX_MESSAGE_SIZE = 0x39  # 57
DHCP_TAG_RENEWAL_TIME_VALUE = 0x3A  # 58
DHCP_TAG_REBINDING_TIME_VALUE = 0x3B  # 59
DHCP_TAG_VENDOR_CLASS_ID = 0x3C  # 60
DHCP_TAG_RAPID_COMMIT = 0x50  # 80
DHCP_TAG_AUTO_CONFIGURE = 0x74  # 116
DHCP_TAG_AUTO_CONFIGURE_DO_NOT_AUTO_CONFIGURE = 0x00
DHCP_TAG_AUTO_CONFIGURE_AUTO_CONFIGURE = 0x01
DHCP_TAG_DOMAIN_SEARCH = 0x77  # 119
DHCP_TAG_CLASSLESS_STATIC_ROUTE = 0x79  # 121
DHCP_TAG_FORCERENEW_NONCE_CAPABLE = 0x91  # 145


class DHCPMessage:
    def __init__(self, op_code, h_type, h_len, hops, xid, seconds, flags, c_i_addr, y_i_addr, s_i_addr,
                 g_i_addr, c_h_addr, server_name, boot_file, options):
        self.operation_code_raw = op_code
        self.hardware_addr_type_raw = h_type
        self.hardware_addr_length_raw = h_len
        self.hops_raw = hops
        self.transaction_id_raw = xid
        self.seconds_raw = seconds
        self.flags_raw = flags
        self.client_ip_address_raw = c_i_addr
        self.your_ip_address_raw = y_i_addr
        self.server_ip_address_raw = s_i_addr
        self.gateway_ip_address_raw = g_i_addr
        self.client_hw_address_raw = c_h_addr
        self.server_name_raw = server_name
        self.boot_file_raw = boot_file
        self.options_raw = options


class DHCPException(Exception):
    pass


class ParserError(Exception):
    pass


def parse_dhcp_request(package):
    package_parser = struct.Struct(DHCP_MESSAGE_PARSE_STRING)
    message_data = package_parser.unpack_from(package)
    if message_data[14] != DHCP_MAGIC_BYTES:  # This starts the options block
        raise ParserError("DHCP Magic Bytes not found")
    dhcp_options = _parse_dhcp_request_options(package[package_parser.size:])
    dhcp_request = DHCPMessage(*message_data[:14], dhcp_options)
    return dhcp_request


def _parse_dhcp_request_options(message_raw_options):
    dhcp_options = dict()
    offset = 0
    while len(message_raw_options) > offset:
        option_type = struct.unpack_from('!B', message_raw_options, offset=offset)[0]
        if option_type == DHCP_TAG_END:
            break
        elif option_type == DHCP_TAG_PAD:
            offset += 1
            continue

        offset += 1
        option_length = struct.unpack_from('!B', message_raw_options, offset=offset)[0]
        offset += 1
        assert isinstance(option_length, int)
        assert option_length + offset < len(message_raw_options)

        option_data = struct.unpack_from('!{}s'.format(option_length), message_raw_options, offset=offset)[0]
        offset += option_length

        dhcp_options[option_type] = option_data
    return dhcp_options
