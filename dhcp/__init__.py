import struct
import collections

DHCP_TAG_PAD = 0x00

DHCP_TAG_END = 0xff

DHCP_MESSAGE_PARSE_STRING = '!ccccIHHIIII6s10s192s4s'

DHCP_MAGIC_BYTES = b'\x63\x82\x53\x63'


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
