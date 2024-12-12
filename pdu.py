import socket
import struct

class IPHeader:
    """
    Represents an IP header, providing functionality to convert between struct bytes
    and IP header attributes.

    Attributes:
        ip_ver (int): IP version (default: 4).
        ip_ihl (int): Internet Header Length (default: 5).
        ip_tos (int): Type of Service (default: 0).
        ip_tot_len (int): Total length of the IP packet (default: 40 bytes).
        ip_id (int): Identification field (default: 0).
        ip_frag_off (int): Fragment offset field (default: 0).
        ip_ttl (int): Time to Live (default: 255).
        ip_proto (int): Protocol used (default: socket.IPPROTO_RAW).
        ip_check (int): Checksum (initially 0, calculated by the kernel).
        ip_saddr (str): Source IP address (default: '127.0.0.2').
        ip_daddr (str): Destination IP address (default: '127.128.0.1').
    """

    def __init__(self, ip_ver=4, ip_ihl=5, ip_tos=0, ip_tot_len=40, ip_id=0, ip_frag_off=0, 
                 ip_ttl=255, ip_proto=socket.IPPROTO_RAW, ip_check=0, source_ip='127.0.0.2', dest_ip='127.128.0.1'):
        """
        Initializes an IPHeader object with the provided values.

        Args:
            ip_ver (int): IP version.
            ip_ihl (int): Internet Header Length.
            ip_tos (int): Type of Service.
            ip_tot_len (int): Total length of the IP packet.
            ip_id (int): Identification field.
            ip_frag_off (int): Fragment offset field.
            ip_ttl (int): Time to Live.
            ip_proto (int): Protocol used.
            ip_check (int): Checksum.
            source_ip (str): Source IP address.
            dest_ip (str): Destination IP address.
        """
        self.ip_ver = ip_ver
        self.ip_ihl = ip_ihl
        self.ip_tos = ip_tos
        self.ip_tot_len = ip_tot_len
        self.ip_id = ip_id
        self.ip_frag_off = ip_frag_off
        self.ip_ttl = ip_ttl
        self.ip_proto = ip_proto
        self.ip_check = ip_check
        self.ip_saddr = source_ip
        self.ip_daddr = dest_ip

    @classmethod
    def from_bytes(cls, data):
        """
        Parses a bytes object into an IPHeader object.

        Args:
            data (bytes): The byte sequence containing the IP header.

        Returns:
            IPHeader: An instance of IPHeader created from the bytes.

        Raises:
            struct.error: If the byte data is invalid.
        """
        unpacked_ip_header = struct.unpack('!BBHHHBBH4s4s', data[0:20])

        ip_ihl_ver = unpacked_ip_header[0]
        ip_ver = (ip_ihl_ver >> 4) & 0xF
        ip_ihl = ip_ihl_ver & 0xF
        ip_tos = unpacked_ip_header[1]
        ip_tot_len = unpacked_ip_header[2]
        ip_id = unpacked_ip_header[3]
        ip_frag_off = unpacked_ip_header[4]
        ip_ttl = unpacked_ip_header[5]
        ip_proto = unpacked_ip_header[6]
        ip_check = unpacked_ip_header[7]
        ip_saddr = socket.inet_ntoa(unpacked_ip_header[8])
        ip_daddr = socket.inet_ntoa(unpacked_ip_header[9])

        return cls(ip_ver, ip_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)


class LSADatagram(IPHeader):
    """
    Represents an LSA (Link-State Advertisement) datagram that extends an IPHeader.
    """

    def __init__(self, ip_ver=4, ip_ihl=5, ip_tos=0, ip_tot_len=40, ip_id=0, ip_frag_off=0, 
                 ip_ttl=255, ip_proto=socket.IPPROTO_RAW, ip_check=0, source_ip='127.0.0.2', 
                 dest_ip='127.128.0.1', adv_rtr='1.1.1.1', lsa_seq_num=0, lsa_data=''):
        """
        Initializes an LSADatagram with the given attributes, including LSA-specific fields.

        Args:
            adv_rtr (str): Advertising router address.
            lsa_seq_num (int): LSA sequence number.
            lsa_data (str): LSA data.
        """
        super().__init__(ip_ver, ip_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, source_ip, dest_ip)
        self.adv_rtr = adv_rtr
        self.lsa_seq_num = lsa_seq_num
        self.lsa_data = lsa_data

    def to_bytes(self):
        """
        Converts the LSADatagram into bytes for transmission over the network.

        Returns:
            bytes: The byte sequence representing the LSADatagram.
        """
        lsa_header = struct.pack('!4sH', socket.inet_aton(self.adv_rtr), self.lsa_seq_num)
        ip_ihl_ver = (self.ip_ver << 4) + self.ip_ihl
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                ip_ihl_ver, self.ip_tos, self.ip_tot_len, self.ip_id, self.ip_frag_off,
                                self.ip_ttl, self.ip_proto, self.ip_check,
                                socket.inet_aton(self.ip_saddr), socket.inet_aton(self.ip_daddr))

        return ip_header + lsa_header + self.lsa_data.encode()

    @classmethod
    def from_bytes(cls, data):
        """
        Parses a bytes object into an LSADatagram.

        Args:
            data (bytes): The byte sequence containing the LSADatagram.

        Returns:
            LSADatagram: An instance of LSADatagram created from the bytes.

        Raises:
            struct.error: If the byte data is invalid.
        """
        ip_header = IPHeader.from_bytes(data)
        adv_rtr, lsa_seq_num = struct.unpack('!4sH', data[20:26])
        lsa_data = data[26:].decode()

        return cls(ip_ver=ip_header.ip_ver, ip_ihl=ip_header.ip_ihl, ip_tos=ip_header.ip_tos,
                   ip_tot_len=ip_header.ip_tot_len, ip_id=ip_header.ip_id, ip_frag_off=ip_header.ip_frag_off,
                   ip_ttl=ip_header.ip_ttl, ip_proto=ip_header.ip_proto, ip_check=ip_header.ip_check,
                   source_ip=ip_header.ip_saddr, dest_ip=ip_header.ip_daddr, adv_rtr=socket.inet_ntoa(adv_rtr),
                   lsa_seq_num=lsa_seq_num, lsa_data=lsa_data)


class HTTPDatagram(IPHeader):
    """
    Represents an HTTP datagram that extends an IPHeader with TCP-like attributes.
    """

    def __init__(self, ip_ver=4, ip_ihl=5, ip_tos=0, ip_tot_len=40, ip_frag_off=0, 
                 ip_ttl=255, ip_proto=socket.IPPROTO_RAW, ip_check=0, source_ip='127.0.0.2', dest_ip='127.128.0.1',
                 source_port=18000, dest_port=8080, seq_num=0, ack_num=0, data_offset=5, 
                 reserved=0, flags=0, window_size=3, checksum=0, urgent_pointer=0, next_hop='', data=''):
        """
        Initializes an HTTPDatagram with the provided values.

        Args:
            source_port (int): Source port number.
            dest_port (int): Destination port number.
            seq_num (int): Sequence number.
            ack_num (int): Acknowledgment number.
            data_offset (int): Data offset (default is 5).
            reserved (int): Reserved bits (default is 0).
            flags (int): Flags for the TCP segment.
            window_size (int): Window size.
            checksum (int): TCP checksum.
            urgent_pointer (int): Urgent pointer.
            next_hop (str): Next hop address.
            data (str): Data payload.
        """
        super().__init__(ip_ver, ip_ihl, ip_tos, ip_tot_len, 0, ip_frag_off, ip_ttl, ip_proto, ip_check, source_ip, dest_ip)
        self.source_port = source_port
        self.dest_port = dest_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.data_offset = data_offset
        self.reserved = reserved
        self.flags = flags
        self.window_size = window_size
        self.checksum = checksum
        self.urgent_pointer = urgent_pointer
        self.next_hop = next_hop
        self.data = data

    def to_bytes(self):
        """
        Converts the HTTPDatagram into bytes for transmission over the network.

        Returns:
            bytes: The byte sequence representing the HTTPDatagram.
        """
        # Pack the TCP header (along with next hop)
        data_offset_reserved = (self.data_offset << 4) + self.reserved
        tcp_header = struct.pack('!HHLLBBHHH4s',
                                 self.source_port,
                                 self.dest_port,
                                 self.seq_num,
                                 self.ack_num,
                                 data_offset_reserved,
                                 self.flags,
                                 self.window_size,
                                 self.checksum,
                                 self.urgent_pointer,
                                 socket.inet_aton(self.next_hop))
        
        # Pack the IP header
        ip_ihl_ver = (self.ip_ver << 4) + self.ip_ihl
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                ip_ihl_ver,
                                self.ip_tos,
                                self.ip_tot_len,
                                0,  # IP ID set to 0 for now
                                self.ip_frag_off,
                                self.ip_ttl,
                                self.ip_proto,
                                self.ip_check,
                                socket.inet_aton(self.ip_saddr),
                                socket.inet_aton(self.ip_daddr))

        # Combine IP header, TCP header, and the payload (data)
        return ip_header + tcp_header + self.data.encode()

    @classmethod
    def from_bytes(cls, data):
        """
        Parses a bytes object into an HTTPDatagram.

        Args:
            data (bytes): The byte sequence containing the HTTPDatagram.

        Returns:
            HTTPDatagram: An instance of HTTPDatagram created from the bytes.

        Raises:
            struct.error: If the byte data is invalid.
        """
        # Unpack IP header
        unpacked_ip_header = struct.unpack('!BBHHHBBH4s4s', data[0:20])

        ip_ihl_ver = unpacked_ip_header[0]
        ip_tos = unpacked_ip_header[1]
        ip_tot_len = unpacked_ip_header[2]
        ip_frag_off = unpacked_ip_header[4]
        ip_ttl = unpacked_ip_header[5]
        ip_proto = unpacked_ip_header[6]
        ip_check = unpacked_ip_header[7]
        ip_saddr = socket.inet_ntoa(unpacked_ip_header[8])
        ip_daddr = socket.inet_ntoa(unpacked_ip_header[9])

        ip_ver = (ip_ihl_ver >> 4) & 0xF
        ip_ihl = ip_ihl_ver & 0xF

        # Unpack TCP header
        unpacked_tcp_header = struct.unpack('!HHLLBBHHH4s', data[20:44])

        source_port = unpacked_tcp_header[0]
        dest_port = unpacked_tcp_header[1]
        seq_num = unpacked_tcp_header[2]
        ack_num = unpacked_tcp_header[3]
        data_offset_reserved = unpacked_tcp_header[4]
        flags = unpacked_tcp_header[5]
        window_size = unpacked_tcp_header[6]
        checksum = unpacked_tcp_header[7]
        urgent_pointer = unpacked_tcp_header[8]
        next_hop = socket.inet_ntoa(unpacked_tcp_header[9])

        data_offset = (data_offset_reserved >> 4) & 0xF
        reserved = data_offset_reserved & 0xF

        # Extract the payload data
        data = data[44:].decode()

        return cls(ip_ver, ip_ihl, ip_tos, ip_tot_len, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr,
                   source_port, dest_port, seq_num, ack_num, data_offset, reserved, flags, window_size,
                   checksum, urgent_pointer, next_hop, data)