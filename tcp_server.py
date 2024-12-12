import socket
import json
from pdu import HTTPDatagram, IPHeader
from pathlib import Path
from datetime import datetime

class Server:
    """
    Represents a custom HTTP-like server using raw sockets. It handles connection requests,
    processes HTTP GET requests, and sends segmented responses using a Go-Back-N protocol.

    Attributes:
        server_ip (str): The server's IP address.
        gateway (str): The server's gateway IP address.
        server_port (int): The server's listening port.
        frame_size (int): Maximum frame size for transmitting data.
        window_size (int): Window size for the Go-Back-N protocol.
        timeout (int): Timeout for the server's socket operations.
        resources (dict): Dictionary containing available resources and metadata.
        base (int): Base sequence number for Go-Back-N protocol.
        seq_num (int): Current sequence number.
        ack_num (int): Current acknowledgment number.
    """

    def __init__(self, server_ip='127.128.0.1', gateway='127.128.0.254', server_port=8080, frame_size=1024, window_size=4, timeout=5):
        """
        Initializes the server with IP address, gateway, port, and network settings.

        Args:
            server_ip (str): Server's IP address.
            gateway (str): Server's gateway IP.
            server_port (int): Port on which the server listens.
            frame_size (int): Maximum size of each frame (default: 1024 bytes).
            window_size (int): Window size for Go-Back-N (default: 4).
            timeout (int): Timeout for socket operations (default: 5 seconds).
        """
        self.server_ip = server_ip
        self.server_port = server_port
        self.gateway = gateway

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.server_socket.bind((self.server_ip, 0))

        self.frame_size = frame_size
        self.window_size = window_size
        self.timeout = timeout
        self.base = 0
        self.seq_num = 0
        self.ack_num = 0

        # Load server resources from a JSON file
        base_path = Path(__file__).parent
        resources_path = base_path / 'resources.json'
        with open(resources_path, 'r') as f:
            self.resources = json.load(f)

    def accept_handshake(self):
        """
        Handles the three-way handshake for establishing a connection with a client.

        Returns:
            bool: True if the handshake is successful, False otherwise.
        """
        syn = False
        while not syn:
            frame = self.server_socket.recv(self.frame_size)
            if IPHeader.from_bytes(frame).ip_daddr != '224.0.0.5':
                datagram_fields = HTTPDatagram.from_bytes(frame)

                if datagram_fields.flags == 2 and datagram_fields.next_hop == self.server_ip:
                    syn = True
                    self.window_size = min(self.window_size, datagram_fields.window_size)
                    self.ack_num = datagram_fields.seq_num + 1

        # Step 2: Send SYN/ACK
        self.server_socket.settimeout(self.timeout)
        syn_ack_datagram = HTTPDatagram(
            source_ip=self.server_ip, dest_ip=datagram_fields.ip_saddr,
            source_port=self.server_port, dest_port=datagram_fields.source_port,
            seq_num=self.seq_num, ack_num=self.ack_num, flags=18, window_size=self.window_size,
            next_hop=self.gateway, data='SYN-ACK'
        )
        self.server_socket.sendto(syn_ack_datagram.to_bytes(), (self.gateway, 0))
        self.seq_num += 1

        # Step 3: Receive ACK
        ack = False
        while not ack:
            try:
                frame = self.server_socket.recv(self.frame_size)
            except socket.timeout:
                self.reset_connection()
                return False
            
            if IPHeader.from_bytes(frame).ip_daddr != '224.0.0.5':
                datagram_fields = HTTPDatagram.from_bytes(frame)
                if datagram_fields.flags == 16 and datagram_fields.ack_num == self.seq_num and datagram_fields.next_hop == self.server_ip:
                    ack = True
                    return True
        return False

    def receive_request_segments(self):
        """
        Receives the segmented request from the client, reassembling it into a full request.

        Returns:
            tuple: The reassembled request string, the source port, and the source IP address.
        """
        self.server_socket.settimeout(None)
        request = ''

        while request[-4:] != '\r\n\r\n':  # End of HTTP request
            frame = self.server_socket.recv(self.frame_size)
            frame_bytes = IPHeader.from_bytes(frame)
            if frame_bytes.ip_daddr == self.server_ip:
                datagram_fields = HTTPDatagram.from_bytes(frame)
                if datagram_fields.next_hop == self.server_ip and datagram_fields.flags in [24, 25]:
                    if datagram_fields.seq_num == self.ack_num:
                        self.ack_num += 1
                        request += datagram_fields.data
                    # Send acknowledgment
                    ack = HTTPDatagram(
                        source_ip=self.server_ip, dest_ip=datagram_fields.ip_saddr,
                        source_port=self.server_port, dest_port=datagram_fields.source_port,
                        seq_num=self.seq_num, ack_num=self.ack_num, flags=16,
                        window_size=self.window_size, next_hop=self.gateway, data='ACK'
                    )
                    self.server_socket.sendto(ack.to_bytes(), (self.gateway, 0))

        return request, datagram_fields.source_port, datagram_fields.ip_saddr

    def process_request(self, request, dest_port, dest_ip):
        """
        Processes the client's HTTP GET request and prepares the appropriate response.

        Args:
            request (str): The client's HTTP request.
            dest_port (int): The client's source port.
            dest_ip (str): The client's source IP address.
        """
        request_lines = request.split('\r\n')
        first_line = request_lines[0].split()
        method = first_line[0]
        resource = first_line[1]
        modified_since = None
        flags = 17  # Default flags for error response

        # Handle HTTP GET requests and validate requested resource
        if method != "GET":
            data = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid Request"
        elif resource not in self.resources:
            data = "HTTP/1.1 404 Not Found\r\n\r\nResource Not Found"
        else:
            # Check for If-Modified-Since header
            for line in request_lines[1:]:
                if line.startswith("If-Modified-Since:"):
                    modified_since = line.split(":", 1)[1].strip()
                    break

            resource_info = self.resources[resource]
            if modified_since:
                modified_since_time = datetime.strptime(modified_since, "%a, %d %b %Y %H:%M:%S GMT")
                last_modified_time = datetime.strptime(resource_info['last_modified'], "%a, %d %b %Y %H:%M:%S GMT")
                if last_modified_time <= modified_since_time:
                    data = "HTTP/1.1 304 Not Modified\r\n\r\n"
                else:
                    data = f"HTTP/1.1 200 OK\r\nContent-Length: {len(resource_info['data'])}\r\n\r\n" + resource_info['data']
                    flags = 24 # Set ACK and PSH flags for valid response
            else:
                data = f"HTTP/1.1 200 OK\r\nContent-Length: {len(resource_info['data'])}\r\n\r\n" + resource_info['data']
                flags = 24  # Set ACK and PSH flags for valid response
        # Send the response in segments using Go-Back-N
        try:
            response_bytes = data.encode()
            max_data_length = self.frame_size - 60  # Assuming headers take 60 bytes
            segments = [response_bytes[i:i + max_data_length] for i in range(0, len(response_bytes), max_data_length)]
        
            init_seq_num = self.seq_num
            while self.base < len(segments):
                for segment in segments[self.base:min(len(segments), self.base + self.window_size)]:
                    if self.seq_num - init_seq_num == len(segments) - 1 and flags == 24:
                        flags = 25  # Set FIN flag on the last segment
                    new_datagram = HTTPDatagram(
                        source_ip=self.server_ip, dest_ip=dest_ip,
                        source_port=self.server_port, dest_port=dest_port,
                        seq_num=self.seq_num, ack_num=self.ack_num, flags=flags,
                        window_size=self.window_size, next_hop=self.gateway, data=segment.decode()
                    )
                    self.server_socket.sendto(new_datagram.to_bytes(), (self.gateway, 0))
                    self.seq_num += 1

                # Process acknowledgments
                while self.base < len(segments):
                    try:
                        frame = self.server_socket.recv(self.frame_size)
                    except socket.timeout:
                        self.seq_num = self.base + init_seq_num  # Retransmit on timeout
                        break

                    datagram_fields = HTTPDatagram.from_bytes(frame)
                    # Confirm frame is meant for this application and is an ACK for the oldest sent packet
                    if (datagram_fields.next_hop == self.server_ip) and (datagram_fields.ip_saddr == dest_ip) and (datagram_fields.flags == 16) and (datagram_fields.ack_num == self.base + init_seq_num + 1):
                        # send another segment (base + window_size) if necessary
                        if self.base + self.window_size < len(segments):
                            segment = segments[self.base + self.window_size]
                            if self.base == min(len(segments), self.base + self.window_size) - 1 and flags == 24:
                                flags = 25
                            new_datagram = HTTPDatagram(source_ip=self.server_ip, dest_ip=dest_ip, source_port=self.server_port, dest_port=dest_port, seq_num=self.seq_num, ack_num=self.ack_num, flags=flags, window_size=self.window_size, next_hop=self.gateway, data=segment.decode())
                            datagram_bytes = new_datagram.to_bytes()
                            self.server_socket.sendto(datagram_bytes, (self.gateway, 0))
                            self.seq_num += 1
                        # increment base
                        self.base += 1
                    
        except Exception as e:
            print(f'Error while sending response: {e}')

    def reset_connection(self):
        """
        Resets the server's connection state (sequence numbers, base, and acknowledgment).
        """
        self.base = 0
        self.seq_num = 0
        self.ack_num = 0
        self.server_socket.settimeout(None)

    def close_server(self):
        """
        Closes the server's raw socket.
        """
        self.server_socket.close()

    def run_server(self, request_list=None):
        """
        Runs the server, accepting handshake, receiving requests, and processing responses.

        Args:
            request_list (list, optional): List to append incoming requests (used for debugging).
        """
        connected = self.accept_handshake()
        if connected:
            request, port, ip = self.receive_request_segments()
            print(request)
            if request_list is not None:
                request_list.append(request)
            self.process_request(request, port, ip)
        self.reset_connection()


if __name__ == "__main__":
    server = Server(frame_size=64)
    server.run_server()