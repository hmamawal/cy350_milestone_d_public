import socket
import json
from pdu import HTTPDatagram, IPHeader
from pathlib import Path
from datetime import datetime
from random import choices

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
        self.base_path = Path(__file__).parent
        self.resources_path = self.base_path / 'resources.json'
        with open(self.resources_path, 'r') as f:
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
                print(f"receive_request_segments in tcp_server - datagram_fields: {datagram_fields}")
                if datagram_fields.next_hop == self.server_ip and datagram_fields.flags in [24, 25]:
                    # print datagra_fields.seq_num and self.ack_num
                    print(f"receive_request_segments in tcp_server - datagram_fields.seq_num: {datagram_fields.seq_num}")
                    print(f"receive_request_segments in tcp_server - self.ack_num: {self.ack_num}")
                    if datagram_fields.seq_num == self.ack_num:
                        self.ack_num += 1
                        request += datagram_fields.data
                        print(f"receive_request_segments in tcp_server - request: {request}")
                    else:
                        print(f"!!! ACK mismatch: seq_num={datagram_fields.seq_num}, expected ack_num={self.ack_num}")
                    # Send acknowledgment
                    ack = HTTPDatagram(
                        source_ip=self.server_ip, dest_ip=datagram_fields.ip_saddr,
                        source_port=self.server_port, dest_port=datagram_fields.source_port,
                        seq_num=self.seq_num, ack_num=self.ack_num, flags=16,
                        window_size=self.window_size, next_hop=self.gateway, data='ACK'
                    )
                    print(f"receive_request_segments in tcp_server - ack: {ack}, datagram_fields.seq_num: {datagram_fields.seq_num}, self.ack_num: {self.ack_num}")
                    self.server_socket.sendto(ack.to_bytes(), (self.gateway, 0))

        return request, datagram_fields.source_port, datagram_fields.ip_saddr
    
    def newRandomETag(self):
        # found random.choices from https://www.w3schools.com/python/ref_random_choices.asp
        # found .join from https://www.freecodecamp.org/news/python-join-how-to-combine-a-list-into-a-string-in-python/
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        digits = "0123456789"
        result = ''.join(choices(alphabet, k=3)) + ''.join(choices(digits, k=3)) 
        print(f"newRandomETag - new ETag: {result}")
        return result
    def add_json_entry(self, file_path, key, entry): # added this function to add a new entry to the resources.json file; from: https://chatgpt.com/share/675a4f94-a71c-8003-ba56-a39625a5bc09
        """
        Adds a new entry to a JSON file.
        
        :param file_path: Path to the JSON file.
        :param key: The key for the new entry.
        :param entry: A dictionary containing the new entry data.
        """
        # Load the JSON file
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Add the new entry
        data[key] = entry
        
        # Write the updated data back to the JSON file
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"Entry added for key: {key}")

    def process_request(self, request, dest_port, dest_ip):
        """
        Processes the client's HTTP GET request and prepares the appropriate response.

        Args:
            request (str): The client's HTTP request.
            dest_port (int): The client's source port.
            dest_ip (str): The client's source IP address.
        """

        """
        when receiving, this is what POST looks like:

        POST /resource HTTP/1.1
        Host: <server>
        Content-Length: <length of data>
        <data>

        AND here is a post response example

        HTTP/1.1 200 OK
        Content-Type: text/plain
        POST request successfully received.
        """
        """
        when receiving, this is what GET looks like:

        GET /resource HTTP/1.1
        Host: <server>
        If-Modified-Since: <timestamp> (optional)
        """
        request_lines = request.split('\r\n')
        print(f"request_lines: {request_lines}")

        first_line = request_lines[0].split()
        print(f"first_line: {first_line}")

        method = first_line[0]
        print(f"method: {method}")

        resource = first_line[1]
        print(f"resource: {resource}")

        # ensure that if a POST request is made to a resource that exists in the resources.json file, a different resource name is given so that a POST request can still go through.
        if resource in self.resources and method == "POST":
            print(f"resource exists in resources.json file")
            resource = '/new_resource.html'

        modified_since = None

        content_length = None
        post_content = ''

        flags = 17  # Default flags for error response

        # Handle HTTP GET requests and validate requested resource
        if method != "GET" and method != "POST":
            data = "HTTP/1.1 400 Bad Request\r\n\r\nInvalid Request"
        elif resource not in self.resources and method == "GET":
            data = "HTTP/1.1 404 Not Found\r\n\r\nResource Not Found"
        else:
            # Check for If-Modified-Since header
            for line in request_lines[1:]:
                if line.startswith("If-Modified-Since:"):
                    modified_since = line.split(":", 1)[1].strip()
                    break
                #elif line.startswith("Content-Length:"):
                    #content_length = int(line.split(":", 1)[1].strip())
                    #break

            if modified_since:
                resource_info = self.resources[resource]
                modified_since_time = datetime.strptime(modified_since, "%a, %d %b %Y %H:%M:%S GMT")
                last_modified_time = datetime.strptime(resource_info['last_modified'], "%a, %d %b %Y %H:%M:%S GMT")
                if last_modified_time <= modified_since_time:
                    data = "HTTP/1.1 304 Not Modified\r\n\r\n"
                else:
                    data = f"HTTP/1.1 200 OK\r\nContent-Length: {len(resource_info['data'])}\r\n\r\n" + resource_info['data']
                    flags = 24 # Set ACK and PSH flags for valid response
            elif method == "POST":
                data = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nPOST request successfully received."
                data += "\r\n\r\n"
                flags = 24
                post_content += request_lines[-1]
                new_resource = {
                    "last_modified": datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT"),
                    "file_size": len(post_content),
                    "etag":self.newRandomETag(),
                    "data": post_content
                }

                # add the post content to the resources.json file (should be a new entry into the dictionary)
                self.resources[resource] = new_resource

                # write the new resources to the resources.json file
                self.add_json_entry(self.resources_path, resource, new_resource) # added this line to write the new entry to the resources.json file; https://chatgpt.com/share/675a4f94-a71c-8003-ba56-a39625a5bc09  

                # confirm the new entry was added to the resources.json file with print statement
                if resource in self.resources:
                    print(f"!!!resource added to resources.json file")
                else:
                    print(f"!!!resource not added to resources.json file")
                
            else:
                data = f"HTTP/1.1 200 OK\r\nContent-Length: {len(resource_info['data'])}\r\n\r\n" + resource_info['data']
                flags = 24  # Set ACK and PSH flags for valid response
        # Send the response in segments using Go-Back-N
        try:
            print(f"in tcp_server process_request function - Sending response: {data}")
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