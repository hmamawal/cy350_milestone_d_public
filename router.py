import time
import socket
import logging
from pdu import IPHeader, LSADatagram, HTTPDatagram
from graph import Graph

class Router:
    def __init__(self, router_id: str, router_interfaces: dict, direct_connections: dict):
        """
        Initializes a Router object.

        Args:
            router_id (str): Unique identifier for the router.
            router_interfaces (dict): A dictionary of router interfaces in the form {interface_name: (source_ip, dest_ip)}.
            direct_connections (dict): A dictionary of directly connected networks in the form {network: (cost, interface)}.

        Raises:
            Exception: If a socket fails to initialize.
        """
        self.router_id = router_id  
        self.router_interfaces = router_interfaces
        self.direct_connections = direct_connections
        self.lsa_seq_num = 0
        self.interface_sockets = {}
        
        # Initialize sockets for each interface
        for interface, (source, _) in self.router_interfaces.items():
            try:
                int_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                int_socket.bind((source, 0))
                int_socket.setblocking(False)
                self.interface_sockets[interface] = int_socket
            except Exception as e:
                logging.error(f'Error creating socket for {interface}: {e}')

        # Create a socket for receiving datagrams
        receive_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        receive_socket.bind(('0.0.0.0', 0))
        receive_socket.setblocking(False)
        self.interface_sockets['rec'] = receive_socket

        # Initialize LSA database, timers, and forwarding table
        self.router_lsa_num = {}
        self.lsdb = {}
        self.lsa_timer = time.time()
        self.forwarding_table = {}

        # Configure logging
        logging.basicConfig(level=logging.INFO,
                            format='%(levelname)s - %(message)s',
                            handlers=[logging.FileHandler('network_app_router.log', mode='w')]
                            )

        self.initialize_lsdb()

    def initialize_lsdb(self):
        """
        Initializes the Link-State Database (LSDB) with the router's direct connections.
        
        The LSDB is a data structure that holds information about the router's directly connected networks
        and the cost of reaching them.
        
        Returns:
            None
        """
        self.lsdb[self.router_id] = [(dst, cost, iface) for dst, (cost, iface) in self.direct_connections.items()]

    def update_lsdb(self, adv_rtr: str, lsa: str):
        """
        Updates the Link-State Database (LSDB) with new information from a received LSA.

        Args:
            adv_rtr (str): The advertising router's ID.
            lsa (str): The LSA data as a string, where each line contains the neighbor, cost, and interface information.

        Returns:
            None
        """
        lsa = [tuple(line.split(',')) for line in lsa.split('\r\n')]
        self.lsdb[adv_rtr] = [(neighbor.strip(), int(cost.strip()), interface.strip()) for neighbor, cost, interface in lsa]

    def send_initial_lsa(self):
        """
        Broadcasts the initial Link-State Advertisement (LSA) containing the router's direct connections to all interfaces.

        Returns:
            None

        Logs:
            Logs the sending of the initial LSA.
        """
        for interface, (source, dest) in self.router_interfaces.items():
            int_socket = self.interface_sockets[interface]
            formatted_lsa_data = [f'{neighbor}, {cost}, {interface}' for neighbor, cost, interface in self.lsdb[self.router_id]]
            new_datagram = LSADatagram(source_ip=source, dest_ip='224.0.0.5', adv_rtr=self.router_id, lsa_seq_num=self.lsa_seq_num, lsa_data='\r\n'.join(formatted_lsa_data))
            int_socket.sendto(new_datagram.to_bytes(), (dest, 0))
        logging.info(f'{self.router_id} has sent the initial LSA.')

    def forward_lsa(self, lsa_datagram: LSADatagram, lsa_int: str):
        """
        Forwards a received LSA to all interfaces except the one on which it was received.

        Args:
            lsa_datagram (LSADatagram): The received LSA datagram to be forwarded.
            lsa_int (str): The interface on which the LSA was received.

        Returns:
            None

        Logs:
            Logs the forwarding of the LSA to the destination.
        
        Exceptions:
            Logs any exceptions that occur during forwarding.
        """
        time.sleep(1) # Make sure all initial LSAs are sent before forwarding an LSA
        for interface in self.router_interfaces:
            if interface != lsa_int and lsa_datagram.adv_rtr != self.router_id:
                source, dest = self.router_interfaces[interface]
                int_socket = self.interface_sockets[interface]
                new_datagram = LSADatagram(source_ip=source, dest_ip='224.0.0.5', adv_rtr=lsa_datagram.adv_rtr, lsa_seq_num=lsa_datagram.lsa_seq_num, lsa_data=lsa_datagram.lsa_data)
                try:
                    int_socket.sendto(new_datagram.to_bytes(), (dest, 0))
                    logging.info(f'{self.router_id}: LSA forwarded to {dest}.')
                except Exception as e:
                    logging.error(f'Error forwarding LSA: {e}')

    def run_route_alg(self):
        """
        Runs Dijkstra's shortest path algorithm to calculate the shortest paths to all nodes
        in the network and updates the forwarding table based on the LSDB.

        Returns:
            None

        Raises:
            None
        """
        graph = Graph()
        for node, neighbors in self.lsdb.items():
            for neighbor, cost, interface in neighbors:
                graph.add_edge(node, neighbor, cost, interface)

        # Initialize Dijkstra's algorithm
        N_prime = {self.router_id}
        D = {node: float('inf') for node in graph.nodes}
        D[self.router_id] = 0
        previous_nodes = {node: (None, None) for node in graph.nodes}
        paths = {node: [] for node in graph.nodes}

        # Update initial neighbors
        for neighbor, cost, interface in graph.nodes[self.router_id]:
            D[neighbor] = cost
            previous_nodes[neighbor] = (self.router_id, interface)
            paths[neighbor] = [(neighbor, interface)]

        # Dijkstra's algorithm
        while len(N_prime) < len(graph.nodes):
            w = min((node for node in D if node not in N_prime), key=D.get)
            N_prime.add(w)
            for neighbor, cost, interface in graph.nodes[w]:
                if neighbor not in N_prime:
                    new_distance = D[w] + cost
                    if new_distance < D[neighbor]:
                        D[neighbor] = new_distance
                        previous_nodes[neighbor] = (w, interface)
                        paths[neighbor] = paths[w] + [(neighbor, interface)]

        # Update forwarding table
        self.forwarding_table = {node: (paths[node][0][1] if paths[node] else None, D[node]) for node in graph.nodes}

    def process_datagrams(self):
        """
        Receives, processes, and forwards incoming datagrams or LSAs. It updates the LSDB and forwarding table as needed,
        and then forwards datagrams to their correct next hop.

        Returns:
            None

        Logs:
            Logs the content of the LSDB and forwarding table.
        """
        while time.time() - self.lsa_timer < 5:
            for interface in self.interface_sockets.keys():
                try:
                    new_datagram_bytes, address = self.interface_sockets[interface].recvfrom(1024)
                    new_datagram = IPHeader.from_bytes(new_datagram_bytes)
                    if new_datagram.ip_daddr == '224.0.0.5' and address[0] in [connection[1] for connection in self.router_interfaces.values()]:
                        self.process_link_state_advertisement(new_datagram_bytes, interface)
                except Exception:
                    continue               
        self.run_route_alg()
        time.sleep(1)
        start_time = time.time()
        while time.time() - start_time < 10:
            for interface in self.interface_sockets.keys():
                try:
                    new_datagram_bytes, _ = self.interface_sockets[interface].recvfrom(1024)
                    self.forward_datagram(new_datagram_bytes)
                except Exception:
                    continue

        logging.info(f'{self.router_id} LSDB: {self.lsdb}')
        logging.info(f'{self.router_id} Forwarding Table: {self.forwarding_table}')
        self.shutdown()

    def process_link_state_advertisement(self, lsa: bytes, interface: str):
        """
        Processes a received Link-State Advertisement (LSA) and updates the LSDB. If the LSA contains new information, 
        the router broadcasts the LSA to its other interfaces.

        Args:
            lsa (bytes): The received LSA in byte form.
            interface (str): The interface on which the LSA was received.

        Returns:
            None

        Raises:
            None
        """
        datagram = LSADatagram.from_bytes(lsa)
        adv_rtr = datagram.adv_rtr
        lsa_seq_num = datagram.lsa_seq_num

        # Process only if it's a newer LSA and not from the router itself
        if (adv_rtr not in self.router_lsa_num or self.router_lsa_num[adv_rtr] < lsa_seq_num) and adv_rtr != self.router_id:
            self.lsa_timer = time.time()  # Reset the LSA timer
            self.router_lsa_num[adv_rtr] = lsa_seq_num  # Update sequence number
            self.update_lsdb(adv_rtr, datagram.lsa_data)  # Update LSDB
            self.forward_lsa(datagram, interface)  # Forward the LSA to other interfaces

    def forward_datagram(self, dgram: bytes):
        """
        Forwards an HTTP datagram to the appropriate next hop based on the forwarding table.

        Args:
            dgram (bytes): The datagram received as raw bytes.

        Returns:
            None

        Logs:
            Logs the process of forwarding the datagram to the appropriate next hop.

        Raises:
            Exception: Logs any errors during the forwarding process.
        """
        datagram = HTTPDatagram.from_bytes(dgram)

        if datagram.next_hop in [connection[0] for connection in self.router_interfaces.values()]: # make sure the datagram was intended for this router

            # Convert destination IP address to binary for longest prefix matching
            dest_ip_binary = ''.join(f'{int(octet):08b}' for octet in datagram.ip_daddr.split('.'))
            longest_prefix = None
            max_length = -1

            # Perform longest prefix match against known networks
            for network in self.forwarding_table.keys():
                try:
                    if '/' in network:
                        network_addr, prefix_length = network.split('/')
                        prefix_length = int(prefix_length)
                        network_addr_binary = ''.join(f'{int(octet):08b}' for octet in network_addr.split('.'))

                        matching_bits = 0

                        for index in range(prefix_length):
                            if dest_ip_binary[index] == network_addr_binary[index]:
                                matching_bits += 1
                            else:
                                break
                        
                        if matching_bits > max_length:
                            max_length = matching_bits
                            longest_prefix = network

                except Exception as e:
                    logging.error(f'Error while performing longest prefix match: {e}')

            # Forward the datagram to the correct interface
            if longest_prefix:
                fwd_int = self.forwarding_table[longest_prefix][0]  # Find forwarding interface

                # Prepare datagram for forwarding
                fwd_socket = self.interface_sockets[fwd_int]
                fwd_dgram = HTTPDatagram(
                    source_ip=datagram.ip_saddr,
                    dest_ip=datagram.ip_daddr,
                    source_port=datagram.source_port,
                    dest_port=datagram.dest_port,
                    seq_num=datagram.seq_num,
                    ack_num=datagram.ack_num,
                    flags=datagram.flags,
                    window_size=datagram.window_size,
                    next_hop=self.router_interfaces[fwd_int][1],
                    data=datagram.data
                )
                fwd_dgram_bytes = fwd_dgram.to_bytes()

                try:
                    # Forward the datagram to the next hop
                    fwd_socket.sendto(fwd_dgram_bytes, (self.router_interfaces[fwd_int][1], 0))
                    logging.info(f'{self.router_id}: Forwarding packet to {self.router_interfaces[fwd_int][1]}.')
                except Exception as e:
                    logging.error(f'Error forwarding the datagram: {e}')

    def shutdown(self):
        """
        Shuts down the router by closing all open sockets.

        Returns:
            None

        Logs:
            Logs the shutdown process of the router.
        """
        # Close all interface sockets
        for interface in self.interface_sockets.keys():
            try:
                self.interface_sockets[interface].close()
            except Exception as e:
                logging.error(f'Error closing socket for {interface}: {e}')

# Example usage
if __name__ == "__main__":
    r1_interfaces = {
        'Gi0/1': ('127.0.0.254', '127.0.0.1'), 
        'Gi0/2': ('127.248.0.1', '127.248.0.2'),
        'Gi0/3': ('127.248.4.1', '127.248.4.2')
    }
    
    r1_direct_connections = {
        '127.0.0.0/24': (0, 'Gi0/1'),
        '2.2.2.2': (3, 'Gi0/2'), 
        '3.3.3.3': (9, 'Gi0/3')
    }
    
    R1 = Router('1.1.1.1', r1_interfaces, r1_direct_connections)
    R1.shutdown()
