import threading
import time
from tcp_client import Client
from router import Router
from tcp_server import Server

class NetworkApp:
    """
    Represents a network application that simulates a network of routers, a web server, 
    and a client interacting in a network environment. The application uses threads to 
    manage the concurrent activities of routers processing datagrams and the server-client interaction.

    Attributes:
        routers (list): A list of `Router` objects that form the network.
        web_server (Server): The web server instance that responds to client requests.
        svr_thread (threading.Thread): A thread to run the server concurrently.
        web_client (Client): The client instance that sends requests to the server.
    """

    def __init__(self, router_data):
        """
        Initializes the NetworkApp with a set of routers and a server.

        Args:
            router_data (list): A list of tuples containing interface and direct connection data for each router.
        """
        self.routers = []
        router_id = 1

        # Create Router instances
        for interfaces, direct_connections in router_data:
            self.routers.append(Router(f'{router_id}.{router_id}.{router_id}.{router_id}', interfaces, direct_connections))
            router_id += 1
        print('The routers have been created!')

        # Create and run the server in a separate thread
        self.web_server = Server()
        self.svr_thread = threading.Thread(target=self.web_server.run_server)
        self.svr_thread.start()
        print('The web server is running!')

    def run_app(self):
        """
        Runs the network application, which includes starting routers, sending link-state advertisements,
        creating a client to request resources, and handling server-client interaction.
        """
        # Start routers in separate threads
        router_threads = []
        for router in self.routers:
            rtr_thread = threading.Thread(target=router.process_datagrams)
            router_threads.append(rtr_thread)
            rtr_thread.start()

        # Routers send initial link-state advertisements
        for router in self.routers:
            router.send_initial_lsa()

        time.sleep(15)  # Allow routers time to exchange LSAs and update their forwarding tables
        print('Routers are ready.')

        # Create and run the client
        self.web_client = Client()
        print('The web client is ready to send the request.')

        # Client requests a resource from the server
        self.web_client.request_resource('/index.html')
        print('The web client has requested and received the resource.')

        time.sleep(1)  # Allow routers and client to complete processing

        # Ensure all router threads finish their tasks
        for thread in router_threads:
            thread.join()

        # Shut down the server and close sockets
        self.web_server.close_server()
        print('The network application is shutdown!')


if __name__ == "__main__":
    # Define router interfaces and direct connections
    router_int_con = [
        ({'Gi0/1': ('127.0.0.254', '127.0.0.1'),
          'Gi0/2': ('127.248.0.1', '127.248.0.2'),
          'Gi0/3': ('127.248.4.1', '127.248.4.2')},
         {'127.0.0.0/24': (0, 'Gi0/1'),
          '2.2.2.2': (3, 'Gi0/2'),
          '3.3.3.3': (9, 'Gi0/3')}),

        ({'Gi0/1': ('127.248.0.2', '127.248.0.1'),
          'Gi0/2': ('127.30.0.254', '127.30.0.1'),
          'Gi0/3': ('127.248.12.1', '127.248.12.2'),
          'Gi0/4': ('127.248.8.1', '127.248.8.2')},
         {'127.30.0.0/24': (0, 'Gi0/2'),
          '1.1.1.1': (3, 'Gi0/1'),
          '3.3.3.3': (5, 'Gi0/4'),
          '4.4.4.4': (12, 'Gi0/3')}),

        ({'Gi0/1': ('127.248.4.2', '127.248.4.1'),
          'Gi0/2': ('127.248.8.2', '127.248.8.1'),
          'Gi0/3': ('127.248.16.1', '127.248.16.2'),
          'Gi0/4': ('127.10.0.254', '127.10.0.1')},
         {'127.10.0.0/24': (0, 'Gi0/4'),
          '1.1.1.1': (9, 'Gi0/1'),
          '2.2.2.2': (5, 'Gi0/2'),
          '5.5.5.5': (10, 'Gi0/3')}),

        ({'Gi0/1': ('127.248.12.2', '127.248.12.1'),
          'Gi0/2': ('127.40.0.254', '127.40.0.1'),
          'Gi0/3': ('127.248.24.1', '127.248.24.2'),
          'Gi0/4': ('127.248.20.1', '127.248.20.2')},
         {'127.40.0.0/24': (0, 'Gi0/2'),
          '2.2.2.2': (12, 'Gi0/1'),
          '5.5.5.5': (4, 'Gi0/4'),
          '6.6.6.6': (10, 'Gi0/3')}),

        ({'Gi0/1': ('127.248.16.2', '127.248.16.1'),
          'Gi0/2': ('127.248.20.2', '127.248.20.1'),
          'Gi0/3': ('127.248.28.1', '127.248.28.2')},
         {'127.20.0.0/24': (0, 'Gi0/4'),
          '3.3.3.3': (10, 'Gi0/1'),
          '4.4.4.4': (4, 'Gi0/2'),
          '6.6.6.6': (5, 'Gi0/3')}),

        ({'Gi0/1': ('127.248.24.2', '127.248.24.1'),
          'Gi0/2': ('127.248.28.2', '127.248.28.1'),
          'Gi0/3': ('127.128.0.254', '127.128.0.1')},
         {'127.128.0.0/24': (0, 'Gi0/3'),
          '4.4.4.4': (10, 'Gi0/1'),
          '5.5.5.5': (5, 'Gi0/2')})
    ]

    # Initialize and run the network application
    app = NetworkApp(router_int_con)
    app.run_app()
