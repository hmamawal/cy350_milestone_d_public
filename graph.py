class Graph:
    """
    Represents a directed, weighted graph used for network routing algorithms. The graph
    consists of nodes (routers or hosts) and edges (connections) between them with associated
    costs (e.g., latency, distance) and network interfaces.

    Attributes:
        nodes (dict): A dictionary representing the graph structure, where keys are node identifiers
                      and values are lists of tuples representing edges (destination node, cost, interface).
    """

    def __init__(self):
        """
        Initializes an empty graph with no nodes.
        """
        self.nodes = {}

    def add_node(self, node):
        """
        Adds a node to the graph. If the node already exists, it is not added again.

        Args:
            node (str): The identifier for the node (e.g., a router ID or network address).
        """
        if node not in self.nodes:
            self.nodes[node] = []

    def add_edge(self, from_node, to_node, cost, interface):
        """
        Adds a directed, weighted edge from one node to another. If either node does not exist in the graph,
        it is added automatically.

        Args:
            from_node (str): The node from which the edge originates.
            to_node (str): The node to which the edge points.
            cost (int): The cost of the edge (e.g., distance or network latency).
            interface (str): The network interface associated with the edge.
        """
        self.add_node(from_node)  # Ensure the source node exists
        self.add_node(to_node)    # Ensure the destination node exists
        self.nodes[from_node].append((to_node, cost, interface))

