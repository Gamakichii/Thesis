import networkx as nx
import numpy as np
import torch
from torch_geometric.data import Data

def get_simulated_graph_data():
    NUM_USERS, NUM_POSTS = 500, 2000
    PCT_MALICIOUS_USERS, PCT_PHISHING_POSTS = 0.05, 0.10
    G = nx.Graph()
    user_nodes = range(NUM_USERS)
    post_nodes = range(NUM_USERS, NUM_USERS + NUM_POSTS)
    malicious_user_ids = np.random.choice(user_nodes, size=int(NUM_USERS * PCT_MALICIOUS_USERS), replace=False)
    phishing_post_ids = np.random.choice(post_nodes, size=int(NUM_POSTS * PCT_PHISHING_POSTS), replace=False)
    for i in user_nodes: G.add_node(i, type='user')
    for i in post_nodes: G.add_node(i, type='post', is_phishing=(i in phishing_post_ids))
    for _ in range(1500):
        user = np.random.choice([u for u in user_nodes if u not in malicious_user_ids])
        post = np.random.choice([p for p in post_nodes if p not in phishing_post_ids])
        G.add_edge(user, post)
    for post_id in phishing_post_ids:
        for _ in range(np.random.randint(2, 5)):
            user = np.random.choice(malicious_user_ids)
            G.add_edge(user, post)
    # Convert to PyG format
    node_features = torch.tensor([[1] if G.nodes[i]['type']=='user' else [2] for i in G.nodes()], dtype=torch.float)
    edge_index = torch.tensor(list(G.edges), dtype=torch.long).t().contiguous()
    return Data(x=node_features, edge_index=edge_index)