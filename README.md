# Applying Re-Encryption for Data-Centric Security and Centralized Control in Distributed Big Data Systems
## Proof of Concept (PoC) Code Description
This repository is a Proof of Concept (PoC) for the proposed data-centric security system is designed to demonstrate the core functionalities and validate the feasibility of the architecture. The system is composed of three main types of nodes: Trusted Authority (TA), Worker Nodes, and Clients. Below is a detailed description of each component and its corresponding implementation in the PoC code.

### Trusted Authority (TA)
The Trusted Authority is the central component responsible for managing user access, handling authentication, and authorizing requests. The TA ensures that all access to data is strictly controlled and monitored.

#### Key Functions:

* User Authentication: Validates the identity of clients using credentials.
* Authorization: Determines if a client has the necessary permissions to perform a requested operation.
* Key Management: Generates and distributes encryption/decryption keys to authorized clients.

### Worker Nodes
Worker Nodes are responsible for storing large volumes of data and performing re-encryption operations. They handle the actual data processing tasks such as encryption, decryption, and storage.

#### Key Functions:

* Data Storage: Stores encrypted data chunks.
* Re-encryption: Re-encrypts data upon receiving updated keys from the TA.
* Data Retrieval: Provides access to data for authorized clients.

### Clients
Clients are the end-users of the system who can read and write data if authorized. Clients interact with the TA to obtain the necessary permissions and keys, and then interact with Worker Nodes to perform data operations.

#### Key Functions:
* Data Upload: Encrypts and uploads data to Worker Nodes.
* Data Download: Requests and decrypts data from Worker Nodes.
* Permission Requests: Communicates with the TA to obtain authorization for data operations.

---

## Usage

### Initial Setup
For the initial setup of the project and the installation of the required dependencies, we need to run the `setup.sh` script:

```
bash setup.sh
```

### Trusted Authority
The Trusted Authority can be configured by updating `config.yaml`. It supports configurations such as the port to listen to, the re-encryption triggers (re-encrypt on read only or on read/write), the scheduling type (lazy or strict), and the block size to use.

To run the Trusted Auhority, can run the following commands:

```
cd TA
python3 main.py
```

### Worker Nodes
The worker nodes can be configured by copying the existing config.yaml and then updating it. It can be used to:
* Specify the location of the Trusted Authority (hostname and port)
* Specify the hostname and port that should be used by the worker node to listen for requests
* Specify the upload and download socket ports for data transport

To start multiple worker nodes, we can create multiple configuration files and update them separately then run:

```
cd WN
python3 main.py ./node-1-config.yaml &
python3 main.py ./node-2-config.yaml &
...
```

### Client Node
For the client node we simply run it using:

```
cd Client
python3 main.py
```

Then, we can choose the action to execute through a menu of possible actions which will be displayed on client start-up.
