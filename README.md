# Server Authentication Proxy
## Requirements
Install requirements from requirements.txt
### Install ndn
    pip install -U git+https://github.com/named-data/python-ndn.git

### Freeze requirements
    pip freeze --local > requirements.txt 

# Business Logic
1. The Client sends an interest packet to the authentication server using the method GetHandshakeToken(). This IPkt's 
   payload contains an AuthMessage encapsulated in the IPkt's Application Parameter field. The Client at this stage
   changes its status to AUTH_REQUEST_SENT and waits for a server reply in the form of a Data Packet.
    

2. The Server receives the previously sent IPkt and detects that it is a HandShake Message, it sets the client's session 
   state to AUTH_REQUEST_RECEIVED, and it then forwards it to the HandshakeReply() pipeline. The pipeline creates a Data 
   Packet (DPkt) with an Authentication Message encapsulated in its content field. This AuthMessage is of type 
   HandshakeReply, and it contains a message parameter of the form <HandshakeToken, handshake_token_value>. 
   The token_value is a randomly generated string. The server then sets the status of this session to 
   HANDSHAKE_TOKEN_SENT.
   



## Solution Components:
### Authentication Server
1. Authenticate a client and issue it an authentication token
2. Validate Producers' Is_Authenticated messages, which confirms if a client has been authenticated or not
### Authentication Client which is also Content Consumer
1. Authenticate to a server and get a token
2. Consume a Producers' protected content using the token
### Content Producer
1. Publishes protected content
2. Validate consumers' token -with the server- to allow the client to access a protected content

## Definitions
* AuthServer: is an NDN applications, that bounds itself to NFD by registering an NDN route. For example, /example/authserv. 
* ClientsManager: is an AuthServers' component, which is responsible for processing authentication messages and keeping track of who is authenticated. It also sets the expiry for both the handshake and the auth tokens.



## Running the lab
* Open three terminals
      
      cd /home/user/ndnota
* On each terminal, activate venv

      source venv/bin/activate
      cd src
* On each terminal, run one of the following commands

      python RunServer.py
      python producer/main.py
      python client/Consumer.py 