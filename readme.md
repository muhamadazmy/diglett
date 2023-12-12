# Diglett

Diglett lets you expose your locally running web server via a public URL.

Diglett does it as follows:

- You need to run a diglett agent on the same private network as your workload
- `diglett` connects to a public `diglett server`
- the agent initiate a handshake to exchange keys, and send configuration including what (sub)domain it needs to configure
  - (authorization) is to grantee agent connection is allowed to use this subdomain
- once the handshake is established the server does the following:
  - listen on a random tcp port (called agent port) usually listens on the localhost. This port then is associated with an agent connection
  - Connection(s) to agent ports are multiplexed over the agent connection according to the wire protocol specifications
  - A custom configuration module is invoked according to server config, this can be as simple as executing an external script
  - The script can for example configure traefik to proxy to do tls termination for that specific domain, and forward traffic to the local listen port
  - If agent connection is terminated, the configuration is cleaned up (for example delete the traefik configuration)

Diglett is a **tcp** proxy that allows running workloads (servers) behind NAT. It have no assumption of the protocol going over the wire. Hence for this to work as an http/https proxy you will still need to run the diglett server behind a proxy like traefik. Then set up traefik config for each connected agent using the proper configuration module or script.

The agent can forward a single port only, for multiple ports you will have to run separate instances

## Technical specifications

### Wire protocol

- On connect, the agent will send a handshake initiate message
- The message contains the agent public key (secp256k1), this is randomly generated on agent start
- The server public key should be public and should be available at `/info` this contains information about the server
  including it's version, hex encoded public key and may be other meta data.
- Once the server receives the agent public key in the handshake, a shared key is generated using `ecdh` algorithm.
- The shared key will be used to encrypt/decrypt the full stream from now on with `chacha20` stream encryption algorithm
- Following this point, all data on the stream is encrypted in both ways
- The agent immediately sends its required configuration this include:
  - the subdomain requested by the agent
  - extra configuration for gateway (tbd)
- server then can send `<stream>` message that contains the following data:
  - client port number (local to the server)
  - type of message
  - size of payload (can be 0)
  - the message is immediately followed by the payload
- when received, the agent will match the client number (used as connection id) to an already esablished connection to backend. if not a new connection is open and mapped to that id
  data is written on the wire (if any)
- the agent will do the same if any data is received from the backend
- server decrypt and forward the data back
