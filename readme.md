# Diglett

<img src="docs/img/icon.png" width="100"/>

Diglett is a simple ingress utility that allows you to expose your private workloads that lives behind **NAT**
over a public gateway

## Operation

`diglett` consists of two parts.

- `diglett-server` this is the `public` gateway part. This runs on a public server, it accept `agents` connections.
- `diglett` is the agent. The agent runs next to your workload that you need to make public (say on your laptop).

Normally, what you need to do is start the `diglett` agent giving the public gateway to connect to and the `backend` that you need to make accessible over the internet

## Example

Let's assume that we have a diglett server running at `gateway.com` port `20000` (right now the port is required). You want to expose a local service that runs on `localhost` port `9000`. And you are authorized to use the name `example` for your service.

You then can run the following agent

```bash
diglett -g gateway.com:20000 -n example localhost:9000
```

Then if server setup is correct. your service should be accessible on `https://example.gateway.com`

## Authentication/Authorization

`diglett` is built to be easily extended regarding two main things:

- Authentication/Authorization
- Configuration of the gateway subdomain (the example.gateway.com part in the example above)

The `diglett` agent right now accepts an optional `token` that is handed over to the server during the agent handshake. The `diglett` server then is free to accept or reject the token during the authentication process.
Then during the registration of the subdomain name `example` the authentication module is consulted to authorize that domain to make sure it's in the allowed user names to be used.

## Configuration

The configuration step that happens on the server side to actually `expose` the full domain `example.gateway.com` is also completely modular, and can be easily completely replaced and/or modified. Right now there is no action is taken (only information about the domain registration is printed by default)

This will then be extended to actually configure the ingress proxy (for example `traefik`) to forward the domain to the local listening port on the server side

## Building

```bash
cargo build --release --target=x86_64-unknown-linux-musl
```

You should then find the 2 binaries

- target/x86_64-unknown-linux-musl/release/diglett
- target/x86_64-unknown-linux-musl/release/diglett-server

## Full Example

We gonna run both the client and server locally

In one terminal start the server

```bash
diglett-server -d
```

The `-d` is for debug messages

In the other terminal start a simple python http server.

```bash
python -m http.server --directory . --bind :: 9000
```

This will start an http server in the current directory

In yet a third terminal you need to start the diglett-agent

```bash
diglett -d -g localhost:20000  -n example -d localhost:9000
```

This will connect to the server at port 20000 and forward connections to backend at `localhost:9000` which is the python server in that case

When you start the agent, you should see a message printed on the `server` terminal that shows

```bash
register domain 'example' -> '<some port number>'
```

This is basically the port on the server side that will be accept connections on your behalf (on the public network) and any connection will then
be forwarded over the agent connection to your backend (the python server)

Let's say the `port` in the previous example is `33605`. Now try to open your browser and type `localhost:33605` you then should be served the web page that is served by the python http server.

What is happening is the following:

- When the agent connected to the server the server opened a local port to accept connections on behalf of the agent
- When someone connect to that port (33605 in the example above) the connection is forwarded over the agent connection to the agent
- The agent then connects to the backend (the http server over port 9000) and pipe the traffic
- Piping happens in the opposite direction as well

## Specifications

Please check specifications and implementation details [here](docs/readme.md)
