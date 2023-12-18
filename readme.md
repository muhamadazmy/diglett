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

## Specifications

Please check specifications and implementation details [here](docs/readme.md)
