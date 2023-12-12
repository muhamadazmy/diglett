use diglett::server::Server;

#[tokio::main]
async fn main() {
    let server = Server::new();

    server.start(("127.0.0.1", 20000)).await.unwrap();
}
