use diglett::server::Server;

#[tokio::main]
async fn main() {
    simple_logger::SimpleLogger::default()
        .with_level(log::LevelFilter::Debug)
        .with_utc_timestamps()
        .init()
        .unwrap();

    let server = Server::new();

    server.start(("127.0.0.1", 20000)).await.unwrap();
}
