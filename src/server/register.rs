use crate::Result;

/// trait to register a domain. Normally this should expose the domain
/// to the given port
#[async_trait::async_trait]
pub trait Registerer: Send + Sync + 'static {
    // The handler is returned when a registration happens
    // the point is when the handler is dropped, this must take care
    // of auto removal of the registration
    type Handler: Send + Sync + 'static;

    async fn register(&self, domain: &str, port: u16) -> Result<Self::Handler>;
}

#[derive(Debug, Clone)]
pub struct PrintRegisterer;

#[async_trait::async_trait]
impl Registerer for PrintRegisterer {
    type Handler = PrintHandler;
    async fn register(&self, domain: &str, port: u16) -> Result<Self::Handler> {
        log::info!("register domain '{}' -> '{}'", domain, port);

        Ok(PrintHandler {
            name: domain.into(),
        })
    }
}

pub struct PrintHandler {
    name: String,
}

impl Drop for PrintHandler {
    fn drop(&mut self) {
        log::info!("unregister domain '{}'", self.name);
    }
}
