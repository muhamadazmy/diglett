use crate::{Error, Result};

pub struct User<U = u64> {
    pub id: U,
    // other user data that might be interesting
}

#[async_trait::async_trait]
pub trait Authenticate: Send + Sync + 'static {
    type U: Send + 'static;

    async fn authenticate(&self, token: &str) -> Result<User<Self::U>>;
    async fn authorize(&self, user: &Self::U, name: &str) -> Result<bool>;
}

#[derive(Debug, Clone)]
pub struct AuthorizeAll;

#[async_trait::async_trait]
impl Authenticate for AuthorizeAll {
    type U = ();

    async fn authenticate(&self, token: &str) -> Result<User<()>> {
        if token == "fail" {
            return Err(Error::AuthenticationError("invalid token".into()));
        }

        Ok(User { id: () })
    }

    async fn authorize(&self, _user: &Self::U, _name: &str) -> Result<bool> {
        Ok(true)
    }
}
