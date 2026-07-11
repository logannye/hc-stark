use crate::error::ApiError;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct GithubClient {
    http: Client,
    client_id: String,
    client_secret: String,
    callback_url: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GithubUser {
    pub id: u64,
    pub login: String,
}

#[derive(Clone, Debug, Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    error: Option<String>,
}

impl GithubClient {
    pub fn new(client_id: String, client_secret: String, callback_url: String) -> Self {
        Self {
            http: Client::builder()
                .user_agent("TinyZKP-public-beta/1")
                .build()
                .expect("valid HTTP client"),
            client_id,
            client_secret,
            callback_url,
        }
    }

    pub fn authorization_url(&self, state: &str, challenge: &str) -> Result<String, ApiError> {
        let mut url = url::Url::parse("https://github.com/login/oauth/authorize")
            .map_err(|_| ApiError::Internal)?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.callback_url)
            .append_pair("scope", "read:user user:email")
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url.to_string())
    }

    pub async fn exchange(&self, code: &str, verifier: &str) -> Result<String, ApiError> {
        #[derive(Serialize)]
        struct Request<'a> {
            client_id: &'a str,
            client_secret: &'a str,
            code: &'a str,
            redirect_uri: &'a str,
            code_verifier: &'a str,
        }
        let response = self
            .http
            .post("https://github.com/login/oauth/access_token")
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&Request {
                client_id: &self.client_id,
                client_secret: &self.client_secret,
                code,
                redirect_uri: &self.callback_url,
                code_verifier: verifier,
            })
            .send()
            .await?
            .error_for_status()?
            .json::<TokenResponse>()
            .await?;
        response.access_token.ok_or_else(|| {
            tracing::warn!(error = ?response.error, "GitHub OAuth exchange rejected");
            ApiError::Unauthorized
        })
    }

    pub async fn identity(&self, token: &str) -> Result<(GithubUser, Option<String>), ApiError> {
        let user = self
            .http
            .get("https://api.github.com/user")
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json::<GithubUser>()
            .await?;
        let emails = self
            .http
            .get("https://api.github.com/user/emails")
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<GithubEmail>>()
            .await?;
        let verified = emails
            .into_iter()
            .find(|email| email.primary && email.verified)
            .map(|email| email.email);
        Ok((user, verified))
    }
}
