use std::env;


#[derive(Debug, Serialize)]
pub struct TokenRequest {
    pub client_id: String,
    pub client_secret: String,
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub scope: String,
}

impl TokenRequest {
    pub fn new(code: String, redir: String) -> TokenRequest { // To generate a new token request object
        TokenRequest {
            client_id: env::var("CLIENT_ID").expect("CLIENT_ID missing"),
            client_secret: env::var("CLIENT_SECRET").expect("CLIENT_SECRET missing"),
            grant_type: String::from("authorization_code"),
            code: code,
            redirect_uri: redir,
            scope: String::from("identify guilds"),
        }
    }
}

#[derive(Deserialize)]
pub struct OAuthQuery {
    pub state: String,
    pub code: String,
}


#[derive(Debug, Deserialize)]
pub struct OAuthAccess {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u32,
    pub refresh_token: String,
    pub scope: String,
}

#[derive(Deserialize)]
pub struct DiscordUser {
    pub id: String,
    pub username: String,
    pub discriminator: String,
}

#[derive(Deserialize)]
pub struct DiscordMember {
    pub roles: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct DiscordGuild {
    pub id: String,
    pub name: String,
    pub permissions: u32,
}

#[derive(Deserialize, Debug)]
pub struct DiscordChannel {
    pub id: String,
    pub name: String,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct DiscordChannelCreator {
    pub name: String,
    pub r#type: u8,
}

#[derive(Deserialize, Debug)]
pub struct DeleteChannel {
    pub id: u64,
}

#[derive(Deserialize, Debug)]
pub struct CreateChannel {
    pub guild: String,
    pub timezone: String,
    pub name: String,
}

pub struct ClockChannel {
    pub guild: String,
    pub id: u64,
    pub timezone: String,
    pub name: String,
}