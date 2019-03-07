use askama::Template;


#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub logged_in: bool,
    pub user: String,
    pub login_redir: String,
}
