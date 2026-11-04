//! Page « Maisons » : liste, rattachement par code, révocation.

use askama::Template;
use axum::response::{IntoResponse, Response};

use super::{render, session::CurrentAccount};

#[derive(Template)]
#[template(path = "maisons.html")]
struct HousesPage {
    connected: bool,
}

pub async fn page(_current: CurrentAccount) -> Response {
    render(&HousesPage { connected: true }).into_response()
}
