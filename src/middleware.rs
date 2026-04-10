use salvo::catcher::Catcher;
use salvo::prelude::*;

use atuin_common::api::{ATUIN_CARGO_VERSION, ATUIN_HEADER_VERSION};
use http::header::HeaderName;

#[handler]
pub async fn clacks_overhead(res: &mut Response, _req: &mut Request) {
    res.headers_mut().insert(
        "X-Clacks-Overhead",
        "GNU Terry Pratchett, Kris Nova".parse().unwrap(),
    );
}

#[handler]
pub async fn version_header(res: &mut Response, _req: &mut Request) {
    let header_name: HeaderName = ATUIN_HEADER_VERSION.parse().unwrap();
    res.headers_mut()
        .insert(header_name, ATUIN_CARGO_VERSION.parse().unwrap());
}

#[handler]
async fn handle404(&self, _req: &Request, _depot: &Depot, res: &mut Response, ctrl: &mut FlowCtrl) {
    if res.status_code.unwrap_or(StatusCode::NOT_FOUND) == StatusCode::NOT_FOUND {
        res.status_code(StatusCode::NOT_FOUND);
        res.render(Json(serde_json::json!({
            "error": "not found"
        })));
        ctrl.skip_rest();
    }
}

pub fn create_catcher() -> Catcher {
    Catcher::default().hoop(handle404)
}
