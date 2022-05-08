#[macro_use]
extern crate rocket;
use rocket::serde::json::Json;

mod invitation;
use invitation::Invitation;

#[get("/")]
fn index() -> Json<Invitation> {
    Json(Invitation::new())
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index])
}

#[cfg(test)]
mod tests {
    use super::*;

    use rocket::http::Status;
    use rocket::local::blocking::Client;

    #[test]
    fn test_invitation_endpoint() {
        let rocket = rocket();
        let client = Client::tracked(rocket).unwrap();
        let req = client.get("/");
        let response = req.dispatch();
        assert_eq!(response.status(), Status::Ok);
        let invitation: Invitation = response.into_json().unwrap();
        assert_eq!(invitation.services[0].typ, "did-communication");
    }
}
