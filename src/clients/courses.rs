use crate::{clients, BasicState};




pub async fn get_user_courses(state: &BasicState, user_id: u32) -> anyhow::Result<Vec<i32>> {
    let endpoint = std::env::var("COURSES_SERVICE_URL").unwrap() + &format!("/internal/courses/users/{}", user_id);
    let resp = clients::request::get_request::<Vec<i32>>(&state.http_client, &endpoint).await?;
    Ok(resp)
}
pub async fn get_user_courses_started(state: &BasicState, user_id: u32) -> anyhow::Result<Vec<i32>> {
    let endpoint = std::env::var("COURSES_SERVICE_URL").unwrap() + &format!("/internal/courses/users/{}/started", user_id);
    let resp = clients::request::get_request::<Vec<i32>>(&state.http_client, &endpoint).await?;
    Ok(resp)
}
pub async fn get_user_courses_completed(state: &BasicState, user_id: u32) -> anyhow::Result<Vec<i32>> {
    let endpoint = std::env::var("COURSES_SERVICE_URL").unwrap() + &format!("/internal/courses/users/{}/completed", user_id);
    let resp = clients::request::get_request::<Vec<i32>>(&state.http_client, &endpoint).await?;
    Ok(resp)
}