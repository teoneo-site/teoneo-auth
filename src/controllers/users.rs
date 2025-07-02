use crate::{clients, db, AppState};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Default, Serialize, Deserialize, ToSchema)]
pub struct UserInfoFull {
    pub username: String,
    pub email: String,
    pub courses: Vec<i32>,
}

#[derive(Default, Serialize, Deserialize, ToSchema)]
pub struct UserInfo {
    pub username: String,
    pub email: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UserStats {
    pub courses_owned: Option<i64>,
    pub courses_started: Option<i64>,
    pub courses_completed: Option<i64>,
}

pub async fn get_user_info_all(app_state: &AppState, user_id: u32) -> anyhow::Result<UserInfoFull> {
    let user_info = get_user_info(app_state, user_id).await?;
    let user_courses = get_courses_info(app_state, user_id).await?;

    let info = UserInfoFull {
        username: user_info.username,
        email: user_info.email,
        courses: user_courses
    };
    Ok(info)
}
pub async fn get_courses_info(app_state: &AppState, user_id: u32) -> anyhow::Result<Vec<i32>> {
    let info = clients::courses::get_user_courses(&app_state.basic, user_id).await?;
    Ok(info)
}

pub async fn get_user_info(app_state: &AppState, user_id: u32) -> anyhow::Result<UserInfo> {
    let info = db::users::get_user_info(app_state, user_id).await?;
    Ok(info)
}

pub async fn get_user_stats(app_state: &AppState, user_id: u32) -> anyhow::Result<UserStats> {
    let user_courses = clients::courses::get_user_courses(&app_state.basic, user_id).await?;
    let courses_started = clients::courses::get_user_courses_started(&app_state.basic, user_id).await?;
    let courses_completed = clients::courses::get_user_courses_completed(&app_state.basic, user_id).await?;

    let stats = UserStats { 
        courses_owned: Some(user_courses.len() as i64), 
        courses_started: Some(courses_started.len() as i64), 
        courses_completed: Some(courses_completed.len() as i64) 
    };
    Ok(stats)
}
