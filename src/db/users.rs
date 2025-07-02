use anyhow::anyhow;
use sqlx::MySqlPool;
use sqlx::Row;

use crate::controllers;
use crate::controllers::users::UserInfo;
use crate::controllers::users::UserInfoFull;
use crate::controllers::users::UserStats;
use crate::AppState;

pub async fn get_user_info(state: &AppState, user_id: u32) -> anyhow::Result<UserInfo> {
    let row = sqlx::query_as!(
        UserInfo,
        r#"
        SELECT username, email
        FROM users
        WHERE id = ?
        "#,
        user_id
    )
    .fetch_one(&state.basic.pool)
    .await?;

    Ok(row)
}

// pub async fn get_user_stats(
//     state: &AppState,
//     user_id: u32,
// ) -> anyhow::Result<UserStats> {
//     let row = sqlx::query_as!(
//         UserStats,
//         r#"
//         SELECT 
//             (SELECT COUNT(DISTINCT course_id) 
//              FROM user_courses 
//              WHERE user_id = ?) AS courses_owned,
            // (SELECT COUNT(DISTINCT m.course_id) 
            //  FROM task_progress tp
            //  JOIN tasks t ON tp.task_id = t.id
            //  JOIN modules m ON t.module_id = m.id
            //  WHERE tp.user_id = ?) AS courses_started,
//             (
//              SELECT COUNT(DISTINCT m.course_id)
//              FROM modules m
//              JOIN (
//                  SELECT t.module_id, COUNT(*) as total_tasks
//                  FROM tasks t
//                  GROUP BY t.module_id
//              ) t ON m.id = t.module_id
//              JOIN (
//                  SELECT t.module_id, COUNT(*) as completed_tasks
//                  FROM task_progress tp
//                  JOIN tasks t ON tp.task_id = t.id
//                  WHERE tp.user_id = ? AND tp.status = 'SUCCESS'
//                  GROUP BY t.module_id
//              ) tc ON m.id = tc.module_id
//              WHERE t.total_tasks = tc.completed_tasks
//              GROUP BY m.course_id
//              HAVING COUNT(DISTINCT m.id) = (
//                  SELECT COUNT(*) 
//                  FROM modules m2 
//                  WHERE m2.course_id = m.course_id
//              )
//             ) AS courses_completed
//         "#,
//         user_id,
//         user_id,
//         user_id
//     )
//     .fetch_one(&state.basic.pool)
//     .await?;

//     Ok(row)
// }


pub async fn create_user(
    pool: &MySqlPool,
    username: &str,
    email: &str,
    password_hash: &str,
) -> anyhow::Result<u32> {
    let row = sqlx::query("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)")
        .bind(username)
        .bind(email)
        .bind(password_hash)
        .execute(pool)
        .await?;
    Ok(row.last_insert_id() as u32)
}

pub async fn id_by_email(pool: &MySqlPool, email: &str) -> anyhow::Result<u32> {
    let row = sqlx::query("SELECT id FROM users WHERE email = ?")
        .bind(email)
        .fetch_one(pool)
        .await?;
    let id: i32 = row.try_get(0)?;
    Ok(id as u32)
}

pub async fn get_password_hash(pool: &MySqlPool, id: u32) -> anyhow::Result<String> {
    let row = sqlx::query("SELECT password_hash FROM users WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await?;
    let hash: String = row.try_get(0)?;
    Ok(hash)
}

pub async fn email_exists(pool: &MySqlPool, email: &str) -> anyhow::Result<()> {
    sqlx::query("SELECT * FROM users WHERE email = ?")
        .bind(email)
        .fetch_one(pool)
        .await?;
    Ok(())
}

pub async fn set_password_by_email(
    pool: &MySqlPool,
    email: &str,
    password_auth: &str,
) -> anyhow::Result<()> {
    sqlx::query("UPDATE users SET password_hash = ? WHERE email = ?")
        .bind(password_auth)
        .bind(email)
        .execute(pool)
        .await?;
    Ok(())
}