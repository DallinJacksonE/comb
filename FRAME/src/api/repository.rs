//! Repository-page HTTP adapters; Store owns permissions and domain behavior.
//!
//! These handlers rely on their parent router for authentication and lifecycle
//! gating. Store resolves accepted revisions and enforces repository access;
//! paths select Git objects, not files in the daemon's runtime filesystem.
use super::{ApiResult, App};
use crate::git::{RepositoryBlob, RepositoryHistory, RepositoryTree};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;

#[derive(Deserialize)]
/// New repository display name; identifier/slug policy belongs to Store.
pub(super) struct Rename {
    name: String,
}
#[derive(Deserialize)]
/// Explicit deletion confirmation interpreted by Store.
pub(super) struct Delete {
    confirmation: String,
}

/// Rename local CELL metadata and return its updated summary.
pub(super) async fn rename(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<Rename>,
) -> ApiResult<Json<crate::store::CellSummary>> {
    Ok(Json(
        app.execute(move |store| store.rename_cell(&id, input.name))
            .await?,
    ))
}

/// Delete the selected local CELL after Store checks the confirmation string.
pub(super) async fn delete(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<Delete>,
) -> ApiResult<Json<serde_json::Value>> {
    let deleted = app
        .execute(move |store| {
            store.delete_cell(&id, &input.confirmation)?;
            Ok(id)
        })
        .await?;
    Ok(Json(serde_json::json!({"deleted": deleted})))
}

#[derive(Deserialize)]
/// Optional accepted revision and Git-relative path (empty means the tree root).
pub(super) struct BrowseQuery {
    revision: Option<String>,
    #[serde(default)]
    path: String,
}

#[derive(Deserialize)]
/// Optional accepted revision and zero-based history offset, defaulting to zero.
pub(super) struct HistoryQuery {
    revision: Option<String>,
    #[serde(default)]
    offset: usize,
}

/// Return one Store-defined history page; invalid offsets/revisions become HTTP 400.
pub(super) async fn history(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(query): Query<HistoryQuery>,
) -> ApiResult<Json<RepositoryHistory>> {
    Ok(Json(
        app.execute(move |store| {
            store.repository_history(&id, query.revision.as_deref(), query.offset)
        })
        .await?,
    ))
}

/// Return committed directory entries, including an empty root for an empty repo.
pub(super) async fn tree(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(query): Query<BrowseQuery>,
) -> ApiResult<Json<RepositoryTree>> {
    Ok(Json(
        app.execute(move |store| {
            store.repository_tree(&id, query.revision.as_deref(), &query.path)
        })
        .await?,
    ))
}

/// Return bounded blob metadata/content through the same revision permission seam.
pub(super) async fn blob(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(query): Query<BrowseQuery>,
) -> ApiResult<Json<RepositoryBlob>> {
    Ok(Json(
        app.execute(move |store| {
            store.repository_blob(&id, query.revision.as_deref(), &query.path)
        })
        .await?,
    ))
}
