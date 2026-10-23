//! DSC task adapter. Offline preparation never uses the legacy worker.
use super::*;
use crate::router::nexus_bridge::cache::special::DscInput;

impl IdaMcpServer {
    pub(super) async fn open_dsc_nexus(
        &self,
        router: &crate::router::RouterState,
        req: OpenDscRequest,
    ) -> Result<CallToolResult, McpError> {
        let config = DscInput {
            arch: req.arch,
            module: req.module,
            frameworks: req.frameworks.unwrap_or_default(),
            ida_version: req.ida_version.unwrap_or(9),
            log_path: req.log_path.as_deref().map(crate::expand_path),
        };
        if let Err(error) = config.validate() {
            return Ok(error.to_tool_result());
        }
        let path = crate::expand_path(&req.path);
        let check_path = path.clone();
        let preparation = crate::preprocess::Preparation::new(std::time::Duration::from_secs(3600));
        let existing = match preparation
            .wait(crate::blocking::run(
                crate::blocking::WorkClass::Prepare,
                move || {
                    let canonical = check_path.canonicalize()?;
                    let existing = if canonical
                        .extension()
                        .is_some_and(|e| e == "i64" || e == "idb")
                    {
                        Some(canonical)
                    } else {
                        let adjacent = canonical.with_extension("i64");
                        adjacent.is_file().then_some(adjacent)
                    };
                    Ok::<_, std::io::Error>(existing)
                },
            ))
            .await
        {
            Ok(Ok(existing)) => existing,
            Ok(Err(error)) => return Ok(ToolError::InvalidPath(error.to_string()).to_tool_result()),
            Err(error) => return Ok(error.to_tool_result()),
        };
        if let Some(existing) = existing {
            return Ok(
                match self
                    .finish_dsc_nexus(
                        router,
                        &existing.to_string_lossy(),
                        None,
                        &config,
                        preparation,
                    )
                    .await
                {
                    Ok(value) => CallToolResult::success(vec![Content::text(value.to_string())]),
                    Err(error) => bridge_loss_tool_result(router, &error, error.to_tool_result()),
                },
            );
        }
        let key = json!({"path":path,"loader":config}).to_string();
        let task_id = match self
            .task_registry
            .create_keyed(&key, "Preparing DSC snapshot and offline database...")
        {
            Ok(id) => id,
            Err(id) => {
                return Ok(CallToolResult::success(vec![Content::text(
                    json!({"status":"already_running","task_id":id}).to_string(),
                )]))
            }
        };
        self.task_registry
            .set_cancellation(&task_id, preparation.cancel.clone());
        let service = self.clone();
        let router = router.clone();
        let tid = task_id.clone();
        let handle = tokio::spawn(async move {
            let result = service
                .finish_dsc_nexus(
                    &router,
                    &path.to_string_lossy(),
                    Some(config.clone()),
                    &config,
                    preparation,
                )
                .await;
            match result {
                Ok(value) => service.task_registry.complete(&tid, value),
                Err(ToolError::Preparation {
                    execution_stopped: true,
                    ..
                }) => service.task_registry.cancellation_confirmed(&tid),
                Err(error) => service.task_registry.fail(&tid, &error.to_string()),
            }
        });
        self.task_registry.set_handle(&task_id, handle);
        Ok(CallToolResult::success(vec![Content::text(
            json!({"status":"started","task_id":task_id,
            "message":"DSC preparation started. Poll task_status(task_id) for progress."})
            .to_string(),
        )]))
    }

    async fn finish_dsc_nexus(
        &self,
        router: &crate::router::RouterState,
        path: &str,
        build: Option<DscInput>,
        config: &DscInput,
        preparation: crate::preprocess::Preparation,
    ) -> Result<Value, ToolError> {
        let (handle, token) = match build {
            Some(config) => {
                router
                    .open_nexus_dsc(path, config, preparation.clone())
                    .await?
            }
            None => {
                router
                    .ensure_worker_prepared(path, None, None, preparation.clone())
                    .await?
            }
        };
        let mut reference =
            crate::router::nexus_tools::ReferenceGuard::new(router.clone(), token.clone());
        router.set_nexus_client(&handle, &self.client);
        let mut value = router.nexus_open_details(&handle, preparation).await?;
        value["db_handle"] = json!(handle);
        value["close_token"] = json!(token);
        value["close_hint"] = json!(self.close_hint());
        value["module"] = json!(config.module);
        value["frameworks_loaded"] = json!(config.frameworks);
        reference.transfer();
        Ok(value)
    }
}
