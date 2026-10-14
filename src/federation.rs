use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationNodeConfig {
    pub name: String,
    pub url: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub tenant_allow: Vec<String>,
    #[serde(default)]
    pub node_id: Option<String>,
}

fn default_weight() -> u32 {
    1
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct FederationNodeStatus {
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub source: String,
    pub last_seen_iso: Option<String>,
    pub capabilities: Vec<String>,
    pub tenant_allow: Vec<String>,
    pub node_id: Option<String>,
    pub healthy: bool,
    pub ready: bool,
    pub worker_count: Option<u64>,
    pub max_workers: Option<u64>,
    pub route_queue_depth: Option<u64>,
    pub prewarm_queue_depth: Option<u64>,
    pub load_score: Option<f64>,
    pub detail: String,
    pub stale: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteDispatchResult {
    pub node: String,
    pub url: String,
    pub response: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteTaskStatus {
    pub node: String,
    pub url: String,
    pub task_id: String,
    pub payload: Value,
}

#[derive(Debug, Clone)]
pub struct FederationNodeRecord {
    pub config: FederationNodeConfig,
    pub source: String,
    pub last_seen_at: Option<Instant>,
    pub last_seen_iso: Option<String>,
}

impl FederationNodeRecord {
    pub fn new(config: FederationNodeConfig, source: impl Into<String>) -> Self {
        Self {
            config,
            source: source.into(),
            last_seen_at: None,
            last_seen_iso: None,
        }
    }

    pub fn touch(&mut self, iso: String) {
        self.last_seen_at = Some(Instant::now());
        self.last_seen_iso = Some(iso);
    }
}

fn heartbeat_ttl() -> Duration {
    std::env::var("IDA_CLI_FEDERATION_HEARTBEAT_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(30))
}

pub fn load_nodes_from_env() -> Vec<FederationNodeConfig> {
    let path = match std::env::var("IDA_CLI_FEDERATION_CONFIG") {
        Ok(path) => path,
        Err(_) => return Vec::new(),
    };
    load_nodes(&path).unwrap_or_default()
}

pub fn load_node_map_from_env() -> std::collections::HashMap<String, FederationNodeRecord> {
    load_nodes_from_env()
        .into_iter()
        .map(|node| (node.name.clone(), FederationNodeRecord::new(node, "static")))
        .collect()
}

pub fn load_nodes(path: &str) -> anyhow::Result<Vec<FederationNodeConfig>> {
    let data = fs::read_to_string(path)?;
    let nodes: Vec<FederationNodeConfig> = serde_json::from_str(&data)?;
    Ok(nodes)
}

pub fn probe_nodes(nodes: &[FederationNodeRecord]) -> Vec<FederationNodeStatus> {
    nodes.iter().map(probe_record).collect()
}

pub fn choose_ready_node(
    nodes: &[FederationNodeRecord],
    method: Option<&str>,
    tenant: Option<&str>,
) -> Option<FederationNodeConfig> {
    choose_ready_nodes(nodes, method, tenant).into_iter().next()
}

pub fn choose_ready_nodes(
    nodes: &[FederationNodeRecord],
    method: Option<&str>,
    tenant: Option<&str>,
) -> Vec<FederationNodeConfig> {
    let mut ready: Vec<(FederationNodeConfig, FederationNodeStatus)> = nodes
        .iter()
        .filter(|node| node.config.enabled)
        .filter(|node| supports_request(&node.config, method, tenant))
        .filter_map(|node| {
            let status = probe_record(node);
            status.ready.then_some((node.config.clone(), status))
        })
        .collect();
    ready.sort_by(|(lhs_node, lhs_status), (rhs_node, rhs_status)| {
        let lhs = node_rank(lhs_node, lhs_status);
        let rhs = node_rank(rhs_node, rhs_status);
        lhs.partial_cmp(&rhs).unwrap_or(std::cmp::Ordering::Equal)
    });
    ready.into_iter().map(|(node, _)| node).collect()
}

pub fn submit_enqueue(
    node: &FederationNodeConfig,
    payload: &Value,
) -> anyhow::Result<RemoteDispatchResult> {
    let uri: hyper::Uri = node.url.parse()?;
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("missing host in node url"))?;
    let port = uri.port_u16().unwrap_or(80);
    let response = post_json(host, port, "/enqueuez", payload)?;
    Ok(RemoteDispatchResult {
        node: node.name.clone(),
        url: node.url.clone(),
        response,
    })
}

pub fn fetch_remote_task(
    node: &FederationNodeConfig,
    task_id: &str,
) -> anyhow::Result<RemoteTaskStatus> {
    let uri: hyper::Uri = node.url.parse()?;
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("missing host in node url"))?;
    let port = uri.port_u16().unwrap_or(80);
    let payload = fetch_json(host, port, &format!("/taskz/{task_id}"))?;
    Ok(RemoteTaskStatus {
        node: node.name.clone(),
        url: node.url.clone(),
        task_id: task_id.to_string(),
        payload,
    })
}

pub fn supports_request(
    node: &FederationNodeConfig,
    method: Option<&str>,
    tenant: Option<&str>,
) -> bool {
    let tenant = tenant.unwrap_or("default");
    let tenant_ok = node.tenant_allow.is_empty() || node.tenant_allow.iter().any(|t| t == tenant);
    let method_ok = match method {
        None => true,
        Some(method) => {
            node.capabilities.is_empty()
                || node
                    .capabilities
                    .iter()
                    .any(|cap| cap == "*" || cap == method)
        }
    };
    tenant_ok && method_ok
}

pub fn probe_record(record: &FederationNodeRecord) -> FederationNodeStatus {
    let node = &record.config;
    if !node.enabled {
        return FederationNodeStatus {
            name: node.name.clone(),
            url: node.url.clone(),
            enabled: false,
            source: record.source.clone(),
            last_seen_iso: record.last_seen_iso.clone(),
            capabilities: node.capabilities.clone(),
            tenant_allow: node.tenant_allow.clone(),
            node_id: node.node_id.clone(),
            healthy: false,
            ready: false,
            worker_count: None,
            max_workers: None,
            route_queue_depth: None,
            prewarm_queue_depth: None,
            load_score: None,
            detail: "disabled".to_string(),
            stale: false,
        };
    }

    let stale = record.source == "heartbeat"
        && record
            .last_seen_at
            .map(|seen| seen.elapsed() > heartbeat_ttl())
            .unwrap_or(true);
    if stale {
        return FederationNodeStatus {
            name: node.name.clone(),
            url: node.url.clone(),
            enabled: true,
            source: record.source.clone(),
            last_seen_iso: record.last_seen_iso.clone(),
            capabilities: node.capabilities.clone(),
            tenant_allow: node.tenant_allow.clone(),
            node_id: node.node_id.clone(),
            healthy: false,
            ready: false,
            worker_count: None,
            max_workers: None,
            route_queue_depth: None,
            prewarm_queue_depth: None,
            load_score: None,
            detail: "heartbeat expired".to_string(),
            stale: true,
        };
    }

    let uri: hyper::Uri = match node.url.parse() {
        Ok(uri) => uri,
        Err(err) => {
            return FederationNodeStatus {
                name: node.name.clone(),
                url: node.url.clone(),
                enabled: true,
                source: record.source.clone(),
                last_seen_iso: record.last_seen_iso.clone(),
                capabilities: node.capabilities.clone(),
                tenant_allow: node.tenant_allow.clone(),
                node_id: node.node_id.clone(),
                healthy: false,
                ready: false,
                worker_count: None,
                max_workers: None,
                route_queue_depth: None,
                prewarm_queue_depth: None,
                load_score: None,
                detail: format!("invalid url: {err}"),
                stale: false,
            };
        }
    };

    if uri.scheme_str() != Some("http") {
        return FederationNodeStatus {
            name: node.name.clone(),
            url: node.url.clone(),
            enabled: true,
            source: record.source.clone(),
            last_seen_iso: record.last_seen_iso.clone(),
            capabilities: node.capabilities.clone(),
            tenant_allow: node.tenant_allow.clone(),
            node_id: node.node_id.clone(),
            healthy: false,
            ready: false,
            worker_count: None,
            max_workers: None,
            route_queue_depth: None,
            prewarm_queue_depth: None,
            load_score: None,
            detail: "only http federation urls are currently supported".to_string(),
            stale: false,
        };
    }

    let host = match uri.host() {
        Some(host) => host,
        None => {
            return FederationNodeStatus {
                name: node.name.clone(),
                url: node.url.clone(),
                enabled: true,
                source: record.source.clone(),
                last_seen_iso: record.last_seen_iso.clone(),
                capabilities: node.capabilities.clone(),
                tenant_allow: node.tenant_allow.clone(),
                node_id: node.node_id.clone(),
                healthy: false,
                ready: false,
                worker_count: None,
                max_workers: None,
                route_queue_depth: None,
                prewarm_queue_depth: None,
                load_score: None,
                detail: "missing host".to_string(),
                stale: false,
            };
        }
    };
    let port = uri.port_u16().unwrap_or(80);

    let statusz = fetch_json(host, port, "/statusz").ok();
    let healthy = fetch_json(host, port, "/healthz")
        .ok()
        .and_then(|v| v.get("ok").and_then(|v| v.as_bool()))
        .unwrap_or(false);
    let ready = fetch_json(host, port, "/readyz")
        .ok()
        .and_then(|v| v.get("ok").and_then(|v| v.as_bool()))
        .unwrap_or(false);
    let worker_count = statusz
        .as_ref()
        .and_then(|v| v.get("worker_count").and_then(|v| v.as_u64()));
    let max_workers = statusz
        .as_ref()
        .and_then(|v| v.get("max_workers").and_then(|v| v.as_u64()));
    let route_queue_depth = statusz.as_ref().and_then(|v| {
        v.get("route_queue")
            .and_then(|v| v.as_array())
            .map(|items| items.len() as u64)
    });
    let prewarm_queue_depth = statusz.as_ref().and_then(|v| {
        v.get("prewarm_queue")
            .and_then(|v| v.as_array())
            .map(|items| items.len() as u64)
    });
    let load_score = compute_load_score(
        worker_count,
        max_workers,
        route_queue_depth,
        prewarm_queue_depth,
    );

    FederationNodeStatus {
        name: node.name.clone(),
        url: node.url.clone(),
        enabled: true,
        source: record.source.clone(),
        last_seen_iso: record.last_seen_iso.clone(),
        capabilities: node.capabilities.clone(),
        tenant_allow: node.tenant_allow.clone(),
        node_id: node.node_id.clone(),
        healthy,
        ready,
        worker_count,
        max_workers,
        route_queue_depth,
        prewarm_queue_depth,
        load_score,
        detail: if healthy || ready {
            "ok".to_string()
        } else {
            "unreachable or unhealthy".to_string()
        },
        stale: false,
    }
}

fn compute_load_score(
    worker_count: Option<u64>,
    max_workers: Option<u64>,
    route_queue_depth: Option<u64>,
    prewarm_queue_depth: Option<u64>,
) -> Option<f64> {
    let worker_score = match (worker_count, max_workers) {
        (Some(current), Some(max)) if max > 0 => current as f64 / max as f64,
        _ => return None,
    };
    let route_penalty = route_queue_depth.unwrap_or(0) as f64 / 100.0;
    let prewarm_penalty = prewarm_queue_depth.unwrap_or(0) as f64 / 100.0;
    Some(worker_score + route_penalty + prewarm_penalty)
}

fn node_rank(node: &FederationNodeConfig, status: &FederationNodeStatus) -> f64 {
    let load = status.load_score.unwrap_or(10.0);
    let weight_bonus = (node.weight.max(1) as f64).recip();
    load + weight_bonus
}

fn connect_with_timeout(host: &str, port: u16, timeout: Duration) -> anyhow::Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let mut last_err: Option<std::io::Error> = None;
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("no addresses resolved for {host}:{port}")))
}

fn fetch_json(host: &str, port: u16, path: &str) -> anyhow::Result<serde_json::Value> {
    let mut stream = connect_with_timeout(host, port, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: application/json\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    let body = buf
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("invalid http response"))?;
    Ok(serde_json::from_str(body)?)
}

fn post_json(host: &str, port: u16, path: &str, payload: &Value) -> anyhow::Result<Value> {
    let mut stream = connect_with_timeout(host, port, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let body = serde_json::to_vec(payload)?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(&body)?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    let body = buf
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("invalid http response"))?;
    Ok(serde_json::from_str(body)?)
}
