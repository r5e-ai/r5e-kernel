use cedar_policy::{Context, Entities, EntityUid, PolicySet, Request};
use rustler::{Binary, Env, OwnedBinary};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::str::FromStr;

#[rustler::nif(schedule = "DirtyCpu")]
fn canonical_hash<'a>(env: Env<'a>, source: String) -> Result<Binary<'a>, String> {
    let policies = PolicySet::from_str(&source).map_err(|e| format!("cedar parse error: {e}"))?;
    let json = policies
        .to_json()
        .map_err(|e| format!("cedar to_json error: {e}"))?;
    let canonical = serde_jcs::to_string(&json).map_err(|e| format!("jcs encode error: {e}"))?;
    let digest = Sha256::digest(canonical.as_bytes());
    let mut owned = OwnedBinary::new(32).ok_or_else(|| "cannot allocate digest".to_string())?;
    owned.as_mut_slice().copy_from_slice(&digest);
    Ok(Binary::from_owned(owned, env))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn validate_policy_syntax(source: String) -> Result<(), String> {
    PolicySet::from_str(&source)
        .map(|_| ())
        .map_err(|e| format!("cedar parse error: {e}"))
}

#[derive(Deserialize)]
struct EvalRequest {
    principal: String,
    action: String,
    resource: String,
    #[serde(default)]
    context: serde_json::Value,
}

#[derive(serde::Serialize)]
struct EvalOutput {
    decision: String,
    matched_policies: Vec<String>,
}

#[rustler::nif(schedule = "DirtyCpu")]
fn evaluate_with_entities(
    source: String,
    request_json: String,
    entities_json: String,
) -> Result<String, String> {
    let policies = PolicySet::from_str(&source).map_err(|e| format!("cedar parse error: {e}"))?;
    let parsed: EvalRequest =
        serde_json::from_str(&request_json).map_err(|e| format!("request parse error: {e}"))?;
    let principal =
        EntityUid::from_str(&parsed.principal).map_err(|e| format!("bad principal: {e}"))?;
    let action = EntityUid::from_str(&parsed.action).map_err(|e| format!("bad action: {e}"))?;
    let resource =
        EntityUid::from_str(&parsed.resource).map_err(|e| format!("bad resource: {e}"))?;
    let context = if parsed.context.is_null() {
        Context::empty()
    } else {
        Context::from_json_value(parsed.context, None)
            .map_err(|e| format!("context parse error: {e}"))?
    };
    let request = Request::new(principal, action, resource, context, None)
        .map_err(|e| format!("request build error: {e}"))?;
    let entities_value =
        serde_json::from_str(&entities_json).map_err(|e| format!("entities parse error: {e}"))?;
    let entities = Entities::from_json_value(entities_value, None)
        .map_err(|e| format!("entities build error: {e}"))?;
    let response = cedar_policy::Authorizer::new().is_authorized(&request, &policies, &entities);
    let matched: BTreeSet<String> = response
        .diagnostics()
        .reason()
        .map(ToString::to_string)
        .collect();
    let output = EvalOutput {
        decision: match response.decision() {
            cedar_policy::Decision::Allow => "allow".to_string(),
            cedar_policy::Decision::Deny => "deny".to_string(),
        },
        matched_policies: matched.into_iter().collect(),
    };
    serde_json::to_string(&output).map_err(|e| format!("response encode error: {e}"))
}

rustler::init!("Elixir.R5e.Cedar.Nif");
