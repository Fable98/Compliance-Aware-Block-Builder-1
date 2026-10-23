use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use compliance_engine::{
    EngineError, EntityType,
    MockComplianceBackend, ScreenRequest, ScreenResponse,
    compute_decision_digest, compute_merkle_root, create_app, evaluate_transaction,
    validate_eth_address,
};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;

const CLEAN_SENDER: &str = "0x1111111111111111111111111111111111111111";
const CLEAN_RECIPIENT: &str = "0x2222222222222222222222222222222222222222";
const SANCTIONED_ADDR: &str = "0x747afb5c7a7fc34b547cd0fdebf9b91759c5a52b";
const MIXER_ADDR: &str = "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b";
const DEV_API_KEY: &str = "dev-engine-secret-2026";

// =========================================================================
// 1. ADDRESS VALIDATION TESTS
// =========================================================================

#[test]
fn test_validate_eth_address_valid() {
    let lower = validate_eth_address("0x747afb5c7a7fc34b547cd0fdebf9b91759c5a52b").unwrap();
    assert_eq!(lower, "0x747afb5c7a7fc34b547cd0fdebf9b91759c5a52b");

    let checksum = validate_eth_address("0x747AFb5C7A7FC34b547Cd0FDeBF9B91759c5a52B").unwrap();
    assert_eq!(checksum, "0x747afb5c7a7fc34b547cd0fdebf9b91759c5a52b");
}

#[test]
fn test_validate_eth_address_invalid() {
    // Empty
    assert!(matches!(
        validate_eth_address(""),
        Err(EngineError::InvalidAddress(_))
    ));

    // Missing 0x prefix
    assert!(matches!(
        validate_eth_address("747afb5c7a7fc34b547cd0fdebf9b91759c5a52b"),
        Err(EngineError::InvalidAddress(_))
    ));

    // Too short (41 chars)
    assert!(matches!(
        validate_eth_address("0x747afb5c7a7fc34b547cd0fdebf9b91759c5a52"),
        Err(EngineError::InvalidAddress(_))
    ));

    // Too long (43 chars)
    assert!(matches!(
        validate_eth_address("0x747afb5c7a7fc34b547cd0fdebf9b91759c5a52b1"),
        Err(EngineError::InvalidAddress(_))
    ));

    // Non-hex characters
    assert!(matches!(
        validate_eth_address("0x747afb5c7a7fc34b547cd0fdebf9b91759c5a5zz"),
        Err(EngineError::InvalidAddress(_))
    ));
}

// =========================================================================
// 2. CRYPTOGRAPHIC INTEGRITY & MERKLE TREE TESTS
// =========================================================================

#[test]
fn test_merkle_root_computation() {
    // Empty root is deterministic 64-char hex
    let empty = compute_merkle_root(&[]);
    assert_eq!(empty.len(), 64);

    // Single item root equals Sha256 digest or decoded value
    let d1 = compute_decision_digest("0x1", "ALLOW", 0, "v1", CLEAN_SENDER, None, None, None);
    let root_single = compute_merkle_root(&[d1.clone()]);
    assert_eq!(root_single.len(), 64);

    // Two items
    let d2 = compute_decision_digest("0x2", "BLOCK", 98, "v1", CLEAN_SENDER, None, None, None);
    let root_pair = compute_merkle_root(&[d1.clone(), d2.clone()]);
    assert_eq!(root_pair.len(), 64);
    assert_ne!(root_single, root_pair);

    // Odd number of items (3 items) balances by duplicating last node
    let d3 = compute_decision_digest("0x3", "FLAG", 45, "v1", CLEAN_SENDER, None, None, None);
    let root_triplet = compute_merkle_root(&[d1, d2, d3]);
    assert_eq!(root_triplet.len(), 64);
}

#[test]
fn test_decision_digest_tamper_evident() {
    let original = compute_decision_digest(
        "0xtx1",
        "ALLOW",
        0,
        "policy-v1",
        CLEAN_SENDER,
        Some(CLEAN_RECIPIENT),
        Some("UnknownEOA"),
        None,
    );

    // Altering any parameter changes the digest
    let tampered_decision = compute_decision_digest(
        "0xtx1",
        "BLOCK", // altered
        0,
        "policy-v1",
        CLEAN_SENDER,
        Some(CLEAN_RECIPIENT),
        Some("UnknownEOA"),
        None,
    );
    assert_ne!(original, tampered_decision);

    let tampered_score = compute_decision_digest(
        "0xtx1",
        "ALLOW",
        1, // altered
        "policy-v1",
        CLEAN_SENDER,
        Some(CLEAN_RECIPIENT),
        Some("UnknownEOA"),
        None,
    );
    assert_ne!(original, tampered_score);
}

// =========================================================================
// 3. DETERMINISTIC SCREENING SUITE (DIRECT SANCTIONS, MIXER, MULTIHOP)
// =========================================================================

#[tokio::test]
async fn test_screening_clean_tx() {
    let mock = MockComplianceBackend::new();
    let req = ScreenRequest {
        tx_hash: "0xtx_clean".to_string(),
        sender: CLEAN_SENDER.to_string(),
        recipient: Some(CLEAN_RECIPIENT.to_string()),
        value: Some(100),
        policy: None,
        bundle_id: None,
        value_usd: None,
        vasp_metadata: None,
    };

    let res = evaluate_transaction(&mock, &req).await.unwrap();
    assert_eq!(res.decision, "ALLOW");
    assert_eq!(res.risk_score, 0);
    assert!(res.reasons.is_empty());
    assert!(res.integrity_hash.is_some());
}

#[tokio::test]
async fn test_screening_sanctioned_sender_blocks() {
    let mock = MockComplianceBackend::new().with_sanctioned(vec![SANCTIONED_ADDR]);
    let req = ScreenRequest {
        tx_hash: "0xtx_sanctioned_sender".to_string(),
        sender: SANCTIONED_ADDR.to_string(),
        recipient: Some(CLEAN_RECIPIENT.to_string()),
        value: Some(500),
        policy: None,
        bundle_id: None,
        value_usd: None,
        vasp_metadata: None,
    };

    let res = evaluate_transaction(&mock, &req).await.unwrap();
    assert_eq!(res.decision, "BLOCK");
    assert_eq!(res.risk_score, 98);
    assert!(res.reasons.iter().any(|r| r == "SANCTIONED_SENDER"));
}

#[tokio::test]
async fn test_screening_sanctioned_recipient_blocks() {
    let mock = MockComplianceBackend::new().with_sanctioned(vec![SANCTIONED_ADDR]);
    let req = ScreenRequest {
        tx_hash: "0xtx_sanctioned_recipient".to_string(),
        sender: CLEAN_SENDER.to_string(),
        recipient: Some(SANCTIONED_ADDR.to_string()),
        value: Some(500),
        policy: None,
        bundle_id: None,
        value_usd: None,
        vasp_metadata: None,
    };

    let res = evaluate_transaction(&mock, &req).await.unwrap();
    assert_eq!(res.decision, "BLOCK");
    assert_eq!(res.risk_score, 98);
    assert!(res.reasons.iter().any(|r| r == "SANCTIONED_RECIPIENT"));
}

#[tokio::test]
async fn test_screening_mixer_interaction() {
    let mock = MockComplianceBackend::new().with_entity(MIXER_ADDR, EntityType::Mixer);
    let req = ScreenRequest {
        tx_hash: "0xtx_mixer".to_string(),
        sender: CLEAN_SENDER.to_string(),
        recipient: Some(MIXER_ADDR.to_string()),
        value: Some(100),
        policy: None,
        bundle_id: None,
        value_usd: None,
        vasp_metadata: None,
    };

    let res = evaluate_transaction(&mock, &req).await.unwrap();
    assert_eq!(res.counterparty_entity_type, Some("Mixer".to_string()));
    assert!(res.reasons.iter().any(|r| r == "INTERACTION_WITH_MIXER"));
    assert_eq!(res.risk_score, 45);
    // Since flag_threshold is 40 and block_threshold is 70 in standard policy, 45 evaluates to FLAG
    assert_eq!(res.decision, "FLAG");
}

#[tokio::test]
async fn test_screening_multihop_exposure() {
    // 1-hop exposure
    let mock_1hop = MockComplianceBackend::new().with_multihop(CLEAN_SENDER, 1);
    let req1 = ScreenRequest {
        tx_hash: "0xtx_1hop".to_string(),
        sender: CLEAN_SENDER.to_string(),
        recipient: Some(CLEAN_RECIPIENT.to_string()),
        value: Some(100),
        policy: None,
        bundle_id: None,
        value_usd: None,
        vasp_metadata: None,
    };
    let res1 = evaluate_transaction(&mock_1hop, &req1).await.unwrap();
    assert_eq!(res1.exposure_hop_distance, Some(1));
    assert_eq!(res1.risk_score, 55);
    assert!(res1.reasons.iter().any(|r| r == "INDIRECT_SENDER_EXPOSURE"));
    assert_eq!(res1.decision, "FLAG");

    // 2-hop exposure
    let mock_2hop = MockComplianceBackend::new().with_multihop(CLEAN_SENDER, 2);
    let req2 = ScreenRequest {
        tx_hash: "0xtx_2hop".to_string(),
        sender: CLEAN_SENDER.to_string(),
        recipient: Some(CLEAN_RECIPIENT.to_string()),
        value: Some(100),
        policy: None,
        bundle_id: None,
        value_usd: None,
        vasp_metadata: None,
    };
    let res2 = evaluate_transaction(&mock_2hop, &req2).await.unwrap();
    assert_eq!(res2.exposure_hop_distance, Some(2));
    assert_eq!(res2.risk_score, 25);
    assert!(res2.reasons.iter().any(|r| r == "INDIRECT_SENDER_EXPOSURE_2HOP"));
    // 25 is below flag threshold (40), so standard policy allows it
    assert_eq!(res2.decision, "ALLOW");
}

#[tokio::test]
async fn test_contract_creation_screening() {
    let mock = MockComplianceBackend::new();
    // Contract creation has recipient: None
    let req = ScreenRequest {
        tx_hash: "0xtx_deploy".to_string(),
        sender: CLEAN_SENDER.to_string(),
        recipient: None,
        value: Some(0),
        policy: None,
        bundle_id: None,
        value_usd: None,
        vasp_metadata: None,
    };
    let res = evaluate_transaction(&mock, &req).await.unwrap();
    assert_eq!(res.decision, "ALLOW");
    assert_eq!(res.risk_score, 0);

    // Contract creation from sanctioned sender must be blocked
    let mock_sanctioned = MockComplianceBackend::new().with_sanctioned(vec![SANCTIONED_ADDR]);
    let req_sanctioned = ScreenRequest {
        tx_hash: "0xtx_deploy_sanctioned".to_string(),
        sender: SANCTIONED_ADDR.to_string(),
        recipient: None,
        value: Some(0),
        policy: None,
        bundle_id: None,
        value_usd: None,
        vasp_metadata: None,
    };
    let res_sanctioned = evaluate_transaction(&mock_sanctioned, &req_sanctioned).await.unwrap();
    assert_eq!(res_sanctioned.decision, "BLOCK");
    assert_eq!(res_sanctioned.risk_score, 98);
}

// =========================================================================
// 4. AXUM HTTP ROUTER INTEGRATION TESTS
// =========================================================================

#[tokio::test]
async fn test_http_health_endpoint() {
    let mock = Arc::new(MockComplianceBackend::new());
    let app = create_app(mock);

    let req = Request::builder()
        .uri("/health")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["service"], "compliance-engine");
}

#[tokio::test]
async fn test_http_screen_endpoint_unauthorized() {
    let mock = Arc::new(MockComplianceBackend::new());
    let app = create_app(mock);

    let screen_payload = serde_json::json!({
        "tx_hash": "0xhttp_clean_tx",
        "sender": CLEAN_SENDER,
        "recipient": CLEAN_RECIPIENT,
        "value": 100
    });

    // Request without API key must return 401 Unauthorized
    let req = Request::builder()
        .uri("/screen")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(screen_payload.to_string()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_http_screen_endpoint_allow() {
    let mock = Arc::new(MockComplianceBackend::new());
    let app = create_app(mock);

    let screen_payload = serde_json::json!({
        "tx_hash": "0xhttp_clean_tx",
        "sender": CLEAN_SENDER,
        "recipient": CLEAN_RECIPIENT,
        "value": 100
    });

    let req = Request::builder()
        .uri("/screen")
        .method("POST")
        .header("content-type", "application/json")
        .header("x-engine-api-key", DEV_API_KEY)
        .body(Body::from(screen_payload.to_string()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let screen_res: ScreenResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(screen_res.tx_hash, "0xhttp_clean_tx");
    assert_eq!(screen_res.decision, "ALLOW");
    assert_eq!(screen_res.risk_score, 0);
}

#[tokio::test]
async fn test_http_screen_endpoint_invalid_address() {
    let mock = Arc::new(MockComplianceBackend::new());
    let app = create_app(mock);

    let screen_payload = serde_json::json!({
        "tx_hash": "0xinvalid_addr_tx",
        "sender": "not_an_eth_address",
        "recipient": CLEAN_RECIPIENT
    });

    let req = Request::builder()
        .uri("/screen")
        .method("POST")
        .header("content-type", "application/json")
        .header("x-engine-api-key", DEV_API_KEY)
        .body(Body::from(screen_payload.to_string()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["code"], "INVALID_ADDRESS");
}

#[tokio::test]
async fn test_http_admin_refresh_unauthorized() {
    let mock = Arc::new(MockComplianceBackend::new());
    let app = create_app(mock);

    let req = Request::builder()
        .uri("/admin/refresh")
        .method("POST")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
