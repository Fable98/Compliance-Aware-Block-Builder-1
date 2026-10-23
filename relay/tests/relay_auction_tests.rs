use relay::{
    BidVerdict, StoredBid, TxItem, filter_valid_transactions, parse_value_wei,
    select_best_compliant_header,
};
use std::collections::HashSet;

// Helper to construct a StoredBid for auction tests
fn create_test_bid(
    bid_id: &str,
    slot: u64,
    builder_id: &str,
    value_wei_str: &str,
    verdict: BidVerdict,
) -> StoredBid {
    let (_, val_num) = parse_value_wei(&serde_json::json!(value_wei_str));
    StoredBid {
        bid_id: bid_id.to_string(),
        slot,
        block_hash: format!("0xblock_{}", bid_id),
        builder_id: builder_id.to_string(),
        builder_pubkey: format!("0xpub_{}", builder_id),
        fee_recipient: format!("0xfee_{}", builder_id),
        value_wei: value_wei_str.to_string(),
        value_wei_num: val_num,
        verdict,
        reasons: vec![],
        txs: vec![],
        tx_count: 0,
        created_at: "2026-10-23T12:00:00Z".to_string(),
    }
}

// Helper to construct a TxItem
fn create_test_tx(hash: &str, sender: &str, recipient: &str, bundle_id: Option<&str>) -> TxItem {
    TxItem {
        hash: hash.to_string(),
        sender: sender.to_string(),
        recipient: Some(recipient.to_string()),
        value: Some(serde_json::json!(100)),
        bundle_id: bundle_id.map(|s| s.to_string()),
        value_usd: None,
        vasp_metadata: None,
    }
}

// =========================================================================
// 1. VALUE WEI PARSING TESTS
// =========================================================================

#[test]
fn test_parse_value_wei_hex_variations() {
    // Standard 0x hex
    let (s, n) = parse_value_wei(&serde_json::json!("0xff"));
    assert_eq!(s, "255");
    assert_eq!(n, 255);

    // Uppercase 0X hex
    let (s, n) = parse_value_wei(&serde_json::json!("0X100"));
    assert_eq!(s, "256");
    assert_eq!(n, 256);

    // 1 ETH in hex: 0xde0b6b3a7640000
    let (s, n) = parse_value_wei(&serde_json::json!("0xde0b6b3a7640000"));
    assert_eq!(s, "1000000000000000000");
    assert_eq!(n, 1000000000000000000u128);
}

#[test]
fn test_parse_value_wei_fallback_and_edge_cases() {
    // Empty string
    let (s, n) = parse_value_wei(&serde_json::json!(""));
    assert_eq!(s, "");
    assert_eq!(n, 0);

    // Non-numeric string
    let (s, n) = parse_value_wei(&serde_json::json!("not_a_number"));
    assert_eq!(s, "not_a_number");
    assert_eq!(n, 0);

    // Null JSON value
    let (s, n) = parse_value_wei(&serde_json::Value::Null);
    assert_eq!(s, "0");
    assert_eq!(n, 0);

    // Boolean JSON value
    let (s, n) = parse_value_wei(&serde_json::json!(true));
    assert_eq!(s, "0");
    assert_eq!(n, 0);
}

// =========================================================================
// 2. AUCTION GATEKEEPER & WINNER SELECTION TESTS
// =========================================================================

#[test]
fn test_auction_selects_highest_compliant_bid() {
    let slot = 100;
    let bids = vec![
        // Highest bid: 10 ETH, but contains sanctioned transaction
        create_test_bid("b1", slot, "builder-sanctioned", "10000000000000000000", BidVerdict::ExposedTx),
        // Second highest: 8 ETH, but builder fee recipient is on OFAC SDN
        create_test_bid("b2", slot, "builder-bad-coinbase", "8000000000000000000", BidVerdict::ExposedBuilder),
        // Third highest: 5 ETH, fully compliant
        create_test_bid("b3", slot, "builder-clean-high", "5000000000000000000", BidVerdict::Compliant),
        // Lowest bid: 1 ETH, compliant
        create_test_bid("b4", slot, "builder-clean-low", "1000000000000000000", BidVerdict::Compliant),
    ];

    let winner = select_best_compliant_header(&bids, slot).expect("Must return a compliant winner");
    assert_eq!(winner.builder_id, "builder-clean-high");
    assert_eq!(winner.value_wei, "5000000000000000000");
}

#[test]
fn test_auction_pending_bids_cannot_win() {
    let slot = 200;
    let bids = vec![
        // High bid pending audit
        create_test_bid("b1", slot, "builder-pending", "9000000000000000000", BidVerdict::Pending),
        // Low bid compliant
        create_test_bid("b2", slot, "builder-compliant", "1000000000000000000", BidVerdict::Compliant),
    ];

    let winner = select_best_compliant_header(&bids, slot).expect("Must return compliant winner");
    assert_eq!(winner.builder_id, "builder-compliant");
}

#[test]
fn test_auction_fail_closed_when_all_bids_exposed() {
    let slot = 300;
    let bids = vec![
        create_test_bid("b1", slot, "builder-1", "5000000000000000000", BidVerdict::ExposedTx),
        create_test_bid("b2", slot, "builder-2", "4000000000000000000", BidVerdict::ExposedBuilder),
        create_test_bid("b3", slot, "builder-3", "3000000000000000000", BidVerdict::ExposedTx),
    ];

    // Must fail closed (return None) rather than proposing a tainted header
    assert!(select_best_compliant_header(&bids, slot).is_none());
}

#[test]
fn test_auction_unpopulated_slot_returns_none() {
    let bids = vec![
        create_test_bid("b1", 10, "builder-clean", "1000000000000000000", BidVerdict::Compliant),
    ];

    // Querying for slot 999 where no bids exist returns None
    assert!(select_best_compliant_header(&bids, 999).is_none());
}

#[test]
fn test_auction_slot_isolation() {
    let bids = vec![
        create_test_bid("b_slot10", 10, "builder-slot-10", "1000000000000000000", BidVerdict::Compliant),
        create_test_bid("b_slot20", 20, "builder-slot-20", "2000000000000000000", BidVerdict::Compliant),
    ];

    let winner10 = select_best_compliant_header(&bids, 10).unwrap();
    assert_eq!(winner10.builder_id, "builder-slot-10");

    let winner20 = select_best_compliant_header(&bids, 20).unwrap();
    assert_eq!(winner20.builder_id, "builder-slot-20");
}

// =========================================================================
// 3. ATOMIC BUNDLE FILTERING TESTS
// =========================================================================

#[test]
fn test_bundle_atomicity_multi_bundle_isolation() {
    // Bundle A has 2 txs: txA1 (clean) and txA2 (blocked)
    let tx_a1 = create_test_tx("0xtxA1", "0xuser1", "0xrecip1", Some("bundle-A"));
    let tx_a2 = create_test_tx("0xtxA2", "0xuser2", "0xrecip2", Some("bundle-A"));

    // Bundle B has 2 txs: txB1 (clean) and txB2 (clean)
    let tx_b1 = create_test_tx("0xtxB1", "0xuser3", "0xrecip3", Some("bundle-B"));
    let tx_b2 = create_test_tx("0xtxB2", "0xuser4", "0xrecip4", Some("bundle-B"));

    // Standalone clean transaction
    let tx_standalone = create_test_tx("0xtxSingle", "0xuser5", "0xrecip5", None);

    let all_txs = vec![tx_a1, tx_a2, tx_b1, tx_b2, tx_standalone];

    // Simulate screening result: txA2 blocked => bundle-A dead
    let mut blocked_txs = HashSet::new();
    blocked_txs.insert("0xtxA2".to_string());

    let mut dead_bundles = HashSet::new();
    dead_bundles.insert("bundle-A".to_string());

    let surviving_txs = filter_valid_transactions(&all_txs, &blocked_txs, &dead_bundles);

    // Bundle A is completely purged (both txA1 and txA2 dropped)
    // Bundle B and standalone tx survive
    assert_eq!(surviving_txs.len(), 3);
    let surviving_hashes: Vec<&str> = surviving_txs.iter().map(|t| t.hash.as_str()).collect();
    assert!(surviving_hashes.contains(&"0xtxB1"));
    assert!(surviving_hashes.contains(&"0xtxB2"));
    assert!(surviving_hashes.contains(&"0xtxSingle"));
    assert!(!surviving_hashes.contains(&"0xtxA1"));
    assert!(!surviving_hashes.contains(&"0xtxA2"));
}

#[test]
fn test_standalone_blocked_tx_does_not_affect_other_txs() {
    let tx1 = create_test_tx("0xtx1", "0xuser1", "0xrecip1", None);
    let tx2_blocked = create_test_tx("0xtx2", "0xsanctioned", "0xrecip2", None);
    let tx3 = create_test_tx("0xtx3", "0xuser3", "0xrecip3", None);

    let all_txs = vec![tx1, tx2_blocked, tx3];
    let mut blocked_txs = HashSet::new();
    blocked_txs.insert("0xtx2".to_string());
    let dead_bundles = HashSet::new();

    let surviving = filter_valid_transactions(&all_txs, &blocked_txs, &dead_bundles);
    assert_eq!(surviving.len(), 2);
    assert_eq!(surviving[0].hash, "0xtx1");
    assert_eq!(surviving[1].hash, "0xtx3");
}

// =========================================================================
// 4. VERDICT ENUM & REASON AUDIT TRAIL TESTS
// =========================================================================

#[test]
fn test_verdict_string_representations() {
    assert_eq!(BidVerdict::Pending.as_str(), "PENDING");
    assert_eq!(BidVerdict::Compliant.as_str(), "COMPLIANT");
    assert_eq!(BidVerdict::ExposedTx.as_str(), "EXPOSED_TX");
    assert_eq!(BidVerdict::ExposedBuilder.as_str(), "EXPOSED_BUILDER");
}
