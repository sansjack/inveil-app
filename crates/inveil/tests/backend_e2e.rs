//! End to end: the real `inveil` binary against a fixture backend that serves signed snapshots and a fake upstream.
#[cfg(test)]
mod fixture;

use fixture::*;
use serde_json::Value;
use std::time::Duration;

const USAGE_WAIT: Duration = Duration::from_secs(15);
const QUIET_PERIOD: Duration = Duration::from_millis(1500);
const REFUSED_EXIT_CODE: i32 = 3;
// The harness blocks its thread while the binary starts, so the fixture servers need a worker of their own.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signed_snapshot_from_the_backend_blocks_ssns_and_its_server_settings_apply() {
    let key = SigningKey::generate();
    let snapshot = snapshot(1, |snapshot| {
        snapshot.settings.deny = vec!["codename-aurora".into()]
    });
    let (backend, _, setup) = backend_serving(&key, &snapshot).await;
    let directory = tempfile::tempdir().unwrap();
    let proxy = RunningProxy::start(directory.path(), &setup);

    let blocked = proxy.post_chat(&chat(SSN_TEXT)).await;
    assert_eq!(blocked.status(), 400);
    let body: Value = blocked.json().await.unwrap();
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("INVEIL BLOCKED"));

    let denied = proxy
        .post_chat(&chat("tell me about codename-aurora"))
        .await;
    assert_eq!(
        denied.status(),
        400,
        "the server's deny term only exists in the signed snapshot:\n{}",
        proxy.log()
    );

    let clean = proxy.post_chat(&chat("hello")).await;
    assert_eq!(clean.status(), 200);
    assert!(echoed_body(clean).await.contains("hello"));
    assert!(proxy.audit_text().contains("\"action\":\"block\""));
    assert!(backend.rules_requests() >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redact_rule_rewrites_the_body_the_upstream_receives() {
    let key = SigningKey::generate();
    let (_, _, setup) = backend_serving(&key, &redacting(1)).await;
    let directory = tempfile::tempdir().unwrap();
    let proxy = RunningProxy::start(directory.path(), &setup);

    let response = proxy.post_chat(&chat(SSN_TEXT)).await;
    assert_eq!(response.status(), 200);
    let sent = echoed_body(response).await;
    assert!(
        sent.contains("[REDACTED:ssn]") && !sent.contains("123-45-6789"),
        "{sent}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshots_signed_by_another_key_or_expired_are_ignored() {
    let key = SigningKey::generate();
    let stranger = SigningKey::generate();
    let upstream = Upstream::start().await;
    let backend = Backend::start().await;
    let setup = Setup::new(&upstream).with_backend(backend.url(), &key);

    for envelope in [
        stranger.sign(&permissive(1)),
        key.sign(&expired(2)),
        "not an envelope".to_string(),
    ] {
        backend.serve(envelope);
        let directory = tempfile::tempdir().unwrap();
        let proxy = RunningProxy::start(directory.path(), &setup);
        let response = proxy.post_chat(&chat(SSN_TEXT)).await;
        assert_eq!(response.status(), 400, "the built-in rules still apply");
    }
    assert!(backend.rules_requests() >= 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_older_snapshot_cannot_replace_one_already_accepted() {
    let key = SigningKey::generate();
    let (backend, upstream, setup) = backend_serving(&key, &redacting(5)).await;
    let directory = tempfile::tempdir().unwrap();
    {
        let proxy = RunningProxy::start(directory.path(), &setup);
        let sent = echoed_body(proxy.post_chat(&chat(SSN_TEXT)).await).await;
        assert!(
            sent.contains("[REDACTED:ssn]"),
            "version 5 is in force: {sent}"
        );
    }

    backend.serve(key.sign(&permissive(4)));
    let proxy = RunningProxy::start(
        directory.path(),
        &Setup::new(&upstream).with_backend(backend.url(), &key),
    );
    let sent = echoed_body(proxy.post_chat(&chat(SSN_TEXT)).await).await;
    assert!(
        sent.contains("[REDACTED:ssn]"),
        "version 4 was refused and the cached version 5 stays: {sent}"
    );

    let conflicting = snapshot(5, |snapshot| {
        snapshot.settings.deny = vec!["extra".into()];
        for rule in &mut snapshot.pii {
            rule.action = contract::Action::Log;
        }
    });
    backend.serve(key.sign(&conflicting));
    let proxy = RunningProxy::start(
        directory.path(),
        &Setup::new(&upstream).with_backend(backend.url(), &key),
    );
    let sent = echoed_body(proxy.post_chat(&chat(SSN_TEXT)).await).await;
    assert!(
        sent.contains("[REDACTED:ssn]"),
        "same version, different content: {sent}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_upstream_outside_allowed_upstreams_stops_the_proxy_from_starting() {
    let key = SigningKey::generate();
    let snapshot = snapshot(1, |snapshot| {
        snapshot.settings.allowed_upstreams = vec!["https://api.anthropic.com".into()];
    });
    let (_, _, setup) = backend_serving(&key, &snapshot).await;
    let directory = tempfile::tempdir().unwrap();
    let (status, log) = RunningProxy::start_expecting_exit(directory.path(), &setup);
    assert_eq!(status.code(), Some(REFUSED_EXIT_CODE), "{log}");
    assert!(
        log.contains("not one of the upstreams the policy allows"),
        "{log}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_upstream_on_the_allowed_list_runs() {
    let key = SigningKey::generate();
    let upstream = Upstream::start().await;
    let snapshot = snapshot(1, |snapshot| {
        snapshot.settings.allowed_upstreams = vec![upstream.url()]
    });
    let backend = Backend::start().await;
    backend.serve(key.sign(&snapshot));
    let directory = tempfile::tempdir().unwrap();
    let proxy = RunningProxy::start(
        directory.path(),
        &Setup::new(&upstream).with_backend(backend.url(), &key),
    );
    assert_eq!(proxy.post_chat(&chat("hello")).await.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_dry_run_cannot_override_a_server_that_enforces() {
    let key = SigningKey::generate();
    let upstream = Upstream::start().await;
    let backend = Backend::start().await;

    backend.serve(key.sign(&snapshot(1, |snapshot| {
        snapshot.settings.dry_run = Some(false)
    })));
    let setup = Setup::new(&upstream)
        .with_backend(backend.url(), &key)
        .top_level("dry_run = true");
    let directory = tempfile::tempdir().unwrap();
    let enforced = RunningProxy::start(directory.path(), &setup);
    assert_eq!(enforced.post_chat(&chat(SSN_TEXT)).await.status(), 400);

    backend.serve(key.sign(&snapshot(2, |_| {})));
    let directory = tempfile::tempdir().unwrap();
    let dry = RunningProxy::start(directory.path(), &setup);
    assert_eq!(
        dry.post_chat(&chat(SSN_TEXT)).await.status(),
        200,
        "the server left the choice to the local file"
    );
    assert!(dry.audit_text().contains("dry_run"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_with_a_foreign_host_or_an_origin_are_rejected() {
    let upstream = Upstream::start().await;
    let directory = tempfile::tempdir().unwrap();
    let proxy = RunningProxy::start(directory.path(), &Setup::new(&upstream));
    let url = format!("{}/v1/messages", proxy.address);

    let rebinding = client()
        .post(&url)
        .header("host", "attacker.example")
        .json(&chat("hi"))
        .send()
        .await
        .unwrap();
    assert_eq!(rebinding.status(), 403);
    let web_page = client()
        .post(&url)
        .header("origin", "https://attacker.example")
        .json(&chat("hi"))
        .send()
        .await
        .unwrap();
    assert_eq!(web_page.status(), 403);
    assert_eq!(proxy.post_chat(&chat("hi")).await.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_mode_makes_no_network_calls_at_all() {
    let key = SigningKey::generate();
    let tripwire = Tripwire::start().await;
    let upstream = Upstream::start().await;
    let configuration = |offline: bool| {
        Setup::new(&upstream)
            .with_backend(format!("http://{}", tripwire.address), &key)
            .top_level(&format!("offline = {offline}"))
            .table("[usage]\nsink = \"http\"")
            .table("[auth]\nmode = \"none\"")
    };

    let directory = tempfile::tempdir().unwrap();
    let offline = RunningProxy::start(directory.path(), &configuration(true));
    assert_eq!(offline.post_chat(&chat("hello")).await.status(), 200);
    assert_eq!(
        offline.post_chat(&chat(SSN_TEXT)).await.status(),
        400,
        "the built-in rules still protect"
    );
    tokio::time::sleep(QUIET_PERIOD).await;
    assert_eq!(tripwire.connections(), 0, "offline touched the network");
    drop(offline);

    let directory = tempfile::tempdir().unwrap();
    let online = RunningProxy::start(directory.path(), &configuration(false));
    assert_eq!(online.post_chat(&chat("hello")).await.status(), 200);
    assert!(
        tripwire.connections() > 0,
        "the tripwire must notice a client that is online"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signed_local_rules_file_works_with_no_backend_and_no_network() {
    let key = SigningKey::generate();
    let tripwire = Tripwire::start().await;
    let upstream = Upstream::start().await;
    let directory = tempfile::tempdir().unwrap();
    let rules_file = directory.path().join("rules.signed.json");
    std::fs::write(&rules_file, key.sign(&redacting(1))).unwrap();

    let setup = Setup::new(&upstream)
        .with_backend(format!("http://{}", tripwire.address), &key)
        .top_level(&format!(
            "offline = true\nrules_file = '{}'",
            rules_file.display()
        ));
    let proxy = RunningProxy::start(directory.path(), &setup);
    let sent = echoed_body(proxy.post_chat(&chat(SSN_TEXT)).await).await;
    assert!(sent.contains("[REDACTED:ssn]"), "{sent}");
    tokio::time::sleep(QUIET_PERIOD).await;
    assert_eq!(tripwire.connections(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_required_reporting_cannot_be_disabled_or_dodged_with_offline() {
    let key = SigningKey::generate();
    let required = snapshot(3, |snapshot| {
        snapshot.settings.usage_reporting = Some(contract::UsageReporting::Required);
        snapshot.settings.heartbeat_seconds = Some(1);
    });
    let (backend, _, setup) = backend_serving(&key, &required).await;
    let setup = setup
        .top_level("mode = \"managed\"\noffline = true")
        .table("[usage]\nsink = \"none\"");
    let directory = tempfile::tempdir().unwrap();
    let proxy = RunningProxy::start(directory.path(), &setup);

    let batches = backend.wait_for_usage(USAGE_WAIT).await;
    assert!(
        !batches.is_empty(),
        "a heartbeat must arrive although the local sink is none and offline is set"
    );
    let client = &batches[0].client;
    assert_eq!(client.policy_version, 3);
    assert_eq!(client.config_hash.len(), 64);
    assert!(
        batches[0].events.is_empty(),
        "an idle client still reports in"
    );
    drop(proxy);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_managed_client_with_optional_reporting_sends_heartbeats_without_events() {
    let key = SigningKey::generate();
    let optional = snapshot(1, |snapshot| {
        snapshot.settings.usage_reporting = Some(contract::UsageReporting::Optional);
        snapshot.settings.heartbeat_seconds = Some(1);
    });
    let (backend, _, setup) = backend_serving(&key, &optional).await;
    let setup = setup
        .top_level("mode = \"managed\"")
        .table("[usage]\nsink = \"none\"");
    let directory = tempfile::tempdir().unwrap();
    let proxy = RunningProxy::start(directory.path(), &setup);

    let first = backend.wait_for_usage(USAGE_WAIT).await;
    assert!(!first.is_empty(), "a heartbeat must arrive");
    proxy.post_chat(&chat(SSN_TEXT)).await;
    tokio::time::sleep(QUIET_PERIOD * 2).await;
    let batches = backend.state.usage_batches.lock().unwrap().clone();
    assert!(
        batches.iter().all(|batch| batch.events.is_empty()),
        "events stay local when the local sink is none"
    );
    drop(proxy);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_managed_client_stays_silent_when_the_server_disables_reporting() {
    let key = SigningKey::generate();
    let disabled = snapshot(1, |snapshot| {
        snapshot.settings.usage_reporting = Some(contract::UsageReporting::Disabled);
        snapshot.settings.heartbeat_seconds = Some(1);
    });
    let (backend, _, setup) = backend_serving(&key, &disabled).await;
    let setup = setup
        .top_level("mode = \"managed\"")
        .table("[usage]\nsink = \"none\"");
    let directory = tempfile::tempdir().unwrap();
    let proxy = RunningProxy::start(directory.path(), &setup);

    tokio::time::sleep(QUIET_PERIOD).await;
    proxy.post_chat(&chat("hello")).await;
    tokio::time::sleep(QUIET_PERIOD).await;
    assert!(backend.state.usage_batches.lock().unwrap().is_empty());
    drop(proxy);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standalone_usage_events_reach_the_backend_without_prompt_content() {
    let key = SigningKey::generate();
    let (backend, _, setup) = backend_serving(&key, &snapshot(1, |_| {})).await;
    let setup = setup.table("[usage]\nsink = \"http\"");
    let directory = tempfile::tempdir().unwrap();
    let proxy = RunningProxy::start(directory.path(), &setup);

    proxy
        .post_chat(&chat(&format!("{SSN_TEXT} SENTINEL-PROMPT")))
        .await;
    let batches = backend.wait_for_usage(USAGE_WAIT).await;
    let event = &batches.first().expect("a usage batch").events[0];
    assert!(event.blocked && event.status == 400 && event.findings == 1);
    assert!(!serde_json::to_string(&batches)
        .unwrap()
        .contains("SENTINEL-PROMPT"));
}

fn unscannable_mode(mode: contract::FailMode) -> impl FnOnce(&mut contract::Snapshot) {
    move |snapshot| snapshot.settings.failure_modes.unscannable = Some(mode)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_body_is_blocked_when_the_unscannable_mode_is_closed() {
    let key = SigningKey::generate();
    let closed = snapshot(1, unscannable_mode(contract::FailMode::Closed));
    let (_, _, setup) = backend_serving(&key, &closed).await;
    let directory = tempfile::tempdir().unwrap();
    let proxy = RunningProxy::start(directory.path(), &setup);

    let response = proxy.post_unreadable_chat().await;
    assert_eq!(response.status(), 400, "{}", proxy.log());
    let audit = proxy.audit_text();
    assert!(audit.contains("\"action\":\"block\""), "{audit}");
    assert!(!audit.contains("fail_open"), "{audit}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_body_is_passed_audited_and_counted_when_the_unscannable_mode_is_open() {
    let key = SigningKey::generate();
    let open = snapshot(1, unscannable_mode(contract::FailMode::Open));
    let (backend, _, setup) = backend_serving(&key, &open).await;
    let setup = setup.table("[usage]\nsink = \"http\"");
    let directory = tempfile::tempdir().unwrap();
    let proxy = RunningProxy::start(directory.path(), &setup);

    let response = proxy.post_unreadable_chat().await;
    assert_eq!(response.status(), 200, "{}", proxy.log());
    assert_eq!(echoed_body(response).await, UNREADABLE_BODY);
    let audit = proxy.audit_text();
    assert!(audit.contains("\"action\":\"fail_open\""), "{audit}");
    assert!(audit.contains("\"condition\":\"unscannable\""), "{audit}");

    let batches = backend.wait_for_usage(USAGE_WAIT).await;
    let client = &batches.first().expect("a usage batch").client;
    assert_eq!(client.fail_open_count, 1);
    let modes = client.failure_modes.as_ref().expect("the active modes");
    assert_eq!(modes.unscannable, Some(contract::FailMode::Open));
    assert_eq!(modes.service_down, Some(contract::FailMode::Open));
    assert_eq!(modes.policy_expired, Some(contract::FailMode::Closed));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_configuration_can_tighten_an_open_mode_through_either_key() {
    let key = SigningKey::generate();
    let open = snapshot(1, unscannable_mode(contract::FailMode::Open));
    for tighten in [
        "block_unscannable = true",
        "[failure_modes]\nunscannable = \"closed\"",
    ] {
        let (_, _, setup) = backend_serving(&key, &open).await;
        let tightened = if tighten.starts_with('[') {
            setup.table(tighten)
        } else {
            setup.top_level(tighten)
        };
        let directory = tempfile::tempdir().unwrap();
        let proxy = RunningProxy::start(directory.path(), &tightened);
        assert_eq!(proxy.post_unreadable_chat().await.status(), 400);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standalone_local_open_passes_an_unreadable_body_and_audits_it() {
    for local_open in [
        "[failure_modes]\nunscannable = \"open\"",
        "block_unscannable = false",
    ] {
        let upstream = Upstream::start().await;
        let setup = Setup::new(&upstream);
        let setup = if local_open.starts_with('[') {
            setup.table(local_open)
        } else {
            setup.top_level(local_open)
        };
        let directory = tempfile::tempdir().unwrap();
        let proxy = RunningProxy::start(directory.path(), &setup);

        let response = proxy.post_unreadable_chat().await;
        assert_eq!(response.status(), 200, "{}", proxy.log());
        assert_eq!(echoed_body(response).await, UNREADABLE_BODY);
        let audit = proxy.audit_text();
        assert!(audit.contains("\"action\":\"fail_open\""), "{audit}");
        assert!(audit.contains("\"condition\":\"unscannable\""), "{audit}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signed_closed_mode_beats_a_standalone_local_open() {
    let key = SigningKey::generate();
    let closed = snapshot(1, unscannable_mode(contract::FailMode::Closed));
    let (_, _, setup) = backend_serving(&key, &closed).await;
    let setup = setup.table("[failure_modes]\nunscannable = \"open\"");
    let directory = tempfile::tempdir().unwrap();
    let proxy = RunningProxy::start(directory.path(), &setup);
    assert_eq!(proxy.post_unreadable_chat().await.status(), 400);
}
