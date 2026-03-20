use super::*;
use std::collections::BTreeSet;
use tokio::io::duplex;
use tokio::net::TcpListener;
use tokio::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum PathClass {
    ConnectFail,
    ConnectSuccess,
    SlowBackend,
}

fn mean_ms(samples: &[u128]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let sum: u128 = samples.iter().copied().sum();
    sum as f64 / samples.len() as f64
}

async fn measure_masking_duration_ms(path: PathClass, timing_norm_enabled: bool) -> u128 {
    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_timing_normalization_enabled = timing_norm_enabled;
    config.censorship.mask_timing_normalization_floor_ms = 220;
    config.censorship.mask_timing_normalization_ceiling_ms = 260;

    let accept_task = match path {
        PathClass::ConnectFail => {
            config.censorship.mask_host = Some("127.0.0.1".to_string());
            config.censorship.mask_port = 1;
            None
        }
        PathClass::ConnectSuccess => {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let backend_addr = listener.local_addr().unwrap();
            config.censorship.mask_host = Some("127.0.0.1".to_string());
            config.censorship.mask_port = backend_addr.port();
            Some(tokio::spawn(async move {
                let (_stream, _) = listener.accept().await.unwrap();
            }))
        }
        PathClass::SlowBackend => {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let backend_addr = listener.local_addr().unwrap();
            config.censorship.mask_host = Some("127.0.0.1".to_string());
            config.censorship.mask_port = backend_addr.port();
            Some(tokio::spawn(async move {
                let (_stream, _) = listener.accept().await.unwrap();
                tokio::time::sleep(Duration::from_millis(320)).await;
            }))
        }
    };

    let (client_reader, _client_writer) = duplex(1024);
    let (_client_visible_reader, client_visible_writer) = duplex(1024);

    let peer: SocketAddr = "198.51.100.230:57230".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let started = Instant::now();
    handle_bad_client(
        client_reader,
        client_visible_writer,
        b"GET /ab-harness HTTP/1.1\r\nHost: x\r\n\r\n",
        peer,
        local,
        &config,
        &beobachten,
    )
    .await;

    if let Some(task) = accept_task {
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    started.elapsed().as_millis()
}

async fn capture_above_cap_forwarded_len(
    body_sent: usize,
    above_cap_blur_enabled: bool,
    above_cap_blur_max_bytes: usize,
) -> usize {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_shape_hardening = true;
    config.censorship.mask_shape_bucket_floor_bytes = 512;
    config.censorship.mask_shape_bucket_cap_bytes = 4096;
    config.censorship.mask_shape_above_cap_blur = above_cap_blur_enabled;
    config.censorship.mask_shape_above_cap_blur_max_bytes = above_cap_blur_max_bytes;

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut got)).await;
        got.len()
    });

    let (client_reader, mut client_writer) = duplex(64 * 1024);
    let (_client_visible_reader, client_visible_writer) = duplex(64 * 1024);

    let peer: SocketAddr = "198.51.100.231:57231".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let mut initial = vec![0u8; 5 + body_sent];
    initial[0] = 0x16;
    initial[1] = 0x03;
    initial[2] = 0x01;
    initial[3..5].copy_from_slice(&7000u16.to_be_bytes());
    initial[5..].fill(0x5A);

    let fallback_task = tokio::spawn(async move {
        handle_bad_client(
            client_reader,
            client_visible_writer,
            &initial,
            peer,
            local,
            &config,
            &beobachten,
        )
        .await;
    });

    client_writer.shutdown().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(4), fallback_task)
        .await
        .unwrap()
        .unwrap();

    tokio::time::timeout(Duration::from_secs(4), accept_task)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn integration_ab_harness_envelope_and_blur_improve_obfuscation_vs_baseline() {
    const ITER: usize = 8;

    let mut baseline_fail = Vec::with_capacity(ITER);
    let mut baseline_success = Vec::with_capacity(ITER);
    let mut baseline_slow = Vec::with_capacity(ITER);

    let mut hardened_fail = Vec::with_capacity(ITER);
    let mut hardened_success = Vec::with_capacity(ITER);
    let mut hardened_slow = Vec::with_capacity(ITER);

    for _ in 0..ITER {
        baseline_fail.push(measure_masking_duration_ms(PathClass::ConnectFail, false).await);
        baseline_success.push(measure_masking_duration_ms(PathClass::ConnectSuccess, false).await);
        baseline_slow.push(measure_masking_duration_ms(PathClass::SlowBackend, false).await);

        hardened_fail.push(measure_masking_duration_ms(PathClass::ConnectFail, true).await);
        hardened_success.push(measure_masking_duration_ms(PathClass::ConnectSuccess, true).await);
        hardened_slow.push(measure_masking_duration_ms(PathClass::SlowBackend, true).await);
    }

    let baseline_means = [
        mean_ms(&baseline_fail),
        mean_ms(&baseline_success),
        mean_ms(&baseline_slow),
    ];
    let hardened_means = [
        mean_ms(&hardened_fail),
        mean_ms(&hardened_success),
        mean_ms(&hardened_slow),
    ];

    let baseline_range = baseline_means
        .iter()
        .copied()
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(mn, mx), v| {
            (mn.min(v), mx.max(v))
        });
    let hardened_range = hardened_means
        .iter()
        .copied()
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(mn, mx), v| {
            (mn.min(v), mx.max(v))
        });

    let baseline_spread = baseline_range.1 - baseline_range.0;
    let hardened_spread = hardened_range.1 - hardened_range.0;

    println!(
        "ab_harness_timing baseline_means={:?} hardened_means={:?} baseline_spread={:.2} hardened_spread={:.2}",
        baseline_means, hardened_means, baseline_spread, hardened_spread
    );

    assert!(
        hardened_spread < baseline_spread,
        "timing envelope should reduce cross-path mean spread: baseline={baseline_spread:.2} hardened={hardened_spread:.2}"
    );

    let mut baseline_a = BTreeSet::new();
    let mut baseline_b = BTreeSet::new();
    let mut hardened_a = BTreeSet::new();
    let mut hardened_b = BTreeSet::new();

    for _ in 0..24 {
        baseline_a.insert(capture_above_cap_forwarded_len(5000, false, 0).await);
        baseline_b.insert(capture_above_cap_forwarded_len(5040, false, 0).await);

        hardened_a.insert(capture_above_cap_forwarded_len(5000, true, 96).await);
        hardened_b.insert(capture_above_cap_forwarded_len(5040, true, 96).await);
    }

    let baseline_overlap = baseline_a.intersection(&baseline_b).count();
    let hardened_overlap = hardened_a.intersection(&hardened_b).count();

    println!(
        "ab_harness_length baseline_overlap={} hardened_overlap={} baseline_a={} baseline_b={} hardened_a={} hardened_b={}",
        baseline_overlap,
        hardened_overlap,
        baseline_a.len(),
        baseline_b.len(),
        hardened_a.len(),
        hardened_b.len()
    );

    assert_eq!(baseline_overlap, 0, "baseline above-cap classes should be disjoint");
    assert!(
        hardened_overlap > baseline_overlap,
        "above-cap blur should increase cross-class overlap: baseline={} hardened={}",
        baseline_overlap,
        hardened_overlap
    );
}
