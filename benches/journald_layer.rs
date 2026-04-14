//! Criterion benchmarks for the custom journald layer.
//!
//! Measures the per-event work the layer does on every `info!/warn!/error!`
//! call, excluding the kernel-bound `send_to` socket write:
//!
//! - `compose_message`: allocation + format of `"<phrase> k=v k=v ..."`
//! - `write_field` serialization loop for MESSAGE + PRIORITY + each field
//! - The end-to-end cost of everything the layer does per event
//!
//! Three event shapes, matching real fail2ban-rs log sites:
//! - no-field: `info!("executor channel closed")`
//! - 3-field typical: `info!(ip, jail, reason, "ban skipped")`
//! - 7-field maxmind: threshold ban with geo enrichment
#![allow(clippy::missing_docs_in_private_items)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use fail2ban_rs::journald_layer::{compose_message, write_field};

// ---------------------------------------------------------------------------
// Event shapes: owned field vectors so the benchmark isn't measuring the
// cost of building these (that's tracing's visitor, which we measure
// separately via the full per-event path below).
// ---------------------------------------------------------------------------

fn fields_zero() -> Vec<(String, String)> {
    Vec::new()
}

fn fields_three() -> Vec<(String, String)> {
    vec![
        ("ip".to_string(), "1.2.3.4".to_string()),
        ("jail".to_string(), "sshd".to_string()),
        ("reason".to_string(), "no_backend".to_string()),
    ]
}

fn fields_seven() -> Vec<(String, String)> {
    vec![
        ("ip".to_string(), "1.2.3.4".to_string()),
        ("jail".to_string(), "sshd".to_string()),
        ("ban_time".to_string(), "3600".to_string()),
        ("ban_count".to_string(), "1".to_string()),
        ("maxmind_asn".to_string(), "AS15169 Google LLC".to_string()),
        ("maxmind_country".to_string(), "US".to_string()),
        ("maxmind_city".to_string(), "Mountain View".to_string()),
    ]
}

// ---------------------------------------------------------------------------
// compose_message — phrase + logfmt field concatenation.
// ---------------------------------------------------------------------------

fn bench_compose(c: &mut Criterion) {
    let mut g = c.benchmark_group("compose_message");

    let zero = fields_zero();
    g.bench_function("0_fields", |b| {
        b.iter(|| compose_message(black_box("executor channel closed"), black_box(&zero)));
    });

    let three = fields_three();
    g.bench_function("3_fields", |b| {
        b.iter(|| compose_message(black_box("ban skipped"), black_box(&three)));
    });

    let seven = fields_seven();
    g.bench_function("7_fields_maxmind", |b| {
        b.iter(|| compose_message(black_box("banned"), black_box(&seven)));
    });

    g.finish();
}

// ---------------------------------------------------------------------------
// write_field — native-protocol serialization of one key=value pair.
// ---------------------------------------------------------------------------

fn bench_write_field(c: &mut Criterion) {
    let mut g = c.benchmark_group("write_field");

    g.bench_function("short_value", |b| {
        b.iter(|| {
            let mut buf = Vec::with_capacity(64);
            write_field(&mut buf, black_box("IP"), black_box("1.2.3.4"));
            black_box(buf);
        });
    });

    g.bench_function("long_value", |b| {
        b.iter(|| {
            let mut buf = Vec::with_capacity(256);
            write_field(
                &mut buf,
                black_box("MESSAGE"),
                black_box("banned ip=1.2.3.4 jail=sshd ban_time=3600 ban_count=1 reason=threshold"),
            );
            black_box(buf);
        });
    });

    g.finish();
}

// ---------------------------------------------------------------------------
// Per-event — compose MESSAGE + serialize full datagram (MESSAGE, PRIORITY,
// all fields). Everything the layer does between receiving an event and
// the `send_to` syscall.
// ---------------------------------------------------------------------------

fn serialize_event(phrase: &str, fields: &[(String, String)]) -> Vec<u8> {
    let composed = compose_message(phrase, fields);
    let mut buf = Vec::with_capacity(256);
    write_field(&mut buf, "MESSAGE", &composed);
    write_field(&mut buf, "PRIORITY", "5");
    for (k, v) in fields {
        // Uppercase the key per journald convention.
        let upper = k.to_ascii_uppercase();
        write_field(&mut buf, &upper, v);
    }
    buf
}

fn bench_per_event(c: &mut Criterion) {
    let mut g = c.benchmark_group("per_event");

    let zero = fields_zero();
    g.bench_function("0_fields_bare", |b| {
        b.iter(|| serialize_event(black_box("executor channel closed"), black_box(&zero)));
    });

    let three = fields_three();
    g.bench_function("3_fields_typical", |b| {
        b.iter(|| serialize_event(black_box("ban skipped"), black_box(&three)));
    });

    let seven = fields_seven();
    g.bench_function("7_fields_maxmind_ban", |b| {
        b.iter(|| serialize_event(black_box("banned"), black_box(&seven)));
    });

    g.finish();
}

criterion_group!(benches, bench_compose, bench_write_field, bench_per_event);
criterion_main!(benches);
