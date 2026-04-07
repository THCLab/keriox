use cesrox::parse_many;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use keri_core::{
    actor::prelude::{BasicProcessor, EventStorage},
    database::redb::RedbDatabase,
    event_message::signed_event_message::Notice,
};
use std::{hint::black_box, path::Path, sync::Arc};

fn setup_processor() -> (
    Arc<BasicProcessor<RedbDatabase>>,
    EventStorage<RedbDatabase>,
) {
    use tempfile::{Builder, NamedTempFile};

    use keri_core::processor::escrow::{default_escrow_bus, EscrowConfig};
    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    std::fs::create_dir_all(root.path()).unwrap();

    let events_db_path = NamedTempFile::new().unwrap();
    let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
    let (not_bus, _escrows) =
        default_escrow_bus(events_db.clone(), EscrowConfig::default(), None);

    let (processor, storage) = (
        BasicProcessor::new(events_db.clone(), Some(not_bus)),
        EventStorage::new(events_db.clone()),
    );
    (Arc::new(processor), storage)
}

fn load_input<P: AsRef<Path>>(path: &P) -> Vec<u8> {
    // Read the entire file into a string
    let mut content = std::fs::read_to_string(path).unwrap();

    // Remove all newline characters
    content = content.replace("\n", "").replace("\r", "");
    content.as_bytes().to_vec()
}

fn process_stream(processor: Arc<BasicProcessor<RedbDatabase>>, stream: &[u8]) {
    let (_rest, parsed) = parse_many(black_box(&stream)).unwrap();
    let notices: Result<Vec<_>, _> = parsed.into_iter().map(Notice::try_from).collect();
    for notice in notices.unwrap() {
        keri_core::actor::process_notice(notice, processor.as_ref()).unwrap()
    }
}

fn process_events_stream(c: &mut Criterion) {
    let mut group = c.benchmark_group("Processing events stream");
    group.measurement_time(std::time::Duration::from_secs(15));
    group.sample_size(10);

    // Preload input data
    let input_3 = load_input(&format!("{}/benches/3_kel.txt", env!("CARGO_MANIFEST_DIR")));
    let input_50 = load_input(&format!(
        "{}/benches/50_kel.txt",
        env!("CARGO_MANIFEST_DIR")
    ));
    let input_100 = load_input(&format!(
        "{}/benches/100_kel.txt",
        env!("CARGO_MANIFEST_DIR")
    ));

    group.bench_function("process_3_events", |b| {
        b.iter_batched(
            setup_processor,
            |(processor, _)| {
                process_stream(processor, black_box(&input_3));
            },
            BatchSize::PerIteration,
        )
    });

    group.bench_function("process_50_events", |b| {
        b.iter_batched(
            setup_processor,
            |(processor, _)| {
                process_stream(processor, black_box(&input_50));
            },
            BatchSize::PerIteration,
        )
    });

    group.bench_function("process_100_events", |b| {
        b.iter_batched(
            setup_processor,
            |(processor, _)| {
                process_stream(processor, black_box(&input_100));
            },
            BatchSize::PerIteration,
        )
    });
}

criterion_group!(benches, process_events_stream);
criterion_main!(benches);
