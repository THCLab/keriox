pub use crate::{
    watcher::{config::WatcherConfig, Watcher},
    watcher_listener::WatcherListener,
};

#[cfg(test)]
mod test;
mod watcher;
pub mod watcher_listener;
