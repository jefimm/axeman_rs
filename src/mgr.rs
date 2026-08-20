use anyhow::anyhow;
use crossbeam_channel::{bounded, Receiver, Sender};
use std::cmp::max;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

struct Shutdown {
    stop: AtomicBool,
    error: Mutex<Option<anyhow::Error>>,
}

impl Shutdown {
    fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
            error: Mutex::new(None),
        }
    }

    fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    fn request_stop(&self, err: anyhow::Error) {
        if let Ok(mut slot) = self.error.lock() {
            if slot.is_none() {
                *slot = Some(err);
            }
        }
        self.stop.store(true, Ordering::Release);
    }

    fn take_error(&self) -> Option<anyhow::Error> {
        self.error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }
}

pub(crate) struct WorkManager<D: Send + 'static> {
    threads: Vec<thread::JoinHandle<()>>,
    work_channel: Option<Sender<D>>,
    shutdown: Arc<Shutdown>,
}

pub(crate) trait ChannelWorker<T> {
    fn handle(&self, work: T) -> anyhow::Result<()>;
}

impl<D: Send + 'static> WorkManager<D> {
    pub(crate) fn new<W: ChannelWorker<D> + Clone + Send + Sync + 'static>(
        size: usize,
        worker: W,
    ) -> WorkManager<D> {
        let shutdown = Arc::new(Shutdown::new());
        let (s, r) = bounded::<D>(max(size * 10, 1000));

        let threads = (0..size.max(1))
            .map(|_| {
                let r_clone = r.clone();
                let worker_clone = worker.clone();
                let shutdown = Arc::clone(&shutdown);
                thread::spawn(move || worker_loop(worker_clone, &r_clone, &shutdown))
            })
            .collect();
        WorkManager {
            threads,
            work_channel: Some(s),
            shutdown,
        }
    }

    pub(crate) fn is_stopped(&self) -> bool {
        self.shutdown.should_stop()
    }

    pub(crate) fn submit(&mut self, work: D) -> anyhow::Result<()> {
        if self.shutdown.should_stop() {
            return Err(self.stopped_error());
        }
        self.work_channel
            .as_ref()
            .ok_or_else(|| anyhow!("work manager stopped"))?
            .send(work)
            .map_err(|e| anyhow!("{e:#?}"))
    }

    /// Disconnect the queue and wait for in-flight blocks to finish.
    pub(crate) fn join(mut self) -> anyhow::Result<()> {
        self.join_workers();
        if let Some(e) = self.shutdown.take_error() {
            return Err(e);
        }
        Ok(())
    }

    fn stopped_error(&self) -> anyhow::Error {
        match self.shutdown.error.lock() {
            Ok(slot) => match slot.as_ref() {
                Some(e) => anyhow!("{e:#}"),
                None => anyhow!("work manager stopped"),
            },
            Err(_) => anyhow!("work manager stopped"),
        }
    }

    fn join_workers(&mut self) {
        drop(self.work_channel.take());
        for thread in self.threads.drain(..) {
            if thread.join().is_err() {
                log::error!("worker thread panicked");
                self.shutdown
                    .request_stop(anyhow!("worker thread panicked"));
            }
        }
    }
}

fn worker_loop<W, D>(worker: W, chan: &Receiver<D>, shutdown: &Shutdown)
where
    W: ChannelWorker<D>,
{
    loop {
        if shutdown.should_stop() {
            return;
        }
        let work = match chan.recv() {
            Ok(work) => work,
            Err(_) => return,
        };
        if shutdown.should_stop() {
            return;
        }
        if let Err(e) = worker.handle(work) {
            log::error!("unrecoverable worker error: {e:#}");
            shutdown.request_stop(e);
            return;
        }
    }
}

impl<D: Send + 'static> Drop for WorkManager<D> {
    fn drop(&mut self) {
        self.join_workers();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;
    use std::sync::{Arc, Barrier, Mutex};

    #[derive(Clone)]
    struct RecordingWorker {
        started: Arc<Mutex<Vec<u32>>>,
        completed: Arc<Mutex<Vec<u32>>>,
        start_barrier: Arc<Barrier>,
    }

    impl ChannelWorker<u32> for RecordingWorker {
        fn handle(&self, work: u32) -> anyhow::Result<()> {
            self.started.lock().unwrap().push(work);
            self.start_barrier.wait();
            if work == 1 {
                bail!("unrecoverable");
            }
            self.completed.lock().unwrap().push(work);
            Ok(())
        }
    }

    #[test]
    fn in_flight_work_finishes_when_another_worker_fails() {
        let worker = RecordingWorker {
            started: Arc::new(Mutex::new(Vec::new())),
            completed: Arc::new(Mutex::new(Vec::new())),
            start_barrier: Arc::new(Barrier::new(2)),
        };
        let mut mgr = WorkManager::new(2, worker.clone());
        mgr.submit(1).unwrap();
        mgr.submit(2).unwrap();

        let err = mgr.join().unwrap_err();
        assert!(err.to_string().contains("unrecoverable"));

        let started = worker.started.lock().unwrap().clone();
        let completed = worker.completed.lock().unwrap().clone();
        assert!(started.contains(&1), "failing block should have started");
        assert!(started.contains(&2), "sibling block should have started");
        assert_eq!(completed, vec![2], "sibling in-flight block must complete");
    }
}
