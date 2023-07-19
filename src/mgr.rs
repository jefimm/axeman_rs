use crossbeam_channel::{bounded, Receiver, Sender};
use std::cmp::max;
use std::thread;

pub(crate) struct WorkManager<D: Send + 'static> {
    threads: Vec<thread::JoinHandle<()>>,
    work_channel: Sender<D>,
}

pub(crate) trait ChannelWorker<T> {
    fn run(&self, chan: &Receiver<T>);
}

impl<D: Send + 'static> WorkManager<D> {
    pub(crate) fn new<W: ChannelWorker<D> + Clone + Send + Sync + 'static>(
        size: usize,
        worker: W,
    ) -> WorkManager<D> {
        let (s, r) = bounded::<D>(max(size * 10, 1000));

        let threads = (0..size.max(1))
            .map(|_| {
                let r_clone = r.clone();
                let worker_clone = worker.clone();
                thread::spawn(move || {
                    worker_clone.run(&r_clone);
                })
            })
            .collect();
        WorkManager {
            threads,
            work_channel: s,
        }
    }

    pub(crate) fn submit(&mut self, work: D) -> anyhow::Result<()> {
        self.work_channel
            .send(work)
            .map_err(|e| anyhow::anyhow!("{e:#?}"))
    }
}

impl<D: Send + 'static> Drop for WorkManager<D> {
    fn drop(&mut self) {
        for thread in self.threads.drain(..) {
            thread.join().expect("Unable to join thread");
        }
    }
}
