use std::cmp::{max};
use std::thread;
use crossbeam_channel::{bounded, Sender, Receiver};

pub(crate) struct WorkManager<D: Send + 'static> {
    threads: Vec<Option<thread::JoinHandle<()>>>,
    work_channel: Sender<D>,
}

pub(crate) trait ChannelWorker<T> {
    fn run(&self, chan: &Receiver<T>);
}

impl<D: Send + 'static> WorkManager<D> {
    pub(crate) fn new<W: ChannelWorker<D> + Clone + Send + Sync + 'static>(size: usize, worker: &W) -> WorkManager<D> {
        let mut threads = Vec::with_capacity(size);
        let (s, r) = bounded::<D>(max(size * 10, 1000));

        for _ in 0..max(size, 1) {
            let r_clone = r.clone();
            let worker_clone = worker.clone();
            let thread = thread::spawn(move || {
                worker_clone.run(&r_clone);
            });
            threads.push(Some(thread));
        }
        WorkManager {
            threads,
            work_channel: s,
        }
    }

    pub(crate) fn submit(&mut self, work: D) {
        match self.work_channel.send(work) {
            Err(e) => {
                panic!("{:#?}", e);
            }
            Ok(_) => return,
        };
    }
}

impl<D: Send + 'static> Drop for WorkManager<D> {
    fn drop(&mut self) {
        drop(self.work_channel.clone());
        for worker in &mut self.threads {
            if let Some(thread) = worker.take() {
                thread.join().unwrap();
            }
        }
    }
}
