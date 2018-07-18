use futures::stream::Stream;
use futures::{Async, Future};

use tokio::timer::Delay;

use std::time::{Duration, Instant};

pub struct TimeoutStream<S> where S : Stream {
    stream: S,
    next_deadline: Delay,
    timeout: Duration,
}

impl<S> TimeoutStream<S> where S : Stream {
    pub fn new(stream: S, timeout: Duration) -> Self {
        let next_deadline = Delay::new(Instant::now() + timeout);
        Self {
            stream,
            next_deadline,
            timeout,
        }
    }
}

impl<S> Stream for TimeoutStream<S> where S : Stream {
    type Item = S::Item;
    type Error = S::Error;
    fn poll(&mut self) -> Result<Async<Option<S::Item>>, S::Error> {
        match self.next_deadline.poll() {
            Ok(Async::Ready(_)) => Ok(Async::Ready(None)),
            Ok(Async::NotReady) => {
                match self.stream.poll() {
                    Ok(Async::Ready(v)) => {
                        self.next_deadline.reset(Instant::now() + self.timeout);
                        Ok(Async::Ready(v))
                    },
                    Ok(Async::NotReady) => Ok(Async::NotReady),
                    Err(e) => Err(e),
                }
            },
            Err(_) => Ok(Async::Ready(None)), // TODO: If I want to upstream TimeoutStream this is gonna need some love
        }
    }
}
