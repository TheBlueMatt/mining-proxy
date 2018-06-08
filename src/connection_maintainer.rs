use futures::future;
use futures::{Future,Stream,Sink};

use tokio;
use tokio::{net, timer};

use tokio_io::{AsyncRead,codec};

use std::{io,marker};
use std::net::{SocketAddr,ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub trait ConnectionHandler<MessageType> {
	type Stream : Stream<Item = MessageType> + Send;
	type Framer : codec::Encoder<Item = MessageType, Error = io::Error> + codec::Decoder<Item = MessageType, Error = io::Error> + Send;
	fn new_connection(&self) -> (Self::Framer, Self::Stream);
	fn handle_message(&self, msg: MessageType) -> Result<(), io::Error>;
	fn connection_closed(&self);
}

pub struct ConnectionMaintainer<MessageType: 'static + Send, HandlerProvider : ConnectionHandler<MessageType>> {
	host: String,
	cur_addrs: Option<Vec<SocketAddr>>,
	handler: HandlerProvider,
	ph : marker::PhantomData<&'static MessageType>,
}

impl<MessageType : Send + Sync, HandlerProvider : 'static + ConnectionHandler<MessageType> + Send + Sync> ConnectionMaintainer<MessageType, HandlerProvider> {
	pub fn new(host: String, handler: HandlerProvider) -> ConnectionMaintainer<MessageType, HandlerProvider> {
		ConnectionMaintainer {
			host: host,
			cur_addrs: None,
			handler: handler,
			ph: marker::PhantomData,
		}
	}

	pub fn make_connection(mut self) {
		if {
			if self.cur_addrs.is_none() {
				//TODO: Resolve async
				match self.host.to_socket_addrs() {
					Err(_) => {
						true
					},
					Ok(addrs) => {
						self.cur_addrs = Some(addrs.collect());
						false
					}
				}
			} else { false }
		} {
			tokio::spawn(timer::Delay::new(Instant::now() + Duration::from_secs(10)).then(move |_| -> future::FutureResult<(), ()> {
				self.make_connection();
				future::result(Ok(()))
			}));
			return;
		}

		let addr_option = {
			let addr = self.cur_addrs.as_mut().unwrap().pop();
			if addr.is_none() {
				self.cur_addrs = None;
			}
			addr
		};

		match addr_option {
			Some(addr) => {
				println!("Trying connection to {}", addr);

				tokio::spawn(net::TcpStream::connect(&addr).then(move |res| -> future::FutureResult<(), ()> {
					match res {
						Ok(stream) => {
							println!("Connected to {}!", stream.peer_addr().unwrap());
							stream.set_nodelay(true).unwrap();

							let (framer, tx_stream) = self.handler.new_connection();
							let (tx, rx) = stream.framed(framer).split();
							let stream = tx_stream.map_err(|_| -> io::Error {
								panic!("mpsc streams cant generate errors!");
							});
							tokio::spawn(tx.send_all(stream).then(|_| {
								println!("Disconnected on send side, will reconnect...");
								future::result(Ok(()))
							}));
							let us = Arc::new(self);
							let us_close = us.clone();
							tokio::spawn(rx.for_each(move |msg| {
								future::result(us.handler.handle_message(msg))
							}).then(move |_| {
								println!("Disconnected on recv side, will reconnect...");
								us_close.handler.connection_closed();
								Arc::try_unwrap(us_close).ok().unwrap().make_connection();
								future::result(Ok(()))
							}));
						},
						Err(_) => {
							self.make_connection();
						}
					};
					future::result(Ok(()))
				}));
			},
			None => {
				tokio::spawn(timer::Delay::new(Instant::now() + Duration::from_secs(10)).then(move |_| {
					self.make_connection();
					future::result(Ok(()))
				}));
			},
		}
	}
}
