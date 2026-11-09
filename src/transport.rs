//! Exclusive, bounded TCP/TLS sessions. A sent request is never retried here.
use crate::{IcError, Result};
use openssl::ssl::{ErrorCode, SslStream};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::BufReader,
    net::{Shutdown, TcpStream},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

const GLOBAL_LIMIT: usize = 256;
#[derive(Clone, Copy)]
pub struct Settings {
    pub idle: Duration,
    pub max_per_peer: usize,
}
impl Settings {
    pub fn parse(raw: &Value) -> Result<Self> {
        let Some(v) = raw.get("transport") else {
            return Ok(Self {
                idle: Duration::from_secs(30),
                max_per_peer: 4,
            });
        };
        let o = v
            .as_object()
            .ok_or_else(|| IcError::new("INVALID_CONFIG", "transport must be an object"))?;
        if o.keys()
            .any(|k| k != "idleTimeoutMs" && k != "maxConnectionsPerPeer")
        {
            return Err(IcError::new("INVALID_CONFIG", "Unknown transport setting"));
        }
        let bounded = |k: &str, default: u64, min: u64, max: u64| -> Result<u64> {
            let n = match v.get(k) {
                Some(n) => n.as_u64().ok_or_else(|| {
                    IcError::new("INVALID_CONFIG", format!("{k} must be an integer"))
                })?,
                None => default,
            };
            if n < min || n > max {
                return Err(IcError::new(
                    "INVALID_CONFIG",
                    format!("{k} outside {min}..{max}"),
                ));
            }
            Ok(n)
        };
        Ok(Self {
            idle: Duration::from_millis(bounded("idleTimeoutMs", 30000, 100, 300000)?),
            max_per_peer: bounded("maxConnectionsPerPeer", 4, 1, 8)? as usize,
        })
    }
}
pub struct Session {
    pub reader: BufReader<SslStream<TcpStream>>,
    pub idle: Duration,
    pub used: Instant,
}
impl Session {
    pub fn alive(&mut self) -> bool {
        if !self.reader.buffer().is_empty() {
            return false;
        }
        let stream = self.reader.get_mut();
        if stream.get_ref().set_nonblocking(true).is_err() {
            return false;
        }
        let peek = stream.ssl_peek(&mut [0u8; 1]);
        let restored = stream.get_ref().set_nonblocking(false).is_ok();
        restored
            && matches!(peek,Err(ref e) if e.code()==ErrorCode::WANT_READ || e.code()==ErrorCode::WANT_WRITE)
    }
    fn close(&self) {
        let _ = self.reader.get_ref().get_ref().shutdown(Shutdown::Both);
    }
}
#[derive(Default)]
struct Lane {
    total: usize,
    generation: u64,
    idle: Vec<Session>,
}
#[derive(Default)]
struct State {
    lanes: BTreeMap<(String, bool), Lane>,
    stopped: bool,
    opened: u64,
    reused: u64,
    idle_closed: u64,
    next: u64,
    sockets: BTreeMap<u64, (String, TcpStream)>,
}
pub struct Pool {
    settings: Settings,
    state: Mutex<State>,
    wake: Condvar,
}
pub struct Lease {
    pool: Arc<Pool>,
    key: (String, bool),
    generation: u64,
    id: u64,
    session: Option<Session>,
    keep: bool,
}
impl Lease {
    pub fn session(&mut self) -> &mut Session {
        self.session.as_mut().unwrap()
    }
    pub fn reusable(&mut self) {
        self.keep = true;
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = self.pool.state.lock().unwrap();
        state.sockets.remove(&self.id);
        let stopped = state.stopped;
        let lane = state.lanes.get_mut(&self.key).unwrap();
        if self.keep && !stopped && lane.generation == self.generation {
            let mut s = self.session.take().unwrap();
            s.used = Instant::now();
            lane.idle.push(s);
        } else {
            if let Some(s) = self.session.take() {
                s.close();
            }
            lane.total -= 1;
        }
        self.pool.wake.notify_all();
    }
}
impl Pool {
    pub fn new(settings: Settings) -> Arc<Self> {
        let pool = Arc::new(Self {
            settings,
            state: Mutex::new(State::default()),
            wake: Condvar::new(),
        });
        let weak = Arc::downgrade(&pool);
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_millis(25));
                let Some(p) = weak.upgrade() else {
                    break;
                };
                if p.state.lock().unwrap().stopped {
                    break;
                }
                p.reap();
            }
        });
        pool
    }
    fn prune(state: &mut State) {
        let now = Instant::now();
        let mut closed = 0;
        for lane in state.lanes.values_mut() {
            lane.idle.retain(|s| {
                if now.duration_since(s.used) >= s.idle {
                    s.close();
                    lane.total -= 1;
                    closed += 1;
                    false
                } else {
                    true
                }
            });
        }
        state.idle_closed += closed;
    }
    pub fn reap(&self) {
        let mut state = self.state.lock().unwrap();
        Self::prune(&mut state);
        self.wake.notify_all();
    }
    pub fn acquire(
        self: &Arc<Self>,
        peer: &str,
        control: bool,
        wait: Duration,
        open: impl FnOnce(&dyn Fn(&TcpStream) -> Result<()>) -> Result<Session>,
    ) -> Result<Lease> {
        let key = (peer.to_owned(), control);
        let end = Instant::now() + wait;
        let mut state = self.state.lock().unwrap();
        let (generation, mut session) = loop {
            if state.stopped {
                return Err(IcError::new("NODE_STOPPING", "Transport is shutting down"));
            }
            Self::prune(&mut state);
            let global: usize = state.lanes.values().map(|l| l.total).sum();
            let lane = state.lanes.entry(key.clone()).or_default();
            if let Some(s) = lane.idle.pop() {
                break (lane.generation, Some(s));
            }
            if lane.total
                < if control {
                    1
                } else {
                    self.settings.max_per_peer
                }
                && global
                    < if control {
                        GLOBAL_LIMIT
                    } else {
                        GLOBAL_LIMIT - 32
                    }
            {
                lane.total += 1;
                break (lane.generation, None);
            }
            let Some(left) = end.checked_duration_since(Instant::now()) else {
                return Err(IcError::new("BUSY", "Connection pool capacity reached"));
            };
            state = self.wake.wait_timeout(state, left).unwrap().0;
        };
        let reused = session.as_mut().is_some_and(Session::alive);
        if !reused && let Some(s) = session.take() {
            s.close();
        }
        // This replacement happens before any caller request is written.
        state.next += 1;
        let id = state.next;
        drop(state);
        let track = |tcp: &TcpStream| -> Result<()> {
            let mut state = self.state.lock().unwrap();
            if state.stopped || state.lanes[&key].generation != generation {
                return Err(IcError::new(
                    "PEER_DENIED",
                    "Session invalidated during connection",
                ));
            }
            state
                .sockets
                .insert(id, (peer.to_owned(), tcp.try_clone()?));
            Ok(())
        };
        let result = match session {
            Some(s) => Ok(s),
            None => open(&track),
        };
        let mut state = self.state.lock().unwrap();
        let s = match result {
            Ok(s) => s,
            Err(e) => {
                state.sockets.remove(&id);
                state.lanes.get_mut(&key).unwrap().total -= 1;
                self.wake.notify_all();
                return Err(e);
            }
        };
        if state.stopped || state.lanes[&key].generation != generation {
            s.close();
            state.sockets.remove(&id);
            state.lanes.get_mut(&key).unwrap().total -= 1;
            self.wake.notify_all();
            return Err(IcError::new(
                "PEER_DENIED",
                "Session invalidated during connection",
            ));
        }
        let tcp = match s.reader.get_ref().get_ref().try_clone() {
            Ok(t) => t,
            Err(e) => {
                s.close();
                state.sockets.remove(&id);
                state.lanes.get_mut(&key).unwrap().total -= 1;
                self.wake.notify_all();
                return Err(e.into());
            }
        };
        if reused {
            state.reused += 1;
        } else {
            state.opened += 1;
        }
        state.sockets.insert(id, (peer.to_owned(), tcp));
        Ok(Lease {
            pool: self.clone(),
            key,
            generation,
            id,
            session: Some(s),
            keep: false,
        })
    }
    pub fn invalidate(&self, peer: Option<&str>) {
        let mut state = self.state.lock().unwrap();
        for ((id, _), lane) in state.lanes.iter_mut() {
            if peer.is_none_or(|p| p == id) {
                lane.generation += 1;
                for s in lane.idle.drain(..) {
                    s.close();
                    lane.total -= 1;
                }
            }
        }
        for (id, tcp) in state.sockets.values() {
            if peer.is_none_or(|p| p == id) {
                let _ = tcp.shutdown(Shutdown::Both);
            }
        }
        self.wake.notify_all();
    }
    pub fn shutdown(&self) {
        self.state.lock().unwrap().stopped = true;
        self.invalidate(None);
    }
    pub fn stats(&self, incoming: usize) -> Value {
        let s = self.state.lock().unwrap();
        let total: usize = s.lanes.values().map(|l| l.total).sum();
        let idle: usize = s.lanes.values().map(|l| l.idle.len()).sum();
        json!({"opened":s.opened,"reused":s.reused,"idleClosed":s.idle_closed,"active":total-idle,"idle":idle,"incomingConnections":incoming})
    }
}

struct Incoming {
    tcp: TcpStream,
    peer: Option<String>,
    idle_since: Option<Instant>,
    invalidated: bool,
}
#[derive(Default)]
struct IncomingState {
    sockets: BTreeMap<u64, Incoming>,
    next: u64,
    stopped: bool,
}
pub struct IncomingSockets {
    state: Mutex<IncomingState>,
    idle: Duration,
}
pub struct IncomingGuard {
    registry: Arc<IncomingSockets>,
    id: u64,
}
impl IncomingGuard {
    pub fn peer(&self, id: &str) {
        if let Some(s) = self
            .registry
            .state
            .lock()
            .unwrap()
            .sockets
            .get_mut(&self.id)
        {
            s.peer = Some(id.to_owned());
        }
    }
    pub fn idle(&self) {
        if let Some(s) = self
            .registry
            .state
            .lock()
            .unwrap()
            .sockets
            .get_mut(&self.id)
        {
            s.idle_since = Some(Instant::now());
        }
    }
    pub fn active(&self) {
        if let Some(s) = self
            .registry
            .state
            .lock()
            .unwrap()
            .sockets
            .get_mut(&self.id)
        {
            s.idle_since = None;
        }
    }
}
impl Drop for IncomingGuard {
    fn drop(&mut self) {
        self.registry.state.lock().unwrap().sockets.remove(&self.id);
    }
}
impl IncomingSockets {
    pub fn new(idle: Duration) -> Arc<Self> {
        let r = Arc::new(Self {
            state: Mutex::new(IncomingState::default()),
            idle,
        });
        let weak = Arc::downgrade(&r);
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_millis(25));
                let Some(r) = weak.upgrade() else {
                    break;
                };
                let mut state = r.state.lock().unwrap();
                if state.stopped {
                    break;
                }
                for s in state.sockets.values_mut() {
                    if s.idle_since.is_some_and(|t| t.elapsed() >= r.idle) {
                        s.invalidated = true;
                        let _ = s.tcp.shutdown(Shutdown::Both);
                    }
                }
            }
        });
        r
    }
    pub fn register(self: &Arc<Self>, tcp: &TcpStream) -> Result<IncomingGuard> {
        let mut state = self.state.lock().unwrap();
        if state.stopped {
            return Err(IcError::new("NODE_STOPPING", "Transport is shutting down"));
        }
        if state.sockets.len() >= 32 {
            return Err(IcError::new("BUSY", "Incoming connection limit reached"));
        }
        state.next += 1;
        let id = state.next;
        state.sockets.insert(
            id,
            Incoming {
                tcp: tcp.try_clone()?,
                peer: None,
                idle_since: None,
                invalidated: false,
            },
        );
        Ok(IncomingGuard {
            registry: self.clone(),
            id,
        })
    }
    /// Authenticated connections currently retained by the transport. This does
    /// not infer reachability from a saved peer configuration.
    pub fn authenticated_peers(&self) -> Vec<String> {
        let state = self.state.lock().unwrap();
        if state.stopped {
            return Vec::new();
        }
        let mut peers = state
            .sockets
            .values()
            .filter(|s| !s.invalidated && !s.idle_since.is_some_and(|t| t.elapsed() >= self.idle))
            .filter_map(|s| s.peer.clone())
            .collect::<Vec<_>>();
        peers.sort();
        peers.dedup();
        peers
    }
    pub fn invalidate(&self, peer: Option<&str>) {
        let mut state = self.state.lock().unwrap();
        for s in state.sockets.values_mut() {
            if peer.is_none_or(|p| s.peer.as_deref() == Some(p)) {
                s.invalidated = true;
                let _ = s.tcp.shutdown(Shutdown::Both);
            }
        }
    }
    pub fn shutdown(&self) {
        self.state.lock().unwrap().stopped = true;
        self.invalidate(None);
    }
}
