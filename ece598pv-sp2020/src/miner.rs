use crate::network::server::Handle as ServerHandle;
use std::sync::Arc;
use crate::blockchain::Blockchain;
use std::sync::Mutex;
use log::info;
use crossbeam::channel::{unbounded, Receiver, Sender, TryRecvError};
use std::time;
use crate::block;
use std::thread;
use crate::crypto::hash::{H256, Hashable, H160};
use std::time::{SystemTime, UNIX_EPOCH};
use super::block::{Content, Header};
use super::transaction::{Transaction,SignedTransaction};
use crate::crypto::merkle::MerkleTree;
use crate::block::Block;
use serde::{Serialize, Deserialize};
use super::network::message::Message;
use crate::txgenerator::TxMempool;
use std::collections::HashMap;
use url::quirks::search;


enum ControlSignal {
    Start(u64), // the number controls the lambda of interval between block generation
    Exit,
}

enum OperatingState {
    Paused,
    Run(u64),
    ShutDown,
}

pub struct Context {
    /// Channel for receiving control signal
    control_chan: Receiver<ControlSignal>,
    operating_state: OperatingState,
    server: ServerHandle,
    blockchain: Arc<Mutex<Blockchain>>,
    tx_pool: Arc<Mutex<TxMempool>>,
    curr_state:Arc<Mutex<HashMap<H160,(u32,u32)>>>,  // <address, (nonce, balance)>
    address: H160,
}

#[derive(Clone)]
pub struct Handle {
    /// Channel for sending signal to the miner thread
    control_chan: Sender<ControlSignal>,
}

pub fn new(
    server: &ServerHandle,
    blockchain: &Arc<Mutex<Blockchain>>,
    tx_pool: &Arc<Mutex<TxMempool>>,
    curr_state: &Arc<Mutex<HashMap<H160, (u32, u32)>>>,
    address: H160,

) -> (Context, Handle) {
    let (signal_chan_sender, signal_chan_receiver) = unbounded();
    let block = blockchain.clone();
    let mempool_buf = tx_pool.clone();
    let curr_state = curr_state.clone();
    let ctx = Context {
        control_chan: signal_chan_receiver,
        operating_state: OperatingState::Paused,
        server: server.clone(),
        blockchain: block,
        tx_pool:mempool_buf,
        curr_state: curr_state,
        address: address,
    };

    let handle = Handle {
        control_chan: signal_chan_sender,
    };

    (ctx, handle)
}

impl Handle {
    pub fn exit(&self) {
        self.control_chan.send(ControlSignal::Exit).unwrap();
    }

    pub fn start(&self, lambda: u64) {
        self.control_chan
            .send(ControlSignal::Start(lambda))
            .unwrap();
    }

}

impl Context {
    pub fn start(mut self) {
        thread::Builder::new()
            .name("miner".to_string())
            .spawn(move || {
                self.miner_loop();
            })
            .unwrap();
        info!("Miner initialized into paused mode");
    }

    fn handle_control_signal(&mut self, signal: ControlSignal) {
        match signal {
            ControlSignal::Exit => {
                info!("Miner shutting down");
                self.operating_state = OperatingState::ShutDown;
            }
            ControlSignal::Start(i) => {
                info!("Miner starting in continuous mode with lambda {}", i);
                self.operating_state = OperatingState::Run(i);
            }
        }
    }
    fn miner_loop(&mut self) {
        // main mining loop
        loop {

            // check and react to control signals
            match self.operating_state {
                OperatingState::Paused => {
                    let signal = self.control_chan.recv().unwrap();
                    self.handle_control_signal(signal);
                    continue;
                }
                OperatingState::ShutDown => {
                    return;
                }
                _ => match self.control_chan.try_recv() {
                    Ok(signal) => {
                        self.handle_control_signal(signal);
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => panic!("Miner control channel detached"),
                },
            }
            if let OperatingState::ShutDown = self.operating_state {
                return;
            }
            let current_state = self.curr_state.lock().unwrap();
            let mut chain = self.blockchain.lock().unwrap();
            let mut pool = self.tx_pool.lock().unwrap();
            if pool.buf.len() > 0 {
                let parent = chain.tip();

                // Generate new block
                let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("").as_millis();
                let mut content_new = Content {
                    content: Vec::<SignedTransaction>::new(),
                };

                // TODO: Add transactions into Block
                for element in pool.buf.iter() {
                    if content_new.content.len() <= 8 {
                        content_new.content.push(element.clone());
                    } else {
                        break;
                    }
                }
                if content_new.content.len() == 0 {
                    continue;
                }
                //println!("current block transaction len {:?}", content_new.content.len());
                //println!("current transaction pool len {:?}", pool.map.len());
                // TODO: Generate new block
                let diff_h256: H256 = hex!("1000000000000000000000000000000000000000000000000000000000000000").into();
                let rand_nonce: u32 = rand::random();
                let head_rand = Header {
                    parent_hash: parent,
                    nonce: rand_nonce,
                    difficulty: diff_h256,
                    timestamp: now,
                    merkle_root: MerkleTree::new(&(content_new.content)),
                };

                let new_block = Block {
                    head: head_rand,
                    content: content_new.clone(),
                };

                //Calculate block hash
                let result = new_block.hash();
                let height = chain.height();
                if result.le(&new_block.head.difficulty) {
                    chain.insert(&new_block);
                    info!("Find new block");
                    info!("Length of transactions in this block {:?}", content_new.content.len());
                    println!("Block hash : {:?}", new_block.clone().hash());
                    println!("---------------------");
                    let all_hash = chain.all_blocks_in_longest_chain();
                    self.server.broadcast(Message::NewBlockHashes(all_hash.clone()));
                    for tx in content_new.content {
                        // Update tx_pool
                        pool.pop_tx(&tx);
                    }

                }

            }
            std::mem::drop(pool);
            std::mem::drop(chain);
            std::mem::drop(current_state);

            if let OperatingState::Run(i) = self.operating_state {
                if i != 0 {
                    let interval = time::Duration::from_micros(i as u64);
                    thread::sleep(interval);
                }
            }
        }
    }
}


// 10秒
//0000100000000000000000000000000000000000000000000000000000000000   --> 5块
//0001000000000000000000000000000000000000000000000000000000000000   --> 23块
//0010000000000000000000000000000000000000000000000000000000000000   --> 418块
