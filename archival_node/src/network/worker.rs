use super::message::Message;
use super::peer;
use crate::network::server::Handle as ServerHandle;
use crossbeam::channel;
use log::{debug, warn};
use std::sync::{Arc, MutexGuard};
use crate::blockchain::Blockchain;
use std::sync::Mutex;
use std::thread;
use crate::crypto::hash::{H256, Hashable, H160};
use crate::block::Block;
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, VecDeque, HashSet};
use crate::transaction::SignedTransaction;
use crate::transaction;
use std::intrinsics::transmute;
use std::borrow::BorrowMut;
use crate::bloomfilter::lib::BloomFilter;

#[derive(Clone)]
pub struct Context {
    bloom_filter: BloomFilter,
    msg_chan: channel::Receiver<(Vec<u8>, peer::Handle)>,
    num_worker: usize,
    server: ServerHandle,
    blockchain: Arc<Mutex<Blockchain>>,
    orphanBuf: Arc<Mutex<OrphanBuffer>>,
    init_state: Arc<Mutex<HashMap<H160,(u32, u32)>>>, // <address, (nonce, balance)>
    address: H160,
    block_state:Arc<Mutex<HashMap<H256,HashMap<H160,(u32,u32)>>>>,
}

#[derive(Clone)]
pub struct OrphanBuffer{
    buf: HashMap<H256, Vec<Block>>,
}

impl OrphanBuffer{
    pub fn new() -> Self{
        let new_buf = HashMap::new();
        OrphanBuffer {
            buf : new_buf,
        }
    }
    pub fn addOrphan(&mut self, block: &Block){
        let mut toAddList = Vec::new();
        let mut curr_buf = &mut self.buf;
        if curr_buf.contains_key(&block.head.parent_hash){
            toAddList = curr_buf.get(&block.head.parent_hash).unwrap().clone();
        }
        toAddList.push(block.clone());
        curr_buf.insert(block.head.parent_hash,toAddList.clone());
    }
    pub fn findChild(&mut self, curr_chain: &mut MutexGuard<Blockchain>, current_block_state: &mut MutexGuard<HashMap<H256,HashMap<H160,(u32,u32)>>>, server: &mut ServerHandle){
        let mut curr_buf = &mut self.buf;
        for key in curr_buf.clone().keys(){
            if curr_chain.chain.contains_key(key){
                for block in curr_buf.clone().get(key).unwrap() {
                    // TODO: State is determined by block's parent
                    let parent_state = current_block_state.get(&block.head.parent_hash).unwrap();
                    //Check tx
                    let mut flag = true;
                    for tx in block.content.content.clone() {
                        let public_hash: H256 = ring::digest::digest(&ring::digest::SHA256, &tx.public_key).into();
                        let owner_add: H160 = public_hash.into();
                        if !transaction::verify(&tx) {
                            flag = false;
                            println!("Signature is not verified");
                        }

                        // 2. Check balance : check balance is enough
                        if parent_state.get(&owner_add).unwrap().1 < tx.transaction.value {
                            flag = false;
                            println!("No enough balance");
                        }

                        // 3. Check double spend : check tx nonce = state owner nonce + 1
                        if parent_state.get(&owner_add).unwrap().0 != tx.transaction.nonce - 1 {
                            flag = false;
                            println!("Mismatch account nonce");
                        }
                    }
                    if flag {
                        curr_chain.insert(block);
                        let mut current_state = parent_state.clone();
                        for tx in block.content.content.clone() {
                            let public_hash: H256 = ring::digest::digest(&ring::digest::SHA256, &tx.public_key).into();
                            let owner_add: H160 = public_hash.into();
                            //Update sender state (balance, nonce)
                            let balance = parent_state.get(&owner_add).unwrap().1;
                            current_state.insert(owner_add, (tx.transaction.nonce, balance - tx.transaction.value));
                            //Update receiver state (balance)
                            let recipient_balance = current_state.get(&tx.transaction.address).unwrap().1;
                            let recipient_nonce = current_state.get(&tx.transaction.address).unwrap().0;
                            current_state.insert(tx.transaction.address, (recipient_nonce, recipient_balance + tx.transaction.value));
                        }
                        //Update Block state
                        current_block_state.insert(block.hash(), current_state.clone());

                        //Send witness
                        let mut new_state = (block.hash(), current_state.clone());
                        server.broadcast(Message::NewState(new_state));

                        //View current properties
                        let snapshot = current_block_state.get(&curr_chain.tail).unwrap();
                        println!("Current state");
                        for i in snapshot.keys(){
                            println!("Peer address: {:?}, properties (nonce, balance) {:?}", i, snapshot.get(i).unwrap());
                        }
                        println!("---------------------");
                        println!("Total chain length: {:?}", curr_chain.height()+1);
                        println!("---------------------");
                        println!("Longest chain blocks hash");
                        println!("Blocks : {:?}", curr_chain.all_blocks_in_longest_chain());
                        println!("---------------------");

                    }
                    //let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("").as_millis();
                    //println!("Delay{:?}",now-block.head.timestamp);
                }

                //All valid children of current key are inserted
                curr_buf.remove(&key);
            }
        }
    }
}
pub fn new(
    bloom_filter: BloomFilter,
    num_worker: usize,
    msg_src: channel::Receiver<(Vec<u8>, peer::Handle)>,
    server: &ServerHandle,
    blockchain: &Arc<Mutex<Blockchain>>,
    orphanBuf: &Arc<Mutex<OrphanBuffer>>,
    init_state: &Arc<Mutex<HashMap<H160, (u32, u32)>>>,
    address: H160,
    block_state: &Arc<Mutex<HashMap<H256,HashMap<H160,(u32,u32)>>>>,
) -> Context {
    let blockchain = blockchain.clone();
    let init_state = init_state.clone();
    let mut block_state = block_state.clone();
    Context {
        bloom_filter: bloom_filter,
        msg_chan: msg_src,
        num_worker,
        server: server.clone(),
        blockchain: blockchain,
        orphanBuf: orphanBuf.clone(),
        init_state: init_state,
        address: address,
        block_state: block_state,
    }
}

impl Context {
    pub fn start(self) {
        let num_worker = self.num_worker;
        for i in 0..num_worker {
            let mut cloned = self.clone();
            thread::spawn(move || {
                cloned.worker_loop();
                warn!("Worker thread {} exited", i);
            });
        }
    }

    fn worker_loop(&mut self) {
        loop {
            let msg = self.msg_chan.recv().unwrap();
            let (msg, peer) = msg;
            let msg: Message = bincode::deserialize(&msg).unwrap();
            let mut current_chain = self.blockchain.lock().unwrap();
            let current_map = &current_chain.chain.clone();
            //println!("len:{:?}",current_chain.height());
            let mut curr_block_state = self.block_state.lock().unwrap();
            let mut init_state = self.init_state.lock().unwrap();
            let mut bloom_filter = self.bloom_filter.clone();
            match msg {
                Message::Ping(nonce) => {
                    debug!("Ping: {}", nonce);
                }
                Message::Pong(nonce) => {
                    debug!("Pong: {}", nonce);
                }

                Message::NewPeer(newPeer) => {
                    // Receive init message by a new coming peer
                    let mut init_block_state = curr_block_state;
                    if !init_state.contains_key(&newPeer){
                        // println!("Got new peer");
                        init_state.insert(newPeer,(0,100));
                        bloom_filter.insert((H160::to_string(&newPeer.clone())+"0"+"100").as_str());
                    }
                    init_block_state.insert(current_chain.tail, init_state.clone());
                    //check status
                    for key in init_block_state.keys(){
                        //println!("Genesis block hash {:?}", key);
                        let snapshot = init_block_state.get(key).unwrap();
                        let new_state = (key.clone(),snapshot.clone());
                        self.server.broadcast(Message::NewState(new_state));
                        for i in snapshot.keys(){
                            println!("Process address is: {:?}, ICO properties (nonce, balance) is:{:?}", i, snapshot.get(i).unwrap());
                        }
                        println!("---------------------");
                    }
                }
                Message::Ack(newPeerList) => {
                    debug!("Ack");
                }
                Message::NewState(NewState)=>{
                    debug!("NewState");
                }
                Message::NewTransactionHashes(NewTransactionHashes) =>{
                    debug!("NewTransactionHashes");
                }
                Message::GetTransactions(GetTransactions) =>{
                    debug!("GetTransactions");
                }
                Message::Transactions(Transactions) =>{
                    debug!("Transactions");
                }
                Message::NewBlockHashes(NewBlockHashes) =>{
                    //debug!("NewBlockHashes");
                    let mut block_vec = Vec::new();
                    //println!("receiver chain height {:?}",current_chain.height());
                    for hash in NewBlockHashes.clone(){
                        if !current_chain.chain.contains_key(&hash) {
                            block_vec.push(hash);
                        }
                    }
                    println!("receiver missing block {:?}",block_vec.len());
                    if (&block_vec).len() > 0 {
                        peer.write(Message::GetBlocks(block_vec));
                    }
                }

                Message::GetBlocks(GetBlocks)=>{
                    //debug!("GetBlocks");
                    //println!("Sender get request {:?}",GetBlocks.len());
                    let mut block_vec = Vec::new();
                    for hash in GetBlocks.clone(){
                        if current_map.contains_key(&hash){
                            let newBlock = (*current_map).get(&hash).unwrap().0.clone();
                            block_vec.push(newBlock.clone());
                            //println!("sent:{:?}",newBlock.hash());
                        }
                    }
                    //println!("sender send {:?}",block_vec.len());
                    if (&block_vec).len() > 0{
                        peer.write(Message::Blocks(block_vec));
                    }
                }

                Message::Blocks(Blocks)=>{
                    //debug!("Blocks");
                    let mut verified_blocks = Vec::new();
                    let mut orphan_buffer = self.orphanBuf.lock().unwrap();
                    for block in Blocks{
                        if !current_map.contains_key(&(block.hash())){
                            let newBlock = block.clone();
                            //PoW validity check
                            if current_chain.diff.eq(&newBlock.head.difficulty)
                                    && newBlock.hash().le(&newBlock.head.difficulty){
                                verified_blocks.push(newBlock.hash());
                                if current_map.contains_key(&newBlock.head.parent_hash) {
                                    //Check transactions
                                    let parent_state = curr_block_state.get(&newBlock.head.parent_hash).unwrap();
                                    let mut current_state = parent_state.clone();
                                    let mut flag = true;
                                    for tx in newBlock.content.content.clone() {
                                        let public_hash: H256 = ring::digest::digest(&ring::digest::SHA256, &tx.public_key).into();
                                        let owner_add: H160 = public_hash.into();
                                        if !transaction::verify(&tx) {
                                            flag = false;
                                            println!("Signature is not verified");
                                        }

                                        // 2. Check balance : check balance is enough
                                        if parent_state.get(&owner_add).unwrap().1 < tx.transaction.value {
                                            flag = false;
                                            println!("No enough balance");
                                        }

                                        // 3. Check double spend : check tx nonce = state owner nonce + 1
                                        if parent_state.get(&owner_add).unwrap().0 != tx.transaction.nonce - 1 {
                                            flag = false;
                                            println!("Mismatch account nonce");
                                        }

                                        // 4. Replace 2 and 3
                                        if !bloom_filter.maybe_present((H160::to_string(&tx.transaction.address.clone())+&(tx.transaction.nonce - 1).to_string()+&tx.transaction.self_balance.to_string()).as_str()) {
                                            flag = false;
                                            println!("Mismatch account nonce or value");
                                        }                                        
                                    }
                                    if flag {
                                        current_chain.insert(&newBlock);
                                        for tx in newBlock.content.content.clone() {
                                            let public_hash: H256 = ring::digest::digest(&ring::digest::SHA256, &tx.public_key).into();
                                            let owner_add: H160 = public_hash.into();
                                            //Update sender state (balance, nonce)
                                            let balance = current_state.get(&owner_add).unwrap().1;
                                            current_state.insert(owner_add, (tx.transaction.nonce, balance - tx.transaction.value));
                                            //Update receiver state (balance)
                                            let recipient_balance = current_state.get(&tx.transaction.address).unwrap().1;
                                            let recipient_nonce = current_state.get(&tx.transaction.address).unwrap().0;
                                            //Update bloom filter
                                            bloom_filter.insert((H160::to_string(&tx.transaction.address.clone())+&tx.transaction.nonce.to_string()+&tx.transaction.self_balance.to_string()).as_str());
                                            current_state.insert(tx.transaction.address, (recipient_nonce, recipient_balance + tx.transaction.value));
                                        }
                                        //Update Block_state
                                        curr_block_state.insert(newBlock.hash(),current_state.clone());

                                        //Send witness
                                        let mut new_state = (newBlock.hash(), current_state.clone());
                                        self.server.broadcast(Message::NewState(new_state));

                                        //View current properties
                                        let snapshot = curr_block_state.get(&current_chain.tail).unwrap();
                                        println!("Current state");
                                        for i in snapshot.keys(){
                                            println!("Peer address: {:?}, properties (nonce, balance) {:?}", i, snapshot.get(i).unwrap());
                                        }
                                        println!("---------------------");
                                        println!("Total chain length: {:?}", current_chain.height()+1);
                                        println!("---------------------");
                                        println!("Longest chain blocks hash");
                                        println!("Blocks : {:?}", current_chain.all_blocks_in_longest_chain());
                                        println!("---------------------");

                                    }else{
                                        println!("Block invalid");
                                    }
                                    //let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("").as_millis();
                                    //println!("Delay{:?}",now-block.head.timestamp);
                                }else{
                                    // Add Orphan to buffer
                                    orphan_buffer.addOrphan(&newBlock);
                                    println!("Found Orphan!");
                                }
                            }
                        }
                    }
                    let mut orphan_vec = Vec::new();
                    orphan_buffer.findChild(&mut current_chain, &mut curr_block_state, &mut self.server);
                    let curr_orphan_buf = orphan_buffer.buf.clone();
                    for key in curr_orphan_buf.keys(){
                        orphan_vec.push(*key);
                    }
                    //println!("orphan_vector:{:?}",orphan_vec.len());
                    if orphan_vec.len() > 0 {
                        self.server.broadcast(Message::GetBlocks(orphan_vec));
                    }
                    if verified_blocks.len() > 0{
                        self.server.broadcast(Message::NewBlockHashes(verified_blocks));
                    }
                }

            }
        }
    }
}
