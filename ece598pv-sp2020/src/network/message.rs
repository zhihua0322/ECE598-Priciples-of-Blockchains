use serde::{Serialize, Deserialize};
use crate::crypto::hash::{H256, Hashable, H160};
use crate::block::Block;
use crate::transaction::{Transaction,SignedTransaction};
use std::collections::{HashMap};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    Ping(String),
    Pong(String),
    NewBlockHashes(Vec<H256>),
    GetBlocks(Vec<H256>),
    Blocks(Vec<Block>),
    NewState((H256,HashMap<H160,(u32,u32)>)),
    NewTransactionHashes(Vec<H256>),
    GetTransactions(Vec<H256>),
    Transactions(Vec<SignedTransaction>),
    NewPeer(H160),
    Ack(Vec<H160>),
}