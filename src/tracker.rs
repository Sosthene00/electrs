use std::collections::HashMap;

use anyhow::{Context, Result};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{BlockHash, Transaction, Txid};

use crate::{
    cache::Cache,
    chain::Chain,
    config::Config,
    daemon::Daemon,
    db::DBStore,
    index::Index,
    mempool::{FeeHistogram, Mempool},
    metrics::Metrics,
    signals::ExitFlag,
    status::{Balance, ScriptHashStatus, UnspentEntry},
};

/// Electrum protocol subscriptions' tracker
pub struct Tracker {
    index: Index,
    mempool: Mempool,
    metrics: Metrics,
    ignore_mempool: bool,
}

pub(crate) enum Error {
    NotReady,
}

impl Tracker {
    pub fn new(config: &Config, metrics: Metrics) -> Result<Self> {
        let store = DBStore::open(&config.db_path, config.auto_reindex)?;
        let chain = Chain::new(config.network);
        Ok(Self {
            index: Index::load(
                store,
                chain,
                &metrics,
                config.index_batch_size,
                config.index_lookup_limit,
                config.reindex_last_blocks,
            )
            .context("failed to open index")?,
            mempool: Mempool::new(&metrics),
            metrics,
            ignore_mempool: config.ignore_mempool,
        })
    }

    pub(crate) fn chain(&self) -> &Chain {
        self.index.chain()
    }

    pub(crate) fn fees_histogram(&self) -> &FeeHistogram {
        self.mempool.fees_histogram()
    }

    pub(crate) fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub(crate) fn get_unspent(&self, status: &ScriptHashStatus) -> Vec<UnspentEntry> {
        status.get_unspent(self.index.chain())
    }

    pub(crate) fn sync(&mut self, daemon: &Daemon, exit_flag: &ExitFlag) -> Result<bool> {
        let done = self.index.sync(daemon, exit_flag)?;
        if done && !self.ignore_mempool {
            self.mempool.sync(daemon);
            // TODO: double check tip - and retry on diff
        }
        Ok(done)
    }

    pub(crate) fn status(&self) -> Result<(), Error> {
        if self.index.is_ready() {
            return Ok(());
        }
        Err(Error::NotReady)
    }

    pub(crate) fn update_scripthash_status(
        &self,
        status: &mut ScriptHashStatus,
        daemon: &Daemon,
        cache: &Cache,
    ) -> Result<bool> {
        let prev_statushash = status.statushash();
        status.sync(&self.index, &self.mempool, daemon, cache)?;
        Ok(prev_statushash != status.statushash())
    }

    pub(crate) fn get_balance(&self, status: &ScriptHashStatus) -> Balance {
        status.get_balance(self.chain())
    }

    pub(crate) fn lookup_transaction(
        &self,
        daemon: &Daemon,
        txid: Txid,
    ) -> Result<Option<(BlockHash, Transaction)>> {
        // Note: there are two blocks with coinbase transactions having same txid (see BIP-30)
        let blockhashes = self.index.filter_by_txid(txid);
        let mut result = None;
        daemon.for_blocks(blockhashes, |blockhash, block| {
            for tx in block.txdata {
                if result.is_some() {
                    return;
                }
                if tx.txid() == txid {
                    result = Some((blockhash, tx));
                    return;
                }
            }
        })?;
        Ok(result)
    }

    pub(crate) fn get_tweaks_single_block(&self, height: usize) -> Result<Vec<PublicKey>> {
        let tweaks: Vec<PublicKey> = self.index.get_tweaks_alone_single_block(height).collect();
        debug!("{:?}", tweaks);
        Ok(tweaks)
    }

    pub(crate) fn get_tweaks(&self, height: usize) -> Result<HashMap<u32, Vec<PublicKey>>> {
        let tweaks: Vec<(u32, PublicKey)> = self.index.get_tweaks_alone(height).collect();
        let mut res: HashMap<u32, Vec<PublicKey>> = HashMap::new();
        for tweak in tweaks {
            res.entry(tweak.0).or_insert_with(Vec::new).push(tweak.1)
        }
        // debug!("{:?}", tweaks);
        Ok(res)
    }
}
