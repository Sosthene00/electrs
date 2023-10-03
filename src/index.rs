use anyhow::{Context, Result};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{Block, BlockHash, OutPoint, Txid};
use bitcoin::secp256k1::PublicKey;

use crate::{
    chain::{Chain, NewHeader},
    daemon::Daemon,
    db::{DBStore, Row, WriteBatch},
    metrics::{self, Gauge, Histogram, Metrics},
    signals::ExitFlag,
    types::{HashPrefixRow, HeaderRow, ScriptHash, ScriptHashRow, SpendingPrefixRow, TxidRow, TweakRow},
    silentpayment::{take_eligible_pubkeys, calculate_tweak_data}
};

#[derive(Clone)]
struct Stats {
    update_duration: Histogram,
    update_size: Histogram,
    height: Gauge,
    db_properties: Gauge,
}

impl Stats {
    fn new(metrics: &Metrics) -> Self {
        Self {
            update_duration: metrics.histogram_vec(
                "index_update_duration",
                "Index update duration (in seconds)",
                "step",
                metrics::default_duration_buckets(),
            ),
            update_size: metrics.histogram_vec(
                "index_update_size",
                "Index update size (in bytes)",
                "step",
                metrics::default_size_buckets(),
            ),
            height: metrics.gauge("index_height", "Indexed block height", "type"),
            db_properties: metrics.gauge("index_db_properties", "Index DB properties", "name"),
        }
    }

    fn observe_duration<T>(&self, label: &str, f: impl FnOnce() -> T) -> T {
        self.update_duration.observe_duration(label, f)
    }

    fn observe_size(&self, label: &str, rows: &[Row]) {
        self.update_size.observe(label, db_rows_size(rows) as f64);
    }

    fn observe_batch(&self, batch: &WriteBatch) {
        self.observe_size("write_funding_rows", &batch.funding_rows);
        self.observe_size("write_spending_rows", &batch.spending_rows);
        self.observe_size("write_txid_rows", &batch.txid_rows);
        self.observe_size("write_header_rows", &batch.header_rows);
        debug!(
            "writing {} funding and {} spending rows from {} transactions, {} blocks, {} sp tweaks",
            batch.funding_rows.len(),
            batch.spending_rows.len(),
            batch.txid_rows.len(),
            batch.header_rows.len(),
            batch.tweak_rows.len()
        );
    }

    fn observe_chain(&self, chain: &Chain) {
        self.height.set("tip", chain.height() as f64);
    }

    fn observe_db(&self, store: &DBStore) {
        for (cf, name, value) in store.get_properties() {
            self.db_properties
                .set(&format!("{}:{}", name, cf), value as f64);
        }
    }
}

struct IndexResult {
    header_row: HeaderRow,
    funding_rows: Vec<HashPrefixRow>,
    spending_rows: Vec<HashPrefixRow>,
    txid_rows: Vec<HashPrefixRow>,
    tweak_rows: Vec<TweakRow>,
}

impl IndexResult {
    fn extend(&self, batch: &mut WriteBatch) {
        let funding_rows = self.funding_rows.iter().map(HashPrefixRow::to_db_row);
        batch.funding_rows.extend(funding_rows);

        let spending_rows = self.spending_rows.iter().map(HashPrefixRow::to_db_row);
        batch.spending_rows.extend(spending_rows);

        let txid_rows = self.txid_rows.iter().map(HashPrefixRow::to_db_row);
        batch.txid_rows.extend(txid_rows);

        batch.header_rows.push(self.header_row.to_db_row());
        batch.tip_row = serialize(&self.header_row.header.block_hash()).into_boxed_slice();

        let tweak_rows = self.tweak_rows.iter().map(TweakRow::to_db_row);
        batch.tweak_rows.extend(tweak_rows);

    }
}

/// Confirmed transactions' address index
pub struct Index {
    store: DBStore,
    batch_size: usize,
    lookup_limit: Option<usize>,
    chain: Chain,
    stats: Stats,
    is_ready: bool,
}

impl Index {
    pub(crate) fn load(
        store: DBStore,
        mut chain: Chain,
        metrics: &Metrics,
        batch_size: usize,
        lookup_limit: Option<usize>,
        reindex_last_blocks: usize,
    ) -> Result<Self> {
        if let Some(row) = store.get_tip() {
            let tip = deserialize(&row).expect("invalid tip");
            let headers = store
                .read_headers()
                .into_iter()
                .map(|row| HeaderRow::from_db_row(&row).header)
                .collect();
            chain.load(headers, tip);
            chain.drop_last_headers(reindex_last_blocks);
        };
        let stats = Stats::new(metrics);
        stats.observe_chain(&chain);
        stats.observe_db(&store);
        Ok(Index {
            store,
            batch_size,
            lookup_limit,
            chain,
            stats,
            is_ready: false,
        })
    }

    pub(crate) fn chain(&self) -> &Chain {
        &self.chain
    }

    pub(crate) fn limit_result<T>(&self, entries: impl Iterator<Item = T>) -> Result<Vec<T>> {
        let mut entries = entries.fuse();
        let result: Vec<T> = match self.lookup_limit {
            Some(lookup_limit) => entries.by_ref().take(lookup_limit).collect(),
            None => entries.by_ref().collect(),
        };
        if entries.next().is_some() {
            bail!(">{} index entries, query may take too long", result.len())
        }
        Ok(result)
    }

    pub(crate) fn get_tweaks_alone_single_block(&self, height: usize) -> impl Iterator<Item = PublicKey> + '_ {
        self.store
            .read_tweaks()
            .into_iter()
            .filter(move |t| {
                let tweak_height = TweakRow::from_db_row(&t).height;
                tweak_height == height as u32
            })
            .map(|row| {
                let tweak = TweakRow::from_db_row(&row).tweak_data;
                PublicKey::from_slice(&tweak).unwrap()
            })
    }

    pub(crate) fn get_tweaks_alone(&self, height: usize) -> impl Iterator<Item = (u32, PublicKey)> + '_ {
        self.store
            .read_tweaks()
            .into_iter()
            .filter(move |t| {
                let tweak_height = TweakRow::from_db_row(&t).height;
                tweak_height >= height as u32
            })
            .map(|row| {
                let tweak = TweakRow::from_db_row(&row).tweak_data;
                let height = TweakRow::from_db_row(&row).height;
                (height, PublicKey::from_slice(&tweak).unwrap())
            })
    }

    // pub(crate) fn get_tweaks(&self, block_hash: BlockHash) -> impl Iterator<Item = PublicKey> + '_ {
    //     if let Some(begin_block) = self.store
    //         .read_headers()
    //         .into_iter()
    //         .find(|row| {
    //             let header_row = HeaderRow::from_db_row(&row);
    //             header_row.header.block_hash() == block_hash
    //         }) 
    //         {
    //             let tweak_vec: Vec<u8> = HeaderRow::from_db_row(&begin_block).sp_tweaks;
    //             let pub_keys: Vec<PublicKey> = tweak_vec.chunks(33)
    //                 .filter_map(|chunk| PublicKey::from_slice(chunk).ok())
    //                 .collect();

    //             pub_keys.into_iter()
    //         }
    //     else {
    //         let empty_pubkeys: Vec<PublicKey> = vec![];

    //         empty_pubkeys.into_iter()
    //     }
    // }

    pub(crate) fn filter_by_txid(&self, txid: Txid) -> impl Iterator<Item = BlockHash> + '_ {
        self.store
            .iter_txid(TxidRow::scan_prefix(txid))
            .map(|row| HashPrefixRow::from_db_row(&row).height())
            .filter_map(move |height| self.chain.get_block_hash(height))
    }

    pub(crate) fn filter_by_funding(
        &self,
        scripthash: ScriptHash,
    ) -> impl Iterator<Item = BlockHash> + '_ {
        self.store
            .iter_funding(ScriptHashRow::scan_prefix(scripthash))
            .map(|row| HashPrefixRow::from_db_row(&row).height())
            .filter_map(move |height| self.chain.get_block_hash(height))
    }

    pub(crate) fn filter_by_spending(
        &self,
        outpoint: OutPoint,
    ) -> impl Iterator<Item = BlockHash> + '_ {
        self.store
            .iter_spending(SpendingPrefixRow::scan_prefix(outpoint))
            .map(|row| HashPrefixRow::from_db_row(&row).height())
            .filter_map(move |height| self.chain.get_block_hash(height))
    }

    // Return `Ok(true)` when the chain is fully synced and the index is compacted.
    pub(crate) fn sync(&mut self, daemon: &Daemon, exit_flag: &ExitFlag) -> Result<bool> {
        let new_headers = self
            .stats
            .observe_duration("headers", || daemon.get_new_headers(&self.chain))?;
        match (new_headers.first(), new_headers.last()) {
            (Some(first), Some(last)) => {
                let count = new_headers.len();
                info!(
                    "indexing {} blocks: [{}..{}]",
                    count,
                    first.height(),
                    last.height()
                );
            }
            _ => {
                self.store.flush(); // full compaction is performed on the first flush call
                self.is_ready = true;
                return Ok(true); // no more blocks to index (done for now)
            }
        }
        for chunk in new_headers.chunks(self.batch_size) {
            exit_flag.poll().with_context(|| {
                format!(
                    "indexing interrupted at height: {}",
                    chunk.first().unwrap().height()
                )
            })?;
            self.sync_blocks(daemon, chunk)?;
        }
        self.chain.update(new_headers);
        self.stats.observe_chain(&self.chain);
        Ok(false) // sync is not done
    }

    fn sync_blocks(&mut self, daemon: &Daemon, chunk: &[NewHeader]) -> Result<()> {
        let blockhashes: Vec<BlockHash> = chunk.iter().map(|h| h.hash()).collect();
        let mut heights = chunk.iter().map(|h| h.height());

        let mut batch = WriteBatch::default();
        daemon.for_blocks(blockhashes, |_blockhash, block| {
            let height = heights.next().expect("unexpected block");
            self.stats.observe_duration("block", || {
                index_single_block(daemon, block, height).extend(&mut batch)
            });
            self.stats.height.set("tip", height as f64);
        })?;
        let heights: Vec<_> = heights.collect();
        assert!(
            heights.is_empty(),
            "some blocks were not indexed: {:?}",
            heights
        );
        batch.sort();
        self.stats.observe_batch(&batch);
        self.stats
            .observe_duration("write", || self.store.write(&batch));
        self.stats.observe_db(&self.store);
        Ok(())
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.is_ready
    }
}

fn db_rows_size(rows: &[Row]) -> usize {
    rows.iter().map(|key| key.len()).sum()
}

fn index_single_block(daemon: &Daemon, block: Block, height: usize) -> IndexResult {
    let mut funding_rows = Vec::with_capacity(block.txdata.iter().map(|tx| tx.output.len()).sum());
    let mut spending_rows = Vec::with_capacity(block.txdata.iter().map(|tx| tx.input.len()).sum());
    let mut txid_rows = Vec::with_capacity(block.txdata.len());
    let mut tweak_rows = Vec::new();
    // let mut sp_tweaks = Vec::new();

    for tx in &block.txdata {
        txid_rows.push(TxidRow::row(tx.txid(), height));

        funding_rows.extend(
            tx.output
                .iter()
                .filter(|txo| !txo.script_pubkey.is_provably_unspendable())
                .map(|txo| {
                    let scripthash = ScriptHash::new(&txo.script_pubkey);
                    ScriptHashRow::row(scripthash, height)
                }),
        );

        if tx.is_coin_base() {
            continue; // coinbase doesn't have inputs
        }
        spending_rows.extend(
            tx.input
                .iter()
                .map(|txin| SpendingPrefixRow::row(txin.previous_output, height)),
        );

        // From here it only concerns silent payment
        if !tx.output.iter().any(|o| o.script_pubkey.is_v1_p2tr()) {
            continue // This transaction can't contain silent payment outputs
        }

        let input_pubkeys = take_eligible_pubkeys(daemon, &tx.input);

        if input_pubkeys.len() == 0 {
            continue // No eligible pubkey here, can't be sp payment
        }

        // We need to extract the tweak data
        // First we get the outpoints
        let outpoints: Vec<OutPoint> = tx.input.iter().map(|i| i.previous_output).collect();

        // Now compute the tweak
        let tweak_data = calculate_tweak_data(&input_pubkeys, &outpoints);

        // and now add it to the batch
        tweak_rows.push(TweakRow::new(tweak_data.serialize(), height));
        // sp_tweaks.extend_from_slice(&tweak_data.serialize());
    }
    IndexResult {
        funding_rows,
        spending_rows,
        txid_rows,
        header_row: HeaderRow::new(block.header),
        // header_row: HeaderRow::new(block.header, sp_tweaks),
        tweak_rows,
    }
}
