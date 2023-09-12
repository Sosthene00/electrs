use std::io::Write;
use bitcoin::opcodes::all::{OP_PUSHBYTES_71, OP_PUSHBYTES_33, OP_PUSHBYTES_16};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Secp256k1, PublicKey, Scalar, XOnlyPublicKey};
use bitcoin::{OutPoint, TxIn, Script};

use crate::daemon::Daemon;

const NUMS_KEY: &[u8] = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0".as_bytes();

fn is_p2pkh(input: &TxIn) -> bool {
    let script = input.script_sig.as_bytes();
    input.script_sig.len() == 106 
        && script[0] == OP_PUSHBYTES_71.to_u8() 
        && script[72] == OP_PUSHBYTES_33.to_u8()
        && PublicKey::from_slice(&script[106-33..]).is_ok()
}

fn is_p2wpkh(input: &TxIn) -> bool {
    input.script_sig.is_empty() 
        && input.witness.len() == 2
        && PublicKey::from_slice(input.witness.last().unwrap()).is_ok()
}

fn is_p2sh_p2wpkh(input: &TxIn) -> bool {
    if let Some((push, program)) = input.script_sig.as_bytes().split_first() {
        *push == OP_PUSHBYTES_16.to_u8() 
            && Script::from_bytes(program).is_v0_p2wpkh()
    } else {
        false
    }
}

fn is_p2tr(input: &TxIn) -> bool {
    input.script_sig.is_empty() 
        && !input.witness.is_empty()
        && (input.witness.len() == 1 
            || XOnlyPublicKey::from_slice(input.witness.last().unwrap()).is_ok()
        )
}

pub(crate) fn take_eligible_pubkeys(daemon: &Daemon, tx_inputs: &Vec<TxIn>) -> Vec<PublicKey> {
    let mut input_pubkeys: Vec<PublicKey> = Vec::with_capacity(tx_inputs.len());

    for i in tx_inputs {
        if is_p2pkh(i) {
            let script = i.script_sig.as_bytes();
            input_pubkeys.push(PublicKey::from_slice(&script[script.len()-33..]).unwrap());
        } else if is_p2wpkh(i) {
            input_pubkeys.push(PublicKey::from_slice(i.witness.last().unwrap()).unwrap());
        } else if is_p2sh_p2wpkh(i) {
            input_pubkeys.push(PublicKey::from_slice(i.witness.last().unwrap()).unwrap());
        } else if is_p2tr(i) {
            if i.witness.len() > 1 {
                let internal = XOnlyPublicKey::from_slice(i.witness.last().unwrap()).unwrap();
                if internal == XOnlyPublicKey::from_slice(NUMS_KEY).unwrap() {
                    continue;
                }
            }
            let (txid, vout) = (i.previous_output.txid, i.previous_output.vout);
            if let Ok(prev_tx) = daemon.get_transaction(&txid, None) {
                let txout = prev_tx.output.get(vout as usize).unwrap();
                let spk = &txout.script_pubkey.as_bytes();
                let xonly_pubkey = XOnlyPublicKey::from_slice(&spk[2..]).unwrap();
                input_pubkeys.push(PublicKey::from_x_only_public_key(xonly_pubkey, bitcoin::secp256k1::Parity::Even));
            } else {
                panic!("Can't find prevout tx for {}", txid);
            }
        }
    }

    input_pubkeys
}

fn get_sum_public_keys(input: &Vec<PublicKey>) -> PublicKey {
    let keys_refs: &Vec<&PublicKey> = &input.iter().collect();

    PublicKey::combine_keys(keys_refs).unwrap()
}

pub(crate) fn calculate_tweak_data(
    input_pub_keys: &Vec<PublicKey>,
    outpoints: &Vec<OutPoint>,
) -> PublicKey {
    let secp = Secp256k1::new();
    let a_sum = get_sum_public_keys(input_pub_keys);
    let outpoints_hash = hash_outpoints(outpoints);

    a_sum.mul_tweak(&secp, &outpoints_hash).unwrap()
}

fn hash_outpoints(sending_data: &Vec<OutPoint>) -> Scalar {
    let mut outpoints: Vec<Vec<u8>> = vec![];

    for outpoint in sending_data {
        let txid = outpoint.txid;
        let vout = outpoint.vout;

        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(txid.as_byte_array());
        bytes.reverse();
        bytes.extend_from_slice(&vout.to_le_bytes());
        outpoints.push(bytes);
    }
    outpoints.sort();

    let mut engine = sha256::HashEngine::default();

    for v in outpoints {
        engine.write_all(&v).unwrap();
    }

    Scalar::from_be_bytes(sha256::Hash::from_engine(engine).to_byte_array()).unwrap()
}
