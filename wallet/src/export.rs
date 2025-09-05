// Bitcoin Dev Kit
// Written in 2020 by Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.
// source: https://github.com/bitcoindevkit/bdk/blob/a5d076f215cd91173f55bda0d1cc59b9dde75511/crates/wallet/src/wallet/export.rs
use core::{fmt, str::FromStr};

use bdk_wallet::{KeychainKind, Wallet};
use bdk_wallet::keys::DescriptorSecretKey;
use serde::{Deserialize, Serialize};
use hex;

/// Structure that contains the export of a wallet
///
/// For a usage example see [this module](crate::wallet::export)'s documentation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletExport {
    pub descriptor: String,
    /// Earliest block to rescan when looking for the wallet's transactions
    pub blockheight: u32,
    /// Arbitrary label for the wallet
    pub label: String,
    /// Hex-encoded private key (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex_secret: Option<String>,
}

impl fmt::Display for WalletExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap())
    }
}

impl FromStr for WalletExport {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

fn remove_checksum(s: String) -> String {
    s.split_once('#').map(|(a, _)| String::from(a)).unwrap()
}

impl WalletExport {
    /// Export a wallet
    ///
    /// This function returns an error if it determines that the `wallet`'s descriptor(s) are not
    /// supported by Bitcoin Core or don't follow the standard derivation paths defined by BIP44
    /// and others.
    ///
    /// If `include_blockheight` is `true`, this function will look into the `wallet`'s database
    /// for the oldest transaction it knows and use that as the earliest block to rescan.
    ///
    /// If the database is empty or `include_blockheight` is false, the `blockheight` field
    /// returned will be `0`.
    pub fn export_wallet(
        wallet: &Wallet,
        label: &str,
        blockheight: u32,
        include_hex_secret: bool,
    ) -> Result<Self, &'static str> {
        let descriptor = wallet
            .public_descriptor(KeychainKind::External)
            .to_string_with_secret(
                &wallet
                    .get_signers(KeychainKind::External)
                    .as_key_map(wallet.secp_ctx()),
            );
        let descriptor = remove_checksum(descriptor);

        // Extract hex secret if requested
        let hex_secret = if include_hex_secret {
            match wallet
                .get_signers(KeychainKind::External)
                .signers()
                .iter()
                .filter_map(|s| s.descriptor_secret_key())
                .next()
            {
                Some(DescriptorSecretKey::XPrv(xprv)) => {
                    Some(hex::encode(xprv.xkey.private_key.secret_bytes()))
                }
                _ => None,
            }
        } else {
            None
        };

        let export = WalletExport {
            descriptor,
            label: label.into(),
            blockheight,
            hex_secret,
        };

        let change_descriptor = {
            let descriptor = wallet
                .public_descriptor(KeychainKind::Internal)
                .to_string_with_secret(
                    &wallet
                        .get_signers(KeychainKind::Internal)
                        .as_key_map(wallet.secp_ctx()),
                );
            Some(remove_checksum(descriptor))
        };

        if export.change_descriptor() != change_descriptor {
            return Err("Incompatible change descriptor");
        }

        Ok(export)
    }

    /// Return the external descriptor
    pub fn descriptor(&self) -> String {
        self.descriptor.clone()
    }

    /// Return the internal descriptor, if present
    pub fn change_descriptor(&self) -> Option<String> {
        let replaced = self.descriptor.replace("/0/*", "/1/*");

        if replaced != self.descriptor {
            Some(replaced)
        } else {
            None
        }
    }
}
