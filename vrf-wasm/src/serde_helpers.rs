// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use crate::error::FastCryptoError;

// Serde treats arrays larger than 32 as variable length arrays, and adds the length as a prefix.
// Since we want a fixed size representation, we wrap it in this helper struct and use serde_as.
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct SerializationHelper<const N: usize>(#[serde_as(as = "[_; N]")] pub [u8; N]);

pub trait ToFromByteArray<const LENGTH: usize>: Sized {
    const BYTE_LENGTH: usize = LENGTH;
    fn from_byte_array(bytes: &[u8; LENGTH]) -> Result<Self, FastCryptoError>;
    fn to_byte_array(&self) -> [u8; LENGTH];
}

/// Macro for generating Serialize/Deserialize for a type that implements [ToFromByteArray].
#[macro_export]
macro_rules! serialize_deserialize_with_to_from_byte_array {
    ($type:ty) => {
        impl ::serde::Serialize for $type {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use $crate::encoding::Base64;
                use $crate::encoding::Encoding;
                use $crate::serde_helpers::SerializationHelper;

                let bytes = &self.to_byte_array();
                match serializer.is_human_readable() {
                    true => Base64::encode(bytes).serialize(serializer),
                    false => SerializationHelper::<{ <$type>::BYTE_LENGTH }>(*bytes)
                        .serialize(serializer),
                }
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $type {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                use $crate::encoding::Base64;
                use $crate::encoding::Encoding;
                use $crate::serde_helpers::SerializationHelper;

                let bytes = match deserializer.is_human_readable() {
                    true => {
                        let s = String::deserialize(deserializer)?;
                        let decoded = Base64::decode(&s)
                            .map_err(|_| de::Error::custom("Base64 decoding failed"))?;
                        if decoded.len() != { <$type>::BYTE_LENGTH } {
                            return Err(de::Error::custom(format!(
                                "Invalid buffer length {}, expecting {}",
                                decoded.len(),
                                { <$type>::BYTE_LENGTH }
                            )));
                        }
                        decoded.try_into().unwrap()
                    }
                    false => {
                        let helper: SerializationHelper<{ <$type>::BYTE_LENGTH }> =
                            Deserialize::deserialize(deserializer)?;
                        helper.0
                    }
                };
                Self::from_byte_array(&bytes)
                    .map_err(|_| de::Error::custom("Failed in reconstructing the object"))
            }
        }
    };
}

#[macro_export]
macro_rules! serialize_deserialize_with_to_from_bytes {
    ($type:ty, $length:tt) => {
        impl ::serde::Serialize for $type {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use $crate::serde_helpers::SerializationHelper;
                match serializer.is_human_readable() {
                    true => serializer.serialize_str(&self.encode_base64()),
                    false => SerializationHelper::<{ $length }>(self.as_ref().try_into().unwrap())
                        .serialize(serializer),
                }
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $type {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                use serde::Deserialize;
                use $crate::serde_helpers::SerializationHelper;
                if deserializer.is_human_readable() {
                    let s = <String as ::serde::Deserialize>::deserialize(deserializer)?;
                    Self::decode_base64(&s).map_err(::serde::de::Error::custom)
                } else {
                    let helper: SerializationHelper<{ $length }> =
                        Deserialize::deserialize(deserializer)?;
                    <Self as ToFromBytes>::from_bytes(&helper.0).map_err(::serde::de::Error::custom)
                }
            }
        }
    };
}
