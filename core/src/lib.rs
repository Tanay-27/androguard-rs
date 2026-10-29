//! androguard-core: androguard 4.1.3's APK, DEX, analysis and resources
//! queries, without androguard's memory cost. Output text is byte-identical to androguard 4.1.3.

pub mod agload;
pub mod apk;
pub mod arsc;
pub mod axml;
mod axml_attrs;
pub mod classes;
pub mod dex;
pub mod dexview;
pub mod exercise;
pub mod index;
pub mod insn;
pub mod irregular;
pub mod insn_rows;
pub mod maplist;
pub mod model;
mod py_decimal;
mod py_lower_tables;
mod py_printable;
pub mod render;
pub mod strict;
#[cfg(test)]
mod testdex;
pub mod zipapk;
