//! Certificate compression and decompression support

use alloc::vec::Vec;
use core::fmt::Debug;

use crate::enums::CertificateCompressionAlgorithm;

/// Returns the supported `CertDecompressor` implementations enabled
/// by crate features.
pub fn default_cert_decompressors() -> &'static [&'static dyn CertDecompressor] {
    &[
        #[cfg(feature = "brotli")]
        BROTLI_DECOMPRESSOR,
        #[cfg(feature = "zlib")]
        ZLIB_DECOMPRESSOR,
    ]
}

/// An available certificate decompression algorithm.
pub trait CertDecompressor: Debug + Send + Sync {
    /// Decompress `input`, writing the result to `output`.
    ///
    /// `output` is sized to match the declared length of the decompressed data.
    ///
    /// `Err(DecompressionFailed)` should be returned if decompression produces more, or fewer
    /// bytes than fit in `output`, or if the `input` is in any way malformed.
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed>;

    /// Which algorithm this decompressor handles.
    fn algorithm(&self) -> CertificateCompressionAlgorithm;
}

/// Returns the supported `CertCompressor` implementations enabled
/// by crate features.
pub fn default_cert_compressors() -> &'static [&'static dyn CertCompressor] {
    &[
        #[cfg(feature = "brotli")]
        BROTLI_COMPRESSOR,
        #[cfg(feature = "zlib")]
        ZLIB_COMPRESSOR,
    ]
}

/// An available certificate compression algorithm.
pub trait CertCompressor: Debug + Send + Sync {
    /// Compress `input`, returning the result.
    ///
    /// `input` is consumed by this function so (if the underlying implementation
    /// supports it) the compression can be performed in-place.
    ///
    /// `level` is a hint as to how much effort to expend on the compression.
    ///
    /// `Err(CompressionFailed)` may be returned for any reason.
    fn compress(
        &self,
        input: Vec<u8>,
        level: CompressionLevel,
    ) -> Result<Vec<u8>, CompressionFailed>;

    /// Which algorithm this compressor handles.
    fn algorithm(&self) -> CertificateCompressionAlgorithm;
}

/// A hint for how many resources to dedicate to a compression.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CompressionLevel {
    /// This compression is happening interactively during a handshake.
    ///
    /// Implementations may wish to choose a conservative compression level.
    Interactive,

    /// The compression may be amortized over many connections.
    ///
    /// Implementations may wish to choose an aggressive compression level.
    Amortized,
}

/// A content-less error for when `CertDecompressor::decompress` fails.
#[derive(Debug)]
pub struct DecompressionFailed;

/// A content-less error for when `CertCompressor::compress` fails.
#[derive(Debug)]
pub struct CompressionFailed;

#[cfg(feature = "zlib")]
mod feat_zlib_rs {
    use zlib_rs::c_api::Z_BEST_COMPRESSION;
    use zlib_rs::{deflate, inflate, ReturnCode};

    use super::*;

    /// A certificate decompressor for the Zlib algorithm using the `zlib-rs` crate.
    pub const ZLIB_DECOMPRESSOR: &dyn CertDecompressor = &ZlibRsDecompressor;

    #[derive(Debug)]
    struct ZlibRsDecompressor;

    impl CertDecompressor for ZlibRsDecompressor {
        fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
            let output_len = output.len();
            match inflate::uncompress_slice(output, input, inflate::InflateConfig::default()) {
                (output_filled, ReturnCode::Ok) if output_filled.len() == output_len => Ok(()),
                (_, _) => Err(DecompressionFailed),
            }
        }

        fn algorithm(&self) -> CertificateCompressionAlgorithm {
            CertificateCompressionAlgorithm::Zlib
        }
    }

    /// A certificate compressor for the Zlib algorithm using the `zlib-rs` crate.
    pub const ZLIB_COMPRESSOR: &dyn CertCompressor = &ZlibRsCompressor;

    #[derive(Debug)]
    struct ZlibRsCompressor;

    impl CertCompressor for ZlibRsCompressor {
        fn compress(
            &self,
            input: Vec<u8>,
            level: CompressionLevel,
        ) -> Result<Vec<u8>, CompressionFailed> {
            let mut output = alloc::vec![0u8; deflate::compress_bound(input.len())];
            let config = match level {
                CompressionLevel::Interactive => deflate::DeflateConfig::default(),
                CompressionLevel::Amortized => deflate::DeflateConfig::new(Z_BEST_COMPRESSION),
            };
            let (output_filled, rc) = deflate::compress_slice(&mut output, &input, config);
            if rc != ReturnCode::Ok {
                return Err(CompressionFailed);
            }

            let used = output_filled.len();
            output.truncate(used);
            Ok(output)
        }

        fn algorithm(&self) -> CertificateCompressionAlgorithm {
            CertificateCompressionAlgorithm::Zlib
        }
    }
}

#[cfg(feature = "zlib")]
pub use feat_zlib_rs::{ZLIB_COMPRESSOR, ZLIB_DECOMPRESSOR};

#[cfg(feature = "brotli")]
mod feat_brotli {
    use std::io::{Cursor, Write};

    use super::*;

    /// A certificate decompressor for the brotli algorithm using the `brotli` crate.
    pub const BROTLI_DECOMPRESSOR: &dyn CertDecompressor = &BrotliDecompressor;

    #[derive(Debug)]
    struct BrotliDecompressor;

    impl CertDecompressor for BrotliDecompressor {
        fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
            let mut in_cursor = Cursor::new(input);
            let mut out_cursor = Cursor::new(output);

            brotli::BrotliDecompress(&mut in_cursor, &mut out_cursor)
                .map_err(|_| DecompressionFailed)?;

            if out_cursor.position() as usize != out_cursor.into_inner().len() {
                return Err(DecompressionFailed);
            }

            Ok(())
        }

        fn algorithm(&self) -> CertificateCompressionAlgorithm {
            CertificateCompressionAlgorithm::Brotli
        }
    }

    /// A certificate compressor for the brotli algorithm using the `brotli` crate.
    pub const BROTLI_COMPRESSOR: &dyn CertCompressor = &BrotliCompressor;

    #[derive(Debug)]
    struct BrotliCompressor;

    impl CertCompressor for BrotliCompressor {
        fn compress(
            &self,
            input: Vec<u8>,
            level: CompressionLevel,
        ) -> Result<Vec<u8>, CompressionFailed> {
            let quality = match level {
                CompressionLevel::Interactive => QUALITY_FAST,
                CompressionLevel::Amortized => QUALITY_SLOW,
            };
            let output = Cursor::new(Vec::with_capacity(input.len() / 2));
            let mut compressor = brotli::CompressorWriter::new(output, BUFFER_SIZE, quality, LGWIN);
            compressor
                .write_all(&input)
                .map_err(|_| CompressionFailed)?;
            Ok(compressor.into_inner().into_inner())
        }

        fn algorithm(&self) -> CertificateCompressionAlgorithm {
            CertificateCompressionAlgorithm::Brotli
        }
    }

    /// Brotli buffer size.
    ///
    /// Chosen based on brotli `examples/compress.rs`.
    const BUFFER_SIZE: usize = 4096;

    /// This is the default lgwin parameter, see `BrotliEncoderInitParams()`
    const LGWIN: u32 = 22;

    /// Compression quality we use for interactive compressions.
    /// See <https://blog.cloudflare.com/results-experimenting-brotli> for data.
    const QUALITY_FAST: u32 = 4;

    /// Compression quality we use for offline compressions (the maximum).
    const QUALITY_SLOW: u32 = 11;
}

#[cfg(feature = "brotli")]
pub use feat_brotli::{BROTLI_COMPRESSOR, BROTLI_DECOMPRESSOR};

#[cfg(all(test, any(feature = "brotli", feature = "zlib")))]
pub mod tests {
    use std::{println, vec};

    use super::*;

    #[test]
    #[cfg(feature = "zlib")]
    fn test_zlib() {
        test_compressor(ZLIB_COMPRESSOR, ZLIB_DECOMPRESSOR);
    }

    #[test]
    #[cfg(feature = "brotli")]
    fn test_brotli() {
        test_compressor(BROTLI_COMPRESSOR, BROTLI_DECOMPRESSOR);
    }

    fn test_compressor(comp: &dyn CertCompressor, decomp: &dyn CertDecompressor) {
        assert_eq!(comp.algorithm(), decomp.algorithm());
        for sz in [16, 64, 512, 2048, 8192, 16384] {
            test_trivial_pairwise(comp, decomp, sz);
        }
        test_decompress_wrong_len(comp, decomp);
        test_decompress_garbage(decomp);
    }

    fn test_trivial_pairwise(
        comp: &dyn CertCompressor,
        decomp: &dyn CertDecompressor,
        plain_len: usize,
    ) {
        let original = vec![0u8; plain_len];

        for level in [CompressionLevel::Interactive, CompressionLevel::Amortized] {
            let compressed = comp
                .compress(original.clone(), level)
                .unwrap();
            println!(
                "{:?} compressed trivial {} -> {} using {:?} level",
                comp.algorithm(),
                original.len(),
                compressed.len(),
                level
            );
            let mut recovered = vec![0xffu8; plain_len];
            decomp
                .decompress(&compressed, &mut recovered)
                .unwrap();
            assert_eq!(original, recovered);
        }
    }

    fn test_decompress_wrong_len(comp: &dyn CertCompressor, decomp: &dyn CertDecompressor) {
        let original = vec![0u8; 2048];
        let compressed = comp
            .compress(original.clone(), CompressionLevel::Interactive)
            .unwrap();
        println!("{compressed:?}");

        // too big
        let mut recovered = vec![0xffu8; original.len() + 1];
        decomp
            .decompress(&compressed, &mut recovered)
            .unwrap_err();

        // too small
        let mut recovered = vec![0xffu8; original.len() - 1];
        decomp
            .decompress(&compressed, &mut recovered)
            .unwrap_err();
    }

    fn test_decompress_garbage(decomp: &dyn CertDecompressor) {
        let junk = [0u8; 1024];
        let mut recovered = vec![0u8; 512];
        decomp
            .decompress(&junk, &mut recovered)
            .unwrap_err();
    }
}