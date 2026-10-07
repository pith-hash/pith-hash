//! The suite-level error type: every fallible facade call returns it.
//!
//! Two shapes cover the suite: codec rejections arrive as
//! [`pith_digest::Error`] and are wrapped with the modality name
//! in [`Error::Decode`]; `pith-audio` — `no_std`, no edge to
//! digest — carries its own [`pith_audio::Error`], wrapped as
//! [`Error::Audio`]. `Display` for both spells the modality name first,
//! so an error read from a log always says *which* pipeline refused.

use crate::Modality;
use core::fmt;
use pith_digest::Format;

/// Every failure the facade can report.
///
/// `Copy` is impossible: [`Error::Audio`] holds a `String` through
/// `pith_audio::Error`. The type still avoids allocating on the hot
/// paths — codec rejections move a `Copy` inner error.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A modality decoder or the chunker rejected the input. `source`
    /// is the codec's own error; `modality` names the pipeline that
    /// refused, because the same `Error::Truncated` means a different
    /// file in "image:" than in "audio:".
    Decode {
        /// The pipeline that rejected the bytes.
        modality: Modality,
        /// The codec's own typed error.
        source: pith_digest::Error,
    },
    /// A recognized format whose modality lane exists in the design
    /// (mp3 → audio, mp4 → video, pdf → text) but whose crate has not
    /// landed yet. This is a refusal to guess, never a failure to parse
    /// — the bytes may be perfectly valid mp4 and the suite still says
    /// "not yet" instead of hashing container noise.
    Unsupported {
        /// The modality the unlanded crate will serve.
        modality: Modality,
        /// The detected container format.
        format: Format,
        /// What is missing, e.g. `"pith-mp3 decoder has not landed"`.
        what: &'static str,
    },
    /// The PDF text layer's own error type (carries page/object
    /// attribution and cannot fold into [`pith_digest::Error`]).
    Pdf(pith_pdf::Error),
    /// The audio facade's own error type (`pith_audio::Error`
    /// carries a `String` and cannot fold into
    /// [`pith_digest::Error`]).
    Audio(pith_audio::Error),
    /// A structurally valid but semantically impossible call:
    /// `match` on two signatures of different modalities, or text
    /// input that is not valid UTF-8.
    BadValue(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decode { modality, source } => {
                f.write_str(modality.as_str())?;
                f.write_str(": ")?;
                fmt::Display::fmt(source, f)
            }
            Error::Unsupported {
                modality,
                format,
                what,
            } => {
                f.write_str(modality.as_str())?;
                f.write_str(" (")?;
                f.write_str(format.as_str())?;
                f.write_str("): ")?;
                f.write_str(what)
            }
            Error::Audio(e) => {
                f.write_str("audio: ")?;
                fmt::Display::fmt(e, f)
            }
            Error::Pdf(e) => {
                f.write_str("text: ")?;
                fmt::Display::fmt(e, f)
            }
            Error::BadValue(what) => {
                f.write_str("bad value: ")?;
                f.write_str(what)
            }
        }
    }
}

impl core::error::Error for Error {}

impl From<pith_pdf::Error> for Error {
    fn from(e: pith_pdf::Error) -> Self {
        Error::Pdf(e)
    }
}

impl From<pith_audio::Error> for Error {
    fn from(e: pith_audio::Error) -> Self {
        Error::Audio(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use pith_digest::Error as DE;
    use pith_pdf::Error as PdfError;

    /// Every variant spells the modality (or lane) first, so a log line
    /// says which pipeline refused.
    #[test]
    fn display_names_the_lane_first() {
        let decode = Error::Decode {
            modality: Modality::Image,
            source: DE::Unsupported("truncated input"),
        };
        assert_eq!(decode.to_string(), "image: unsupported: truncated input");

        let unsupported = Error::Unsupported {
            modality: Modality::Video,
            format: Format::Mp4,
            what: "non-AVC track",
        };
        assert_eq!(unsupported.to_string(), "video (mp4): non-AVC track");

        let pdf = Error::Pdf(PdfError::Kit(DE::Unsupported("truncated input")));
        assert!(pdf.to_string().starts_with("text: "), "{}", pdf);

        let audio = Error::Audio(pith_audio::Error::Unsupported("sample rate"));
        assert_eq!(audio.to_string(), "audio: unsupported: sample rate");

        assert_eq!(
            Error::BadValue("match_ across different modalities").to_string(),
            "bad value: match_ across different modalities"
        );
    }

    /// The `From` conversions route a codec's own error into the
    /// facade shape without changing its message.
    #[test]
    fn from_conversions_preserve_source_messages() {
        let pdf: Error = PdfError::Kit(DE::Unsupported("truncated input")).into();
        assert!(matches!(pdf, Error::Pdf(_)));

        let audio: Error = pith_audio::Error::Unsupported("no peaks").into();
        assert!(matches!(audio, Error::Audio(_)));
        assert!(audio.to_string().contains("no peaks"));
    }
}
