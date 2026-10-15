//! Message framing: split a byte stream into discrete messages.
//!
//! Strategies: length_prefix, delimiter, fixed, regex.
use once_cell::sync::Lazy;
use std::collections::HashMap;

use crate::safe_eval::{eval, EvalContext, Expr, Value};

#[derive(Debug, Clone)]
pub enum FramingStrategy {
    /// Read a length prefix of `prefix_bytes`, then `length` bytes.
    LengthPrefix {
        prefix_bytes: usize,
        big_endian: bool,
        /// If true, `length` includes the prefix itself.
        length_includes_prefix: bool,
        max_message: usize,
    },
    /// Split on a fixed delimiter. `include_delim` controls whether the
    /// delimiter is part of the emitted message.
    Delimiter {
        delim: Vec<u8>,
        include_delim: bool,
        max_message: usize,
    },
    /// Fixed-size messages.
    Fixed { size: usize, max_message: usize },
    /// Regex-based. The first match in the buffer is the message.
    Regex {
        pattern: String,
        include_match: bool,
        max_message: usize,
    },
}

#[derive(Debug, Clone)]
pub struct FramedMessage {
    pub offset: u64,
    pub length: usize,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FramingOutput {
    pub messages: Vec<FramedMessage>,
    pub leftover: Vec<u8>,
    pub leftover_offset: u64,
    pub leftover_reason: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("message exceeds max_message ({0})")]
    TooLarge(usize),
    #[error("regex compile error: {0}")]
    RegexCompile(String),
    #[error("constraint expression error: {0}")]
    Constraint(String),
}

pub fn frame(
    stream: &[u8],
    strategy: &FramingStrategy,
) -> Result<FramingOutput, FramingError> {
    match strategy {
        FramingStrategy::LengthPrefix {
            prefix_bytes,
            big_endian,
            length_includes_prefix,
            max_message,
        } => frame_length_prefix(
            stream,
            *prefix_bytes,
            *big_endian,
            *length_includes_prefix,
            *max_message,
        ),
        FramingStrategy::Delimiter {
            delim,
            include_delim,
            max_message,
        } => frame_delimiter(stream, delim, *include_delim, *max_message),
        FramingStrategy::Fixed { size, max_message } => frame_fixed(stream, *size, *max_message),
        FramingStrategy::Regex {
            pattern,
            include_match,
            max_message,
        } => frame_regex(stream, pattern, *include_match, *max_message),
    }
}

fn frame_length_prefix(
    stream: &[u8],
    prefix_bytes: usize,
    big_endian: bool,
    length_includes_prefix: bool,
    max_message: usize,
) -> Result<FramingOutput, FramingError> {
    let mut messages = Vec::new();
    let mut pos = 0usize;
    let mut leftover_reason: Option<String> = None;

    while pos + prefix_bytes <= stream.len() {
        let prefix = &stream[pos..pos + prefix_bytes];
        let mut len: u64 = 0;
        if big_endian {
            for &b in prefix {
                len = (len << 8) | b as u64;
            }
        } else {
            for &b in prefix.iter().rev() {
                len = (len << 8) | b as u64;
            }
        }
        let total = if length_includes_prefix {
            len as usize
        } else {
            prefix_bytes + len as usize
        };
        if total > max_message {
            return Err(FramingError::TooLarge(total));
        }
        if pos + total > stream.len() {
            let available = stream.len() - pos;
            leftover_reason = Some(format!(
                "prefix at offset {} says {} bytes, only {} available",
                pos, total, available
            ));
            break;
        }
        messages.push(FramedMessage {
            offset: pos as u64,
            length: total,
            bytes: stream[pos..pos + total].to_vec(),
        });
        pos += total;
    }

    // Если цикл завершился по условию `pos + prefix_bytes > stream.len()`
    // и leftover_reason ещё не выставлен — значит остался «огрызок»
    // меньше размера префикса, не из чего даже прочитать длину.
    if leftover_reason.is_none() && pos < stream.len() {
        let available = stream.len() - pos;
        if available > 0 {
            leftover_reason = Some(format!(
                "{} trailing bytes < prefix_bytes={}, cannot read length",
                available, prefix_bytes
            ));
        }
    }

    Ok(FramingOutput {
        messages,
        leftover: stream[pos..].to_vec(),
        leftover_offset: pos as u64,
        leftover_reason,
    })
}

fn frame_delimiter(
    stream: &[u8],
    delim: &[u8],
    include_delim: bool,
    max_message: usize,
) -> Result<FramingOutput, FramingError> {
    if delim.is_empty() {
        return Ok(FramingOutput {
            messages: Vec::new(),
            leftover: stream.to_vec(),
            leftover_offset: 0,
            leftover_reason: Some("empty delimiter — nothing to split on".into()),
        });
    }
    let mut messages = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i + delim.len() <= stream.len() {
        if &stream[i..i + delim.len()] == delim {
            let end = if include_delim { i + delim.len() } else { i };
            let msg = stream[start..end].to_vec();
            if msg.len() > max_message {
                return Err(FramingError::TooLarge(msg.len()));
            }
            messages.push(FramedMessage {
                offset: start as u64,
                length: msg.len(),
                bytes: msg,
            });
            i += delim.len();
            start = i;
        } else {
            i += 1;
        }
    }

    let leftover_reason = if start < stream.len() {
        Some(format!(
            "trailing {} bytes without delimiter at the end",
            stream.len() - start
        ))
    } else {
        None
    };

    Ok(FramingOutput {
        messages,
        leftover: stream[start..].to_vec(),
        leftover_offset: start as u64,
        leftover_reason,
    })
}

fn frame_fixed(
    stream: &[u8],
    size: usize,
    max_message: usize,
) -> Result<FramingOutput, FramingError> {
    if size == 0 || size > max_message {
        return Err(FramingError::TooLarge(size));
    }
    let mut messages = Vec::new();
    let mut pos = 0usize;
    while pos + size <= stream.len() {
        messages.push(FramedMessage {
            offset: pos as u64,
            length: size,
            bytes: stream[pos..pos + size].to_vec(),
        });
        pos += size;
    }

    let leftover_reason = if pos < stream.len() {
        Some(format!(
            "trailing {} bytes < fixed size {}",
            stream.len() - pos,
            size
        ))
    } else {
        None
    };

    Ok(FramingOutput {
        messages,
        leftover: stream[pos..].to_vec(),
        leftover_offset: pos as u64,
        leftover_reason,
    })
}

static REGEX_CACHE: Lazy<std::sync::Mutex<HashMap<String, regex::Regex>>> =
    Lazy::new(|| std::sync::Mutex::new(HashMap::new()));

fn compile_regex(pattern: &str) -> Result<regex::Regex, FramingError> {
    let mut cache = REGEX_CACHE.lock().unwrap();
    if let Some(r) = cache.get(pattern) {
        return Ok(r.clone());
    }
    let r = regex::Regex::new(pattern).map_err(|e| FramingError::RegexCompile(e.to_string()))?;
    cache.insert(pattern.to_string(), r.clone());
    Ok(r)
}

fn frame_regex(
    stream: &[u8],
    pattern: &str,
    include_match: bool,
    max_message: usize,
) -> Result<FramingOutput, FramingError> {
    let re = compile_regex(pattern)?;
    // Regex crate operates on &str. We restrict to UTF-8-lossy view.
    let text = String::from_utf8_lossy(stream).into_owned();
    let mut messages = Vec::new();
    let mut last_end = 0usize;

    for m in re.find_iter(&text) {
        // Message boundaries:
        //   include_match=true  → message = сам матч [m.start, m.end)
        //   include_match=false → message = gap перед матчем [last_end, m.start)
        let (start, end) = if include_match {
            (m.start(), m.end())
        } else {
            (last_end, m.start())
        };

        if end <= start {
            // Пустое сообщение — пропускаем, но обновляем курсор
            if include_match {
                last_end = m.end();
            }
            continue;
        }

        let slice = &stream[start..end];
        if slice.len() > max_message {
            return Err(FramingError::TooLarge(slice.len()));
        }
        messages.push(FramedMessage {
            offset: start as u64,
            length: slice.len(),
            bytes: slice.to_vec(),
        });

        if include_match {
            last_end = m.end();
        } else {
            last_end = m.start();
        }
    }

    // Leftover — всё, что после последнего матча (для include_match=true)
    // или после последнего gap-сообщения (для include_match=false).
    let leftover_start = if include_match {
        last_end
    } else {
        // Для include_match=false последнее "сообщение" — это gap перед последним
        // матчем. Всё, начиная с последнего матча, — leftover.
        last_end
    };
    let leftover = if leftover_start <= stream.len() {
        stream[leftover_start..].to_vec()
    } else {
        Vec::new()
    };

    let leftover_reason = if leftover.is_empty() {
        None
    } else {
        Some(format!(
            "trailing {} bytes unmatched by regex",
            leftover.len()
        ))
    };

    Ok(FramingOutput {
        messages,
        leftover,
        leftover_offset: leftover_start as u64,
        leftover_reason,
    })
}

/// Optional constraint check against a framed message.
pub fn check_constraints(
    constraints: &[Expr],
    fields: &HashMap<String, Value>,
) -> Result<bool, FramingError> {
    let mut ctx = EvalContext::new();
    for (k, v) in fields {
        ctx.set(k.clone(), v.clone());
    }
    for c in constraints {
        let v = eval(c, &ctx).map_err(|e| FramingError::Constraint(e.to_string()))?;
        if !v.as_bool().map_err(|e| FramingError::Constraint(e.to_string()))? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefix_be() {
        let mut s = Vec::new();
        s.extend_from_slice(&[0x00, 0x03, b'a', b'b', b'c']);
        s.extend_from_slice(&[0x00, 0x02, b'h', b'i']);
        let strat = FramingStrategy::LengthPrefix {
            prefix_bytes: 2,
            big_endian: true,
            length_includes_prefix: false,
            max_message: 1024,
        };
        let out = frame(&s, &strat).unwrap();
        assert_eq!(out.messages.len(), 2);
        assert_eq!(out.messages[0].bytes, b"\x00\x03abc");
        assert_eq!(out.messages[1].bytes, b"\x00\x02hi");
    }

    #[test]
    fn delimiter_crlf() {
        let s = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nBODY";
        let strat = FramingStrategy::Delimiter {
            delim: b"\r\n\r\n".to_vec(),
            include_delim: true,
            max_message: 65536,
        };
        let out = frame(s, &strat).unwrap();
        assert_eq!(out.messages.len(), 1);
        assert!(out.messages[0].bytes.ends_with(b"\r\n\r\n"));
        assert_eq!(out.leftover, b"BODY");
    }

    #[test]
    fn fixed_size() {
        let s = b"AAAAABBBBBCC";
        let strat = FramingStrategy::Fixed {
            size: 5,
            max_message: 100,
        };
        let out = frame(s, &strat).unwrap();
        assert_eq!(out.messages.len(), 2);
        assert_eq!(out.leftover, b"CC");
    }

    #[test]
    fn regex_line() {
        let s = b"one\ntwo\nthree";
        let strat = FramingStrategy::Regex {
            pattern: r"[^\n]*\n".into(),
            include_match: true,
            max_message: 1024,
        };
        let out = frame(s, &strat).unwrap();
        assert_eq!(out.messages.len(), 2);
        assert_eq!(out.messages[0].bytes, b"one\n");
        assert_eq!(out.messages[1].bytes, b"two\n");
    }

    #[test]
    fn length_prefix_leftover_reason_insufficient_data() {
        // Префикс говорит "5 байт", но в потоке только 3 после префикса
        let s = b"\x00\x05ab"; // prefix=00 05 → length=5, available = 2
        let strat = FramingStrategy::LengthPrefix {
            prefix_bytes: 2,
            big_endian: true,
            length_includes_prefix: false,
            max_message: 1024,
        };
        let out = frame(s, &strat).unwrap();
        assert_eq!(out.messages.len(), 0);
        assert_eq!(out.leftover.len(), 4);
        assert!(out.leftover_reason.is_some());
        let reason = out.leftover_reason.unwrap();
        assert!(reason.contains("says 7 bytes"), "reason: {}", reason);
        assert!(reason.contains("only 4 available"), "reason: {}", reason);
    }

    #[test]
    fn length_prefix_leftover_reason_short_tail() {
        // Один байт в хвосте < prefix_bytes=2 — нельзя даже прочитать длину
        let s = b"\x00\x03abc\xFF"; // 5 байт, prefix 2, msg 3, хвост 1 байт
        let strat = FramingStrategy::LengthPrefix {
            prefix_bytes: 2,
            big_endian: true,
            length_includes_prefix: false,
            max_message: 1024,
        };
        let out = frame(s, &strat).unwrap();
        assert_eq!(out.messages.len(), 1);
        assert_eq!(out.messages[0].bytes, b"\x00\x03abc");
        assert_eq!(out.leftover, b"\xFF");
        assert!(out.leftover_reason.is_some());
        assert!(out.leftover_reason.unwrap().contains("1 trailing bytes"));
    }

    #[test]
    fn delimiter_leftover_reason() {
        let s = b"one\r\ntwo\r\nthree";
        let strat = FramingStrategy::Delimiter {
            delim: b"\r\n".to_vec(),
            include_delim: false,
            max_message: 1024,
        };
        let out = frame(s, &strat).unwrap();
        assert_eq!(out.messages.len(), 2);
        assert_eq!(out.leftover, b"three");
        assert!(out.leftover_reason.is_some());
    }

    #[test]
    fn fixed_leftover_reason() {
        let s = b"ABCDEFGHXY";
        let strat = FramingStrategy::Fixed {
            size: 4,
            max_message: 100,
        };
        let out = frame(s, &strat).unwrap();
        assert_eq!(out.messages.len(), 2);
        assert_eq!(out.leftover, b"XY");
        assert!(out.leftover_reason.is_some());
        assert!(out.leftover_reason.unwrap().contains("trailing 2 bytes"));
    }
}