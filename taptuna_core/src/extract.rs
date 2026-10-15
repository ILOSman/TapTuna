//! Declarative field extractor.
//!
//! A `MessageSpec` describes an ordered list of fields. Each field has a
//! type, an offset rule and a size rule. Offsets and sizes may be constant,
//! refer to a previous field, or be an expression evaluated by `safe_eval`.
use std::collections::HashMap;

use crate::safe_eval::{eval, EvalContext, EvalError, Expr, Value};

#[derive(Debug, Clone)]
pub enum FieldType {
    U8,
    I8,
    U16Be,
    U16Le,
    U24Be,
    U24Le,
    U32Be,
    U32Le,
    U64Be,
    U64Le,
    Bytes,
    Bcd { digits: usize },
    Utf8,
    Ascii,
    /// Вычисляемое поле: значение = safe_eval-выражение над уже
    /// извлечёнными полями. Байты не читаются.
    Expression(Box<Expr>),
}

#[derive(Debug, Clone)]
pub enum OffsetSpec {
    /// Absolute offset from start of message.
    Fixed(u64),
    /// Offset from end of message (0 = last byte).
    FromEnd(u64),
    /// Continue from end of previous field. Only valid for fields after the first.
    Auto,
    /// Expression evaluated against previously extracted fields.
    Expr(Expr),
}

#[derive(Debug, Clone)]
pub enum SizeSpec {
    /// Fixed byte count.
    Fixed(usize),
    /// Everything up to end of message.
    Remaining,
    /// Expression evaluated against previously extracted fields.
    Expr(Expr),
    /// Size taken from a previously extracted integer field.
    FromField(String),
}

#[derive(Debug, Clone)]
pub struct FieldSpec {
    pub name: String,
    pub field_type: FieldType,
    pub offset: OffsetSpec,
    pub size: SizeSpec,
}

#[derive(Debug, Clone)]
pub struct MessageSpec {
    pub name: String,
    pub fields: Vec<FieldSpec>,
}

#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("buffer too short: need {need} bytes at offset {offset}, have {have}")]
    TooShort { offset: u64, need: usize, have: usize },
    #[error("auto offset used on first field")]
    AutoOnFirst,
    #[error("expr error: {0}")]
    Eval(#[from] EvalError),
    #[error("field {0} not found for size reference")]
    SizeFieldMissing(String),
    #[error("field {0} is not an integer")]
    SizeFieldNotInt(String),
    #[error("bcd field must have even digits; got {0}")]
    BadBcd(usize),
    #[error("utf8 decode error")]
    Utf8,
    #[error("expression field cannot be decoded from bytes")]
    ExpressionNotDecodable,
}

pub fn extract(
    spec: &MessageSpec,
    bytes: &[u8],
) -> Result<HashMap<String, Value>, ExtractError> {
    let mut fields: HashMap<String, Value> = HashMap::new();
    let mut cursor: u64 = 0;

    for (i, f) in spec.fields.iter().enumerate() {
        // Expression: не читаем байты, вычисляем значение из уже
        // извлечённых полей.
        if let FieldType::Expression(expr) = &f.field_type {
            let ctx = make_ctx(&fields);
            let val = eval(expr, &ctx)?;
            fields.insert(f.name.clone(), val);
            continue;
        }

        // Resolve offset.
        let offset = match &f.offset {
            OffsetSpec::Fixed(o) => *o,
            OffsetSpec::FromEnd(n) => (bytes.len() as u64).saturating_sub(*n),
            OffsetSpec::Auto => {
                if i == 0 {
                    return Err(ExtractError::AutoOnFirst);
                }
                cursor
            }
            OffsetSpec::Expr(e) => {
                let ctx = make_ctx(&fields);
                eval(e, &ctx)?.as_i128()? as u64
            }
        };

        // Resolve size.
        let size = match &f.size {
            SizeSpec::Fixed(n) => *n,
            SizeSpec::Remaining => {
                let rem = (bytes.len() as u64).saturating_sub(offset);
                rem as usize
            }
            SizeSpec::Expr(e) => {
                let ctx = make_ctx(&fields);
                let v = eval(e, &ctx)?;
                v.as_i128()? as usize
            }
            SizeSpec::FromField(name) => {
                let v = fields
                    .get(name)
                    .ok_or_else(|| ExtractError::SizeFieldMissing(name.clone()))?;
                let n = v.as_i128()?;
                if n < 0 {
                    return Err(ExtractError::SizeFieldNotInt(name.clone()));
                }
                n as usize
            }
        };

        let start = offset as usize;
        let end = start.checked_add(size).ok_or(ExtractError::TooShort {
            offset,
            need: size,
            have: bytes.len(),
        })?;
        if end > bytes.len() {
            return Err(ExtractError::TooShort {
                offset,
                need: size,
                have: bytes.len(),
            });
        }
        let slice = &bytes[start..end];

        let value = decode(f.field_type.clone(), slice)?;
        fields.insert(f.name.clone(), value);
        cursor = end as u64;
    }

    Ok(fields)
}

fn make_ctx(fields: &HashMap<String, Value>) -> EvalContext {
    let mut ctx = EvalContext::new();
    for (k, v) in fields {
        ctx.set(k.clone(), v.clone());
    }
    ctx
}

fn decode(ft: FieldType, b: &[u8]) -> Result<Value, ExtractError> {
    Ok(match ft {
        FieldType::U8 => Value::UInt(*b.first().unwrap_or(&0) as u64),
        FieldType::I8 => Value::Int(*b.first().unwrap_or(&0) as i8 as i64),
        FieldType::U16Be => Value::UInt(u16::from_be_bytes(need2(b)?) as u64),
        FieldType::U16Le => Value::UInt(u16::from_le_bytes(need2(b)?) as u64),
        FieldType::U24Be => {
            let a = need_n(b, 3)?;
            Value::UInt(((a[0] as u64) << 16) | ((a[1] as u64) << 8) | a[2] as u64)
        }
        FieldType::U24Le => {
            let a = need_n(b, 3)?;
            Value::UInt(((a[2] as u64) << 16) | ((a[1] as u64) << 8) | a[0] as u64)
        }
        FieldType::U32Be => Value::UInt(u32::from_be_bytes(need4(b)?) as u64),
        FieldType::U32Le => Value::UInt(u32::from_le_bytes(need4(b)?) as u64),
        FieldType::U64Be => Value::UInt(u64::from_be_bytes(need8(b)?)),
        FieldType::U64Le => Value::UInt(u64::from_le_bytes(need8(b)?)),
        FieldType::Bytes => Value::Bytes(b.to_vec()),
        FieldType::Ascii => Value::Str(
            std::str::from_utf8(b)
                .map_err(|_| ExtractError::Utf8)?
                .to_string(),
        ),
        FieldType::Utf8 => Value::Str(
            std::str::from_utf8(b)
                .map_err(|_| ExtractError::Utf8)?
                .to_string(),
        ),
        FieldType::Bcd { digits } => {
            if digits == 0 || digits % 2 != 0 {
                return Err(ExtractError::BadBcd(digits));
            }
            let need = digits / 2;
            let a = need_n(b, need)?;
            let mut s = String::with_capacity(digits);
            for byte in a {
                let hi = byte >> 4;
                let lo = byte & 0x0F;
                if hi > 9 || lo > 9 {
                    return Err(ExtractError::BadBcd(digits));
                }
                s.push((b'0' + hi) as char);
                s.push((b'0' + lo) as char);
            }
            Value::Str(s)
        }
        FieldType::Expression(_) => {
            // Не должно случиться: обработка Expression — в `extract`
            // до вызова decode. Если всё-таки пришли — ошибка.
            return Err(ExtractError::ExpressionNotDecodable);
        }
    })
}

fn need2(b: &[u8]) -> Result<[u8; 2], ExtractError> {
    b.try_into().map_err(|_| ExtractError::TooShort {
        offset: 0,
        need: 2,
        have: b.len(),
    })
}
fn need4(b: &[u8]) -> Result<[u8; 4], ExtractError> {
    b.try_into().map_err(|_| ExtractError::TooShort {
        offset: 0,
        need: 4,
        have: b.len(),
    })
}
fn need8(b: &[u8]) -> Result<[u8; 8], ExtractError> {
    b.try_into().map_err(|_| ExtractError::TooShort {
        offset: 0,
        need: 8,
        have: b.len(),
    })
}
fn need_n(b: &[u8], n: usize) -> Result<&[u8], ExtractError> {
    if b.len() < n {
        return Err(ExtractError::TooShort {
            offset: 0,
            need: n,
            have: b.len(),
        });
    }
    Ok(&b[..n])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_len_field(name: &str) -> FieldSpec {
        FieldSpec {
            name: name.into(),
            field_type: FieldType::U16Be,
            offset: OffsetSpec::Auto,
            size: SizeSpec::Fixed(2),
        }
    }

    #[test]
    fn simple_header() {
        // magic (2) | len (2) | payload (len bytes)
        let spec = MessageSpec {
            name: "test".into(),
            fields: vec![
                FieldSpec {
                    name: "magic".into(),
                    field_type: FieldType::U16Be,
                    offset: OffsetSpec::Fixed(0),
                    size: SizeSpec::Fixed(2),
                },
                bytes_len_field("len"), // Auto — ok, это второе поле
                FieldSpec {
                    name: "payload".into(),
                    field_type: FieldType::Bytes,
                    offset: OffsetSpec::Auto,
                    size: SizeSpec::FromField("len".into()),
                },
            ],
        };
        let msg = b"\xCA\xFE\x00\x05hello";
        let out = extract(&spec, msg).unwrap();
        assert_eq!(out.get("magic"), Some(&Value::UInt(0xCAFE)));
        assert_eq!(out.get("len"), Some(&Value::UInt(5)));
        assert_eq!(out.get("payload"), Some(&Value::Bytes(b"hello".to_vec())));
    }

    #[test]
    fn too_short() {
        let spec = MessageSpec {
            name: "t".into(),
            fields: vec![FieldSpec {
                name: "a".into(),
                field_type: FieldType::U16Be,
                offset: OffsetSpec::Fixed(0),
                size: SizeSpec::Fixed(2),
            }],
        };
        let err = extract(&spec, b"\x01").unwrap_err();
        assert!(
            matches!(err, ExtractError::TooShort { .. }),
            "expected TooShort, got {:?}",
            err
        );
    }

    #[test]
    fn expression_field() {
        // temp_raw (2 BE) | temp = temp_raw / 10
        use crate::safe_eval::{Expr, Value as V};
        let expr = Expr::FloorDiv(
            Box::new(Expr::Field("temp_raw".into())),
            Box::new(Expr::Const(V::Int(10))),
        );
        let spec = MessageSpec {
            name: "t".into(),
            fields: vec![
                FieldSpec {
                    name: "temp_raw".into(),
                    field_type: FieldType::U16Be,
                    offset: OffsetSpec::Fixed(0),
                    size: SizeSpec::Fixed(2),
                },
                FieldSpec {
                    name: "temp".into(),
                    field_type: FieldType::Expression(Box::new(expr)),
                    offset: OffsetSpec::Auto,
                    size: SizeSpec::Remaining,
                },
            ],
        };
        // temp_raw = 0x0123 = 291 → temp = 29
        let msg = b"\x01\x23";
        let out = extract(&spec, msg).unwrap();

        // temp_raw — U16Be, поэтому UInt.
        assert_eq!(out.get("temp"), Some(&Value::Int(29)));   // было UInt(29)

        // ← ИЗМЕНЕНО: const 10 приходит как Int(10),
        // правило "Int заражает" даёт Int(29).
        assert_eq!(out.get("temp"), Some(&Value::Int(29)));
    }
}