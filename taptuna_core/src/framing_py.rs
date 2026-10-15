use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use crate::framing::{frame, FramingStrategy};
use crate::safe_eval::Value;
use crate::safe_eval_py::{parse_expr_pub, value_from_py};
use std::collections::HashMap;

#[pyfunction]
fn check_constraints_py(
    constraints: Vec<Bound<'_, PyAny>>,
    fields: &Bound<'_, PyDict>,
) -> PyResult<bool> {
    let mut rust_fields: HashMap<String, Value> = HashMap::new();
    for (k, v) in fields.iter() {
        rust_fields.insert(k.extract::<String>()?, value_from_py(&v)?);
    }
    let mut exprs = Vec::with_capacity(constraints.len());
    for c in &constraints {
        exprs.push(parse_expr_pub(c)?);
    }
    crate::framing::check_constraints(&exprs, &rust_fields)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

pub fn create_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new_bound(py, "framing")?;
    m.add_function(wrap_pyfunction!(frame_stream, &m)?)?;
    m.add_function(wrap_pyfunction!(check_constraints_py, &m)?)?;
    Ok(m)
}

fn parse_strategy(d: &Bound<'_, PyDict>) -> PyResult<FramingStrategy> {
    let kind: String = d
        .get_item("kind")?
        .ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(
                "framing spec must contain 'kind' field",
            )
        })?
        .extract()?;
    let max_message: usize = d
        .get_item("max_message")?
        .map(|v| v.extract())
        .transpose()?
        .unwrap_or(1 << 24);

    Ok(match kind.as_str() {
        "length_prefix" => FramingStrategy::LengthPrefix {
            prefix_bytes: d
                .get_item("prefix_bytes")?
                .map(|v| v.extract())
                .transpose()?
                .unwrap_or(4),
            big_endian: d
                .get_item("big_endian")?
                .map(|v| v.extract())
                .transpose()?
                .unwrap_or(true),
            length_includes_prefix: d
                .get_item("length_includes_prefix")?
                .map(|v| v.extract())
                .transpose()?
                .unwrap_or(false),
            max_message,
        },
        "delimiter" => FramingStrategy::Delimiter {
            delim: d
                .get_item("delim")?
                .ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(
                        "delimiter framing requires 'delim' field",
                    )
                })?
                .extract()?,
            include_delim: d
                .get_item("include_delim")?
                .map(|v| v.extract())
                .transpose()?
                .unwrap_or(true),
            max_message,
        },
        "fixed" => FramingStrategy::Fixed {
            size: d
                .get_item("size")?
                .ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(
                        "fixed framing requires 'size' field",
                    )
                })?
                .extract()?,
            max_message,
        },
        "regex" => FramingStrategy::Regex {
            pattern: d
                .get_item("pattern")?
                .ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(
                        "regex framing requires 'pattern' field",
                    )
                })?
                .extract()?,
            include_match: d
                .get_item("include_match")?
                .map(|v| v.extract())
                .transpose()?
                .unwrap_or(true),
            max_message,
        },
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown framing strategy: {}",
                other
            )))
        }
    })
}

#[pyfunction]
fn frame_stream(
    py: Python<'_>,
    stream: Vec<u8>,
    strategy: &Bound<'_, PyDict>,
) -> PyResult<PyObject> {
    let strat = parse_strategy(strategy)?;
    let out = frame(&stream, &strat)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

    let messages = PyList::empty_bound(py);
    for m in &out.messages {
        let d = PyDict::new_bound(py);
        d.set_item("offset", m.offset)?;
        d.set_item("length", m.length)?;
        // PyBytes вместо Vec<u8>: PyO3 конвертировал бы Vec<u8> в list[int]
        // (по ~28 байт на элемент). PyBytes — это bytes, 1 байт на элемент.
        // Экономия памяти при 100k сообщений — ~×20-30.
        d.set_item("bytes", PyBytes::new_bound(py, &m.bytes))?;
        messages.append(d)?;
    }

    let result = PyDict::new_bound(py);
    result.set_item("messages", messages)?;
    result.set_item("leftover", PyBytes::new_bound(py, &out.leftover))?;
    result.set_item("leftover_offset", out.leftover_offset)?;
    result.set_item("leftover_reason", out.leftover_reason.clone())?;
    Ok(result.into())
}