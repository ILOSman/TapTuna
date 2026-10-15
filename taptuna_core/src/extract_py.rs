use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::extract::{extract, FieldSpec, FieldType, MessageSpec, OffsetSpec, SizeSpec};
use crate::safe_eval::Value;
use crate::safe_eval_py::parse_expr_pub;

pub fn create_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new_bound(py, "extract")?;
    m.add_function(wrap_pyfunction!(extract_fields, &m)?)?;
    Ok(m)
}

fn parse_field_type(s: &str, digits: Option<usize>) -> PyResult<FieldType> {
    Ok(match s {
        "u8" => FieldType::U8,
        "i8" => FieldType::I8,
        "u16be" => FieldType::U16Be,
        "u16le" => FieldType::U16Le,
        "u24be" => FieldType::U24Be,
        "u24le" => FieldType::U24Le,
        "u32be" => FieldType::U32Be,
        "u32le" => FieldType::U32Le,
        "u64be" => FieldType::U64Be,
        "u64le" => FieldType::U64Le,
        "bytes" => FieldType::Bytes,
        "utf8" => FieldType::Utf8,
        "ascii" => FieldType::Ascii,
        "bcd" => FieldType::Bcd {
            digits: digits.unwrap_or(2),
        },
        // "expression" обрабатывается отдельно в extract_fields,
        // потому что требует чтения AST из поля `expr`.
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown field type: {}",
                other
            )))
        }
    })
}

fn parse_offset(v: &Bound<'_, PyAny>) -> PyResult<OffsetSpec> {
    if let Ok(i) = v.extract::<u64>() {
        return Ok(OffsetSpec::Fixed(i));
    }
    let d: &Bound<'_, PyDict> = v.downcast()?;
    if let Some(kind) = d.get_item("kind")? {
        let kind: String = kind.extract()?;
        return Ok(match kind.as_str() {
            "auto" => OffsetSpec::Auto,
            "from_end" => OffsetSpec::FromEnd(d.get_item("n")?.unwrap().extract()?),
            "expr" => OffsetSpec::Expr(parse_expr_pub(&d.get_item("expr")?.unwrap())?),
            other => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "unknown offset kind: {}",
                    other
                )))
            }
        });
    }
    Err(pyo3::exceptions::PyValueError::new_err("bad offset spec"))
}

fn parse_size(v: &Bound<'_, PyAny>) -> PyResult<SizeSpec> {
    if let Ok(i) = v.extract::<usize>() {
        return Ok(SizeSpec::Fixed(i));
    }
    if let Ok(s) = v.extract::<String>() {
        if s == "remaining" {
            return Ok(SizeSpec::Remaining);
        }
        return Ok(SizeSpec::FromField(s));
    }
    let d: &Bound<'_, PyDict> = v.downcast()?;
    if let Some(expr) = d.get_item("expr")? {
        return Ok(SizeSpec::Expr(parse_expr_pub(&expr)?));
    }
    if let Some(f) = d.get_item("from_field")? {
        return Ok(SizeSpec::FromField(f.extract()?));
    }
    Err(pyo3::exceptions::PyValueError::new_err("bad size spec"))
}

#[pyfunction]
fn extract_fields(
    py: Python<'_>,
    spec: &Bound<'_, PyDict>,
    bytes: Vec<u8>,
) -> PyResult<PyObject> {
    let name: String = spec
        .get_item("name")?
        .map(|v| v.extract())
        .transpose()?
        .unwrap_or_else(|| "message".into());
    let fields_list: Vec<Bound<'_, PyAny>> = spec
        .get_item("fields")?
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("missing 'fields'"))?
        .downcast::<PyList>()?
        .iter()
        .collect();

    let mut fields = Vec::with_capacity(fields_list.len());
    for f in fields_list {
        let fd: &Bound<'_, PyDict> = f.downcast()?;
        let field_name: String = fd
            .get_item("name")?
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("field must contain 'name'")
            })?
            .extract()?;
        let ftype_str: String = fd
            .get_item("type")?
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("field must contain 'type'")
            })?
            .extract()?;

        if ftype_str == "expression" {
            // Вычисляемое поле: читаем AST из поля `expr`.
            let expr_obj = fd.get_item("expr")?.ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "field '{}': type 'expression' requires 'expr' (safe_eval AST)",
                    field_name
                ))
            })?;
            let expr = parse_expr_pub(&expr_obj)?;
            fields.push(FieldSpec {
                name: field_name,
                field_type: FieldType::Expression(Box::new(expr)),
                // offset/size игнорируются при extract для Expression,
                // но структура требует их наличия.
                offset: OffsetSpec::Auto,
                size: SizeSpec::Remaining,
            });
            continue;
        }

        let digits: Option<usize> = fd
            .get_item("digits")?
            .map(|v| v.extract())
            .transpose()?;
        let ftype = parse_field_type(&ftype_str, digits)?;
        let offset = parse_offset(&fd.get_item("offset")?.unwrap())?;
        let size = parse_size(&fd.get_item("size")?.unwrap())?;
        fields.push(FieldSpec {
            name: field_name,
            field_type: ftype,
            offset,
            size,
        });
    }

    let ms = MessageSpec { name, fields };
    let spec_name = ms.name.clone();
    let out = extract(&ms, &bytes)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{}: {}", spec_name, e)))?;

    let d = PyDict::new_bound(py);
    for (k, v) in out {
        d.set_item(k, value_to_py(py, &v)?)?;
    }
    Ok(d.into())
}

fn value_to_py(py: Python<'_>, v: &Value) -> PyResult<PyObject> {
    Ok(match v {
        Value::Int(i) => i.into_py(py),
        Value::UInt(u) => u.into_py(py),
        Value::Bool(b) => b.into_py(py),
        Value::Str(s) => s.into_py(py),
        Value::Bytes(b) => b.clone().into_py(py),
        Value::Null => py.None(),
    })
}