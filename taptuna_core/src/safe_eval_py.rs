use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::safe_eval::{eval, eval_constraints, EvalContext, Expr, Value};

pub fn create_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new_bound(py, "safe_eval")?;
    m.add_function(wrap_pyfunction!(eval_expr, &m)?)?;
    m.add_function(wrap_pyfunction!(eval_constraints_py, &m)?)?;
    Ok(m)
}

pub(crate) fn value_from_py(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    if let Ok(b) = obj.extract::<bool>() {
        return Ok(Value::Bool(b));
    }
    if let Ok(i) = obj.extract::<i64>() {
        return Ok(Value::Int(i));
    }
    if let Ok(u) = obj.extract::<u64>() {
        return Ok(Value::UInt(u));
    }
    if let Ok(s) = obj.extract::<String>() {
        return Ok(Value::Str(s));
    }
    if let Ok(b) = obj.extract::<Vec<u8>>() {
        return Ok(Value::Bytes(b));
    }
    if obj.is_none() {
        return Ok(Value::Null);
    }
    Err(pyo3::exceptions::PyTypeError::new_err(
        "unsupported value type",
    ))
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

/// Parse a JSON-ish dict into an Expr AST.
fn parse_expr(obj: &Bound<'_, PyAny>) -> PyResult<Expr> {
    let d: &Bound<'_, PyDict> = obj.downcast()?;
    let op: String = d
        .get_item("op")?
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("missing 'op'"))?
        .extract()?;

    let req = |k: &str| -> PyResult<Bound<'_, PyAny>> {
        d.get_item(k)?
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err(format!("missing '{}'", k)))
    };

    Ok(match op.as_str() {
        "const" => Expr::Const(value_from_py(&req("value")?)?),
        "field" => Expr::Field(req("name")?.extract()?),
        "add" => Expr::Add(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "sub" => Expr::Sub(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "mul" => Expr::Mul(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "div" => Expr::Div(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "floordiv" => Expr::FloorDiv(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "mod" => Expr::Mod(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "neg" => Expr::Neg(Box::new(parse_expr(&req("a")?)?)),
        "eq" => Expr::Eq(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "ne" => Expr::Ne(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "lt" => Expr::Lt(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "le" => Expr::Le(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "gt" => Expr::Gt(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "ge" => Expr::Ge(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "and" => Expr::And(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "or" => Expr::Or(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "not" => Expr::Not(Box::new(parse_expr(&req("a")?)?)),
        "bitand" => Expr::BitAnd(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "bitor" => Expr::BitOr(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "bitxor" => Expr::BitXor(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "shl" => Expr::Shl(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "shr" => Expr::Shr(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "len" => Expr::Len(Box::new(parse_expr(&req("a")?)?)),
        "contains" => Expr::Contains(
            Box::new(parse_expr(&req("a")?)?),
            Box::new(parse_expr(&req("b")?)?),
        ),
        "exists" => {
            // Принимаем либо {"op":"exists","name":"x"}, либо {"op":"exists","a":{"op":"field","name":"x"}}
            if let Some(name_obj) = d.get_item("name")? {
                Expr::Exists(name_obj.extract()?)
            } else if let Some(a) = d.get_item("a")? {
                let ad: &Bound<'_, PyDict> = a.downcast()?;
                let name: String = ad.get_item("name")?
                    .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("exists: missing 'name'"))?
                    .extract()?;
                Expr::Exists(name)
            } else {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "exists requires 'name' or 'a':{op:field,name}"));
            }
        }
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown op: {}",
                other
            )))
        }
    })
}

#[pyfunction]
fn eval_expr(
    py: Python<'_>,
    expr: &Bound<'_, PyAny>,
    fields: &Bound<'_, PyDict>,
) -> PyResult<PyObject> {
    let e = parse_expr(expr)?;
    let mut ctx = EvalContext::new();
    for (k, v) in fields.iter() {
        ctx.set(k.extract::<String>()?, value_from_py(&v)?);
    }
    let v = eval(&e, &ctx).map_err(|err| {
        pyo3::exceptions::PyValueError::new_err(err.to_string())
    })?;
    value_to_py(py, &v)
}

#[pyfunction]
fn eval_constraints_py(
    exprs: Vec<Bound<'_, PyAny>>,
    fields: &Bound<'_, PyDict>,
) -> PyResult<bool> {
    let mut ctx = EvalContext::new();
    for (k, v) in fields.iter() {
        ctx.set(k.extract::<String>()?, value_from_py(&v)?);
    }
    let mut rust_exprs = Vec::with_capacity(exprs.len());
    for e in &exprs {
        rust_exprs.push(parse_expr(e)?);
    }
    eval_constraints(&rust_exprs, &ctx)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

pub fn parse_expr_pub(obj: &Bound<'_, PyAny>) -> PyResult<Expr> {
    parse_expr(obj)
}