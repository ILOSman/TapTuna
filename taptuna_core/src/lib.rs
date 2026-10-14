use pyo3::prelude::*;

pub mod wire;
pub mod seq;
pub mod reassembly;
pub mod safe_eval;
pub mod extract;
pub mod framing;

mod wire_py;
mod seq_py;
mod reassembly_py;
mod safe_eval_py;
mod extract_py;
mod framing_py;

#[pyfunction]
fn __version__() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(__version__, m)?)?;
    m.add("wire", wire_py::create_module(m.py())?)?;
    m.add("seq", seq_py::create_module(m.py())?)?;
    m.add("reassembly", reassembly_py::create_module(m.py())?)?;
    m.add("safe_eval", safe_eval_py::create_module(m.py())?)?;
    m.add("extract", extract_py::create_module(m.py())?)?;
    m.add("framing", framing_py::create_module(m.py())?)?;
    Ok(())
}