//! Safe expression evaluation for framing offsets, sizes and constraints.
//!
//! Only a whitelisted AST is evaluated. No arbitrary code, no I/O, no
//! environment access. All arithmetic promotes to i128 internally and
//! checks range on the way out.
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    UInt(u64),
    Bool(bool),
    Str(String),
    Bytes(Vec<u8>),
    Null,
}

impl Value {
    pub fn as_i128(&self) -> Result<i128, EvalError> {
        match self {
            Value::Int(i) => Ok(*i as i128),
            Value::UInt(u) => Ok(*u as i128),
            Value::Bool(b) => Ok(if *b { 1 } else { 0 }),
            other => Err(EvalError::TypeError(format!(
                "expected number, got {:?}",
                other
            ))),
        }
    }

    pub fn as_bool(&self) -> Result<bool, EvalError> {
        match self {
            Value::Bool(b) => Ok(*b),
            Value::Int(i) => Ok(*i != 0),
            Value::UInt(u) => Ok(*u != 0),
            Value::Null => Ok(false),
            Value::Str(s) => Ok(!s.is_empty()),
            Value::Bytes(b) => Ok(!b.is_empty()),
        }
    }

    pub fn from_i128(v: i128) -> Result<Value, EvalError> {
        if (0..=u64::MAX as i128).contains(&v) {
            Ok(Value::UInt(v as u64))
        } else if (i64::MIN as i128..=i64::MAX as i128).contains(&v) {
            Ok(Value::Int(v as i64))
        } else {
            Err(EvalError::Overflow)
        }
    }
}

// ← ДОБАВЛЕНО: хелперы для сохранения знаковости.
//
// Правило: если ХОТЯ БЫ ОДИН операнд — Int, результат арифметики
// тоже должен быть Int. Иначе знаковое поле (i16be и т.п.) после
// арифметики неожиданно превращается в UInt, и `temp_raw == temp`
// перестаёт быть true для положительных значений.
//
// Пример: temp_raw = Int(291), temp = temp_raw // 10.
// Без хелпера: 291 // 10 = 29 → from_i128(29) → UInt(29).
// С хелпером:  prefer_int(Int, UInt) = true → Int(29).
fn prefer_int(a: &Value, b: &Value) -> bool {
    matches!(a, Value::Int(_)) || matches!(b, Value::Int(_))
}

/// Упаковывает i128 обратно в Value, сохраняя Int, если prefer_int.
/// Если результат не влезает в i64 — падает в UInt через from_i128.
fn from_i128_signed(v: i128, prefer_signed: bool) -> Result<Value, EvalError> {
    if prefer_signed && (i64::MIN as i128..=i64::MAX as i128).contains(&v) {
        Ok(Value::Int(v as i64))
    } else {
        Value::from_i128(v)
    }
}

#[derive(Debug, Clone)]
pub enum Expr {
    Const(Value),
    Field(String),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    Div(Box<Expr>, Box<Expr>),
    FloorDiv(Box<Expr>, Box<Expr>),
    Mod(Box<Expr>, Box<Expr>),
    Neg(Box<Expr>),
    Eq(Box<Expr>, Box<Expr>),
    Ne(Box<Expr>, Box<Expr>),
    Lt(Box<Expr>, Box<Expr>),
    Le(Box<Expr>, Box<Expr>),
    Gt(Box<Expr>, Box<Expr>),
    Ge(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    BitAnd(Box<Expr>, Box<Expr>),
    BitOr(Box<Expr>, Box<Expr>),
    BitXor(Box<Expr>, Box<Expr>),
    Shl(Box<Expr>, Box<Expr>),
    Shr(Box<Expr>, Box<Expr>),
    Len(Box<Expr>),
    Contains(Box<Expr>, Box<Expr>),
    Exists(String),
}

pub struct EvalContext {
    pub fields: HashMap<String, Value>,
}

impl EvalContext {
    pub fn new() -> Self {
        EvalContext {
            fields: HashMap::new(),
        }
    }
    pub fn set(&mut self, name: impl Into<String>, value: Value) {
        self.fields.insert(name.into(), value);
    }
}

impl Default for EvalContext {
    fn default() -> Self {
        EvalContext::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EvalError {
    #[error("field not found: {0}")]
    FieldNotFound(String),
    #[error("type error: {0}")]
    TypeError(String),
    #[error("division by zero")]
    DivisionByZero,
    #[error("numeric overflow")]
    Overflow,
    #[error("shift amount out of range")]
    BadShift,
}

pub fn eval(expr: &Expr, ctx: &EvalContext) -> Result<Value, EvalError> {
    match expr {
        Expr::Const(v) => Ok(v.clone()),
        Expr::Field(name) => ctx
            .fields
            .get(name)
            .cloned()
            .ok_or_else(|| EvalError::FieldNotFound(name.clone())),

        Expr::Add(a, b) => num2(a, b, ctx, |x, y| x.checked_add(y)),
        Expr::Sub(a, b) => num2(a, b, ctx, |x, y| x.checked_sub(y)),
        Expr::Mul(a, b) => num2(a, b, ctx, |x, y| x.checked_mul(y)),

        // ← ИЗМЕНЕНО: все арифметические ветки теперь сохраняют
        // знаковость через prefer_int / from_i128_signed.
        Expr::Div(a, b) => {
            let av = eval(a, ctx)?;
            let bv = eval(b, ctx)?;
            let pi = prefer_int(&av, &bv);
            let x = av.as_i128()?;
            let y = bv.as_i128()?;
            if y == 0 {
                return Err(EvalError::DivisionByZero);
            }
            from_i128_signed(x.checked_div(y).ok_or(EvalError::Overflow)?, pi)
        }
        Expr::FloorDiv(a, b) => {
            let av = eval(a, ctx)?;
            let bv = eval(b, ctx)?;
            let pi = prefer_int(&av, &bv);
            let x = av.as_i128()?;
            let y = bv.as_i128()?;
            if y == 0 {
                return Err(EvalError::DivisionByZero);
            }
            from_i128_signed(x.div_euclid(y), pi)
        }
        Expr::Mod(a, b) => {
            let av = eval(a, ctx)?;
            let bv = eval(b, ctx)?;
            let pi = prefer_int(&av, &bv);
            let x = av.as_i128()?;
            let y = bv.as_i128()?;
            if y == 0 {
                return Err(EvalError::DivisionByZero);
            }
            from_i128_signed(x.rem_euclid(y), pi)
        }
        Expr::Neg(a) => {
            let av = eval(a, ctx)?;
            // Neg сохраняет тип операнда: Int остаётся Int, UInt → Int.
            let pi = matches!(av, Value::Int(_));
            let x = av.as_i128()?;
            from_i128_signed(x.checked_neg().ok_or(EvalError::Overflow)?, pi)
        }

        Expr::Eq(a, b) => Ok(Value::Bool(eval(a, ctx)? == eval(b, ctx)?)),
        Expr::Ne(a, b) => Ok(Value::Bool(eval(a, ctx)? != eval(b, ctx)?)),
        Expr::Lt(a, b) => cmp(a, b, ctx, |o| o == std::cmp::Ordering::Less),
        Expr::Le(a, b) => cmp(a, b, ctx, |o| o != std::cmp::Ordering::Greater),
        Expr::Gt(a, b) => cmp(a, b, ctx, |o| o == std::cmp::Ordering::Greater),
        Expr::Ge(a, b) => cmp(a, b, ctx, |o| o != std::cmp::Ordering::Less),

        Expr::And(a, b) => {
            let x = eval(a, ctx)?.as_bool()?;
            if !x {
                return Ok(Value::Bool(false));
            }
            Ok(Value::Bool(eval(b, ctx)?.as_bool()?))
        }
        Expr::Or(a, b) => {
            let x = eval(a, ctx)?.as_bool()?;
            if x {
                return Ok(Value::Bool(true));
            }
            Ok(Value::Bool(eval(b, ctx)?.as_bool()?))
        }
        Expr::Not(a) => Ok(Value::Bool(!eval(a, ctx)?.as_bool()?)),

        Expr::BitAnd(a, b) => int2(a, b, ctx, |x, y| x & y),
        Expr::BitOr(a, b) => int2(a, b, ctx, |x, y| x | y),
        Expr::BitXor(a, b) => int2(a, b, ctx, |x, y| x ^ y),

        // ← ИЗМЕНЕНО: shl/shr тоже сохраняют знаковость.
        Expr::Shl(a, b) => {
            let av = eval(a, ctx)?;
            let bv = eval(b, ctx)?;
            let pi = prefer_int(&av, &bv);
            let x = av.as_i128()?;
            let y = bv.as_i128()?;
            if !(0..128).contains(&y) {
                return Err(EvalError::BadShift);
            }
            from_i128_signed(
                x.checked_shl(y as u32).ok_or(EvalError::Overflow)?,
                pi,
            )
        }
        Expr::Shr(a, b) => {
            let av = eval(a, ctx)?;
            let bv = eval(b, ctx)?;
            let pi = prefer_int(&av, &bv);
            let x = av.as_i128()?;
            let y = bv.as_i128()?;
            if !(0..128).contains(&y) {
                return Err(EvalError::BadShift);
            }
            from_i128_signed(
                x.checked_shr(y as u32).ok_or(EvalError::Overflow)?,
                pi,
            )
        }

        Expr::Exists(name) => Ok(Value::Bool(ctx.fields.contains_key(name))),

        Expr::Len(a) => match eval(a, ctx)? {
            Value::Bytes(b) => Ok(Value::UInt(b.len() as u64)),
            Value::Str(s) => Ok(Value::UInt(s.len() as u64)),
            other => Err(EvalError::TypeError(format!(
                "len() expects bytes or str, got {:?}",
                other
            ))),
        },
        Expr::Contains(a, b) => {
            let hay = eval(a, ctx)?;
            let needle = eval(b, ctx)?;
            match (hay, needle) {
                (Value::Bytes(h), Value::Bytes(n)) => Ok(Value::Bool(
                    h.windows(n.len()).any(|w| w == n.as_slice()),
                )),
                (Value::Str(h), Value::Str(n)) => Ok(Value::Bool(h.contains(&n))),
                _ => Err(EvalError::TypeError(
                    "contains() expects bytes/bytes or str/str".into(),
                )),
            }
        }
    }
}

// ← ИЗМЕНЕНО: num2 сохраняет знаковость.
fn num2(
    a: &Expr,
    b: &Expr,
    ctx: &EvalContext,
    op: impl FnOnce(i128, i128) -> Option<i128>,
) -> Result<Value, EvalError> {
    let av = eval(a, ctx)?;
    let bv = eval(b, ctx)?;
    let pi = prefer_int(&av, &bv);
    let x = av.as_i128()?;
    let y = bv.as_i128()?;
    from_i128_signed(op(x, y).ok_or(EvalError::Overflow)?, pi)
}

// ← ИЗМЕНЕНО: int2 сохраняет знаковость.
fn int2(
    a: &Expr,
    b: &Expr,
    ctx: &EvalContext,
    op: impl FnOnce(i128, i128) -> i128,
) -> Result<Value, EvalError> {
    let av = eval(a, ctx)?;
    let bv = eval(b, ctx)?;
    let pi = prefer_int(&av, &bv);
    let x = av.as_i128()?;
    let y = bv.as_i128()?;
    from_i128_signed(op(x, y), pi)
}

fn cmp(
    a: &Expr,
    b: &Expr,
    ctx: &EvalContext,
    pred: impl FnOnce(std::cmp::Ordering) -> bool,
) -> Result<Value, EvalError> {
    let x = eval(a, ctx)?.as_i128()?;
    let y = eval(b, ctx)?.as_i128()?;
    Ok(Value::Bool(pred(x.cmp(&y))))
}

/// Evaluate a list of constraint expressions; returns Ok(true) iff all hold.
pub fn eval_constraints(constraints: &[Expr], ctx: &EvalContext) -> Result<bool, EvalError> {
    for c in constraints {
        if !eval(c, ctx)?.as_bool()? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(v: i64) -> Box<Expr> {
        Box::new(Expr::Const(Value::Int(v)))
    }
    fn uint(v: u64) -> Box<Expr> {
        Box::new(Expr::Const(Value::UInt(v)))
    }

    #[test]
    fn arith() {
        let ctx = EvalContext::new();
        // ← ИЗМЕНЕНО: Int + Int → Int (было UInt(5)).
        let e = Expr::Add(int(2), int(3));
        assert_eq!(eval(&e, &ctx).unwrap(), Value::Int(5));
        let e = Expr::Sub(int(2), int(5));
        assert_eq!(eval(&e, &ctx).unwrap(), Value::Int(-3));
        let e = Expr::FloorDiv(int(-7), int(2));
        assert_eq!(eval(&e, &ctx).unwrap(), Value::Int(-4));
        // ← ИЗМЕНЕНО: Int % Int → Int (было UInt(1)).
        let e = Expr::Mod(int(-7), int(2));
        assert_eq!(eval(&e, &ctx).unwrap(), Value::Int(1));

        // ← ДОБАВЛЕНО: смешанные операнды → Int, если есть Int.
        let e = Expr::Add(int(10), uint(20));
        assert_eq!(eval(&e, &ctx).unwrap(), Value::Int(30));
        let e = Expr::Add(uint(10), int(20));
        assert_eq!(eval(&e, &ctx).unwrap(), Value::Int(30));

        // ← ДОБАВЛЕНО: UInt + UInt → UInt (не сломали).
        let e = Expr::Add(uint(10), uint(20));
        assert_eq!(eval(&e, &ctx).unwrap(), Value::UInt(30));
    }

    #[test]
    fn div_by_zero() {
        let ctx = EvalContext::new();
        let e = Expr::Div(int(1), int(0));
        assert!(matches!(eval(&e, &ctx), Err(EvalError::DivisionByZero)));
    }

    #[test]
    fn exists_op() {
        let mut ctx = EvalContext::new();
        ctx.set("x", Value::UInt(10));
        assert_eq!(eval(&Expr::Exists("x".into()), &ctx).unwrap(), Value::Bool(true));
        assert_eq!(eval(&Expr::Exists("y".into()), &ctx).unwrap(), Value::Bool(false));
    }

    #[test]
    fn overflow() {
        let ctx = EvalContext::new();
        let e = Expr::Mul(
            Box::new(Expr::Const(Value::UInt(u64::MAX))),
            Box::new(Expr::Const(Value::UInt(2))),
        );
        assert!(matches!(eval(&e, &ctx), Err(EvalError::Overflow)));
    }

    #[test]
    fn fields() {
        let mut ctx = EvalContext::new();
        ctx.set("x", Value::UInt(10));
        let e = Expr::Gt(Box::new(Expr::Field("x".into())), uint(5));
        assert_eq!(eval(&e, &ctx).unwrap(), Value::Bool(true));
    }

    // ← ДОБАВЛЕНО: тесты на знаковость арифметики.
    #[test]
    fn signed_preservation_floordiv() {
        // temp_raw (Int) // const → Int
        let mut ctx = EvalContext::new();
        ctx.set("temp_raw", Value::Int(291));
        let e = Expr::FloorDiv(
            Box::new(Expr::Field("temp_raw".into())),
            Box::new(Expr::Const(Value::Int(10))),
        );
        assert_eq!(eval(&e, &ctx).unwrap(), Value::Int(29));
    }

    #[test]
    fn signed_uint_field_div_stays_uint() {
        // Если оба операнда UInt, результат — UInt.
        let mut ctx = EvalContext::new();
        ctx.set("x", Value::UInt(291));
        let e = Expr::FloorDiv(
            Box::new(Expr::Field("x".into())),
            Box::new(Expr::Const(Value::UInt(10))),
        );
        assert_eq!(eval(&e, &ctx).unwrap(), Value::UInt(29));
    }

    #[test]
    fn signed_preservation_neg() {
        let ctx = EvalContext::new();
        let e = Expr::Neg(int(5));
        assert_eq!(eval(&e, &ctx).unwrap(), Value::Int(-5));

        let e = Expr::Neg(uint(5));
        assert_eq!(eval(&e, &ctx).unwrap(), Value::Int(-5));
    }

    #[test]
    fn signed_preservation_bitand() {
        let ctx = EvalContext::new();
        let e = Expr::BitAnd(int(0xFF), int(0x0F));
        assert_eq!(eval(&e, &ctx).unwrap(), Value::Int(0x0F));
    }
}