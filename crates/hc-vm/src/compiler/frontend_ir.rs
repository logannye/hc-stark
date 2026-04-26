//! Typed intermediate representation for the hc-STARK compiler.
//!
//! Programs are represented as a sequence of function definitions, each
//! containing a list of basic blocks. This IR is designed to be:
//!
//! 1. Simple enough to lower directly to VM instructions.
//! 2. Rich enough to express loops, conditionals, and function calls.
//! 3. Easy to construct from a text DSL or JSON.

use std::fmt;

/// A complete IR program: a collection of named functions.
#[derive(Clone, Debug)]
pub struct IrProgram {
    /// All function definitions. The first one is the entry point.
    pub functions: Vec<FnDef>,
}

impl IrProgram {
    pub fn new(functions: Vec<FnDef>) -> Self {
        Self { functions }
    }

    /// Get the entry-point function (the first one).
    pub fn entry(&self) -> Option<&FnDef> {
        self.functions.first()
    }

    /// Look up a function by name.
    pub fn find_function(&self, name: &str) -> Option<&FnDef> {
        self.functions.iter().find(|f| f.name == name)
    }
}

/// A function definition.
#[derive(Clone, Debug)]
pub struct FnDef {
    /// Function name (used for calls and debug output).
    pub name: String,
    /// Parameter names (mapped to registers during lowering).
    pub params: Vec<String>,
    /// The function body as a list of statements.
    pub body: Vec<Stmt>,
}

/// A statement in the IR.
#[derive(Clone, Debug)]
pub enum Stmt {
    /// `let name = expr;` — bind a new variable.
    Let { name: String, value: Expr },
    /// `name = expr;` — assign to an existing variable.
    Assign { name: String, value: Expr },
    /// `if cond { then_body } else { else_body }`
    If {
        condition: Expr,
        then_body: Vec<Stmt>,
        else_body: Vec<Stmt>,
    },
    /// `while cond { body }`
    While { condition: Expr, body: Vec<Stmt> },
    /// `for name in start..end { body }` (counted loop, unrolled during lowering).
    For {
        var: String,
        start: Expr,
        end: Expr,
        body: Vec<Stmt>,
    },
    /// `return expr;`
    Return(Expr),
    /// `assert_zero(expr);` — constrain expression to zero.
    AssertZero(Expr),
    /// `store(addr_expr, value_expr);`
    Store { addr: Expr, value: Expr },
    /// Raw VM instruction (escape hatch for advanced users).
    RawInstruction(crate::isa::Instruction),
}

/// An expression in the IR.
#[derive(Clone, Debug)]
pub enum Expr {
    /// Integer literal.
    Literal(u64),
    /// Variable reference.
    Var(String),
    /// Binary operation.
    BinOp {
        op: BinOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    /// Unary operation.
    UnaryOp { op: UnaryOp, operand: Box<Expr> },
    /// Function call.
    Call { name: String, args: Vec<Expr> },
    /// Memory load: `load(addr_expr)`.
    Load(Box<Expr>),
}

/// Binary operators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Eq,
    Lt,
}

/// Unary operators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnaryOp {
    Neg,
    Inv,
    Square,
}

// ─── Display implementations ─────────────────────────────────────────────────

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BinOp::Add => write!(f, "+"),
            BinOp::Sub => write!(f, "-"),
            BinOp::Mul => write!(f, "*"),
            BinOp::And => write!(f, "&"),
            BinOp::Or => write!(f, "|"),
            BinOp::Xor => write!(f, "^"),
            BinOp::Shl => write!(f, "<<"),
            BinOp::Shr => write!(f, ">>"),
            BinOp::Eq => write!(f, "=="),
            BinOp::Lt => write!(f, "<"),
        }
    }
}

impl fmt::Display for UnaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnaryOp::Neg => write!(f, "-"),
            UnaryOp::Inv => write!(f, "inv"),
            UnaryOp::Square => write!(f, "sq"),
        }
    }
}

// ─── Builder helpers ─────────────────────────────────────────────────────────

impl Expr {
    /// Shorthand for `Expr::Literal(n)`.
    pub fn lit(n: u64) -> Self {
        Self::Literal(n)
    }

    /// Shorthand for `Expr::Var(name)`.
    pub fn var(name: &str) -> Self {
        Self::Var(name.to_string())
    }

    // The add/sub/mul builder methods below build AST nodes rather than perform
    // arithmetic. Naming them after the std::ops traits is deliberate (it gives
    // a fluent builder API) but clippy can't tell — silence the false positive.
    #[allow(clippy::should_implement_trait)]
    /// `self + other`
    pub fn add(self, other: Self) -> Self {
        Self::BinOp {
            op: BinOp::Add,
            left: Box::new(self),
            right: Box::new(other),
        }
    }

    #[allow(clippy::should_implement_trait)]
    /// `self - other`
    pub fn sub(self, other: Self) -> Self {
        Self::BinOp {
            op: BinOp::Sub,
            left: Box::new(self),
            right: Box::new(other),
        }
    }

    #[allow(clippy::should_implement_trait)]
    /// `self * other`
    pub fn mul(self, other: Self) -> Self {
        Self::BinOp {
            op: BinOp::Mul,
            left: Box::new(self),
            right: Box::new(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_fibonacci_ir() {
        let program = IrProgram::new(vec![FnDef {
            name: "fib".to_string(),
            params: vec!["n".to_string()],
            body: vec![
                Stmt::Let {
                    name: "a".to_string(),
                    value: Expr::lit(1),
                },
                Stmt::Let {
                    name: "b".to_string(),
                    value: Expr::lit(1),
                },
                Stmt::For {
                    var: "i".to_string(),
                    start: Expr::lit(0),
                    end: Expr::var("n"),
                    body: vec![
                        Stmt::Let {
                            name: "tmp".to_string(),
                            value: Expr::var("a").add(Expr::var("b")),
                        },
                        Stmt::Assign {
                            name: "a".to_string(),
                            value: Expr::var("b"),
                        },
                        Stmt::Assign {
                            name: "b".to_string(),
                            value: Expr::var("tmp"),
                        },
                    ],
                },
                Stmt::Return(Expr::var("a")),
            ],
        }]);
        assert_eq!(program.entry().unwrap().name, "fib");
        assert_eq!(program.functions.len(), 1);
    }

    #[test]
    fn find_function_by_name() {
        let program = IrProgram::new(vec![
            FnDef {
                name: "main".to_string(),
                params: vec![],
                body: vec![],
            },
            FnDef {
                name: "helper".to_string(),
                params: vec!["x".to_string()],
                body: vec![],
            },
        ]);
        assert!(program.find_function("helper").is_some());
        assert!(program.find_function("missing").is_none());
    }
}
