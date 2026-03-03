pub mod frontend_ir;
pub mod lower_to_vm;
pub mod parser;

pub use frontend_ir::IrProgram;
pub use lower_to_vm::{lower, LowerError};
pub use parser::{parse, ParseError};

/// Error from the combined parse + lower pipeline.
#[derive(Clone, Debug)]
pub enum CompileError {
    Parse(ParseError),
    Lower(LowerError),
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "{e}"),
            Self::Lower(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CompileError {}

impl From<ParseError> for CompileError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

impl From<LowerError> for CompileError {
    fn from(e: LowerError) -> Self {
        Self::Lower(e)
    }
}

/// Compile DSL source to a VM [`Program`](crate::isa::Program) in one step.
///
/// Composes [`parse`] and [`lower`] into a single call.
pub fn compile(source: &str) -> Result<crate::isa::Program, CompileError> {
    let ir = parse(source)?;
    let program = lower(&ir)?;
    Ok(program)
}
