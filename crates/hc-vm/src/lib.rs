#![forbid(unsafe_code)]

pub mod compiler;
pub mod exec;
pub mod isa;
pub mod memory;
pub mod state;
pub mod trace_gen;

pub use compiler::{compile, lower, parse, CompileError, IrProgram};
pub use exec::{execute, execute_full};
pub use isa::{Instruction, Program};
pub use memory::Memory;
pub use state::{TraceRow, VmState, TRACE_WIDTH};
pub use trace_gen::generate_trace;
