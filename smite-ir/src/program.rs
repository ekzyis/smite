//! IR program definition.

use serde::{Deserialize, Serialize};

use super::context::ProgramContext;
use super::instruction::Instruction;

/// An IR program: an ordered list of instructions plus execution context.
///
/// Programs are serialized with postcard for transport between the AFL++ custom
/// mutator and the scenario executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    /// Instructions in SSA order.
    pub instructions: Vec<Instruction>,
    /// Snapshot context (target pubkey, chain hash, etc.).
    pub context: ProgramContext,
}
