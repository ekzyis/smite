//! LDK init message fuzzing scenario binary.

use smite::scenarios::smite_run;
use smite_scenarios::scenarios::InitScenario;
use smite_scenarios::targets::LdkTarget;

fn main() -> std::process::ExitCode {
    smite_run::<InitScenario<LdkTarget>>()
}
