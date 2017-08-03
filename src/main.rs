// XXX Add license
#![feature(rustc_private)]

extern crate getopts;
extern crate rustc;
extern crate rustc_driver;
extern crate rustc_errors;
extern crate rustc_data_structures;
extern crate syntax;
extern crate log;

use rustc::session::Session;
use rustc_driver::{Compilation, CompilerCalls, RustcDefaultCalls};
use rustc_driver::driver::{CompileState, CompileController};
use rustc::session::config::{self, Input, ErrorOutputType};
use rustc::mir::{BasicBlockData, BasicBlock};
use rustc::hir::def_id::{DefIndex, CrateNum, DefId};
use rustc_data_structures::indexed_vec::Idx;
use syntax::ast;
use std::path::PathBuf;
use std::process::exit;

static CRATE_NAME: &'static str = "rororo";

struct ROCompilerCalls<'tcx> {
    ccs: RustcDefaultCalls,
    def_idx: DefIndex,      // Index of the function
    block: BasicBlock,      // The basic block we are interested in.
    block_data: Option<BasicBlockData<'tcx>>, // The result
}

impl<'tcx> ROCompilerCalls<'tcx> {
    fn new(ccs: RustcDefaultCalls, def_idx: usize, block: usize) -> Self {
        Self {
            ccs: ccs,
            def_idx: DefIndex::new(def_idx),
            block: BasicBlock::new(block),
            block_data: None,
        }
    }
}

impl<'a, 'tcx> CompilerCalls<'a> for ROCompilerCalls<'tcx> {
    fn early_callback(
        &mut self,
        matches: &getopts::Matches,
        sopts: &config::Options,
        cfg: &ast::CrateConfig,
        descriptions: &rustc_errors::registry::Registry,
        output: ErrorOutputType
    ) -> Compilation {
        self.ccs.early_callback(matches, sopts, cfg, descriptions, output)
    }
    fn no_input(
        &mut self,
        matches: &getopts::Matches,
        sopts: &config::Options,
        cfg: &ast::CrateConfig,
        odir: &Option<PathBuf>,
        ofile: &Option<PathBuf>,
        descriptions: &rustc_errors::registry::Registry
    ) -> Option<(Input, Option<PathBuf>)> {
        self.ccs.no_input(matches, sopts, cfg, odir, ofile, descriptions)
    }
    fn late_callback(
        &mut self,
        matches: &getopts::Matches,
        sess: &Session,
        input: &Input,
        odir: &Option<PathBuf>,
        ofile: &Option<PathBuf>
    ) -> Compilation {
        self.ccs.late_callback(matches, sess, input, odir, ofile)
    }

    fn build_controller(&mut self, sess: &Session, matches: &getopts::Matches) -> CompileController<'a> {
        let mut control = self.ccs.build_controller(sess, matches);
        let def_idx = self.def_idx.clone();

        let callback = move |state: &mut CompileState| {
            let did = DefId {
                krate: get_cratenum(state.session),
                index: def_idx,
            };
            println!("{:?}", did);
        };
        control.after_analysis.callback = Box::new(callback);
        control.after_analysis.stop = Compilation::Stop;
        control
    }
}

fn get_cratenum(sess: &Session) -> CrateNum {
    for cnum in sess.cstore.crates() {
        let name = sess.cstore.crate_name(cnum);
        println!("name: {}", name);
        if name == CRATE_NAME {
            return cnum;
        }
    }
    panic!("can't find crate");
}

fn find_sysroot() -> String {
    if let Ok(sysroot) = std::env::var("RO_SYSROOT") {
        return sysroot;
    }

    // Taken from https://github.com/Manishearth/rust-clippy/pull/911.
    let home = option_env!("RUSTUP_HOME").or(option_env!("MULTIRUST_HOME"));
    let toolchain = option_env!("RUSTUP_TOOLCHAIN").or(option_env!("MULTIRUST_TOOLCHAIN"));
    match (home, toolchain) {
        (Some(home), Some(toolchain)) => format!("{}/toolchains/{}", home, toolchain),
        _ => option_env!("RUST_SYSROOT")
            .expect("need to specify RO_SYSROOT env var or use rustup or multirust")
            .to_owned(),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("bad usage");
        exit(1);
    }

    let mut new_args = Vec::new();

    // dummy executable name
    new_args.push(String::from("dummy"));

    // sysroot required
    new_args.push(String::from("--sysroot"));
    new_args.push(find_sysroot());

    // Don't expect to find a main()
    new_args.push(String::from("--crate-type=lib"));

    // The rlib to inspect
    let rlib_arg = format!("{}={}", CRATE_NAME, args[1]);
    new_args.push(String::from("--extern"));
    new_args.push(String::from(rlib_arg));

    // Dummy source file
    new_args.push(String::from("/dev/null"));

    println!("querying {}", args[1]);
    println!("args: {:?}", new_args);

    let mut ro_calls = ROCompilerCalls::new(RustcDefaultCalls, 0, 0);
    rustc_driver::run_compiler(&new_args, &mut ro_calls, None, None);
}
