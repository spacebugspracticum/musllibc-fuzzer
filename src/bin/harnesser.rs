/// ::crate-lib-name::path::to::item;
use ::libc_fuzzer::{extract_decls, FunctionDecl};
use clap::Parser;
use log::{info, warn};
use std::env::current_dir;
use std::fs::write;
use std::io::{Error};
use std::process::Command;
use which::which;

// libc fuzzer generator
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    // List of libc functions to fuzz
    functions: Vec<String>,
}

fn main() -> Result<(), Error> {
    // Default to info log level
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    // Extract musl libc header declarations
    let args = Args::parse();
    assert!(!args.functions.is_empty());

    // run "grep -iR function_name( musl/install/include/" and use the first result as FILE_SOURCE
    let mut cmd = Command::new("grep");
    cmd.arg("-Rl");
    cmd.arg(args.functions[0].clone());
    cmd.arg("musl/install/include/"); // cmd | head -1
    let output = cmd.output().expect("failed to execute process");
    let output_str = String::from_utf8_lossy(&output.stdout); // use only the first line of the output
    // be graceful and allow None
    let output_str = output_str.lines().next().unwrap_or("");
    let mut file_source = output_str.to_string();

    // if file_source is empty, then run "grep -iR function_name musl/src/" and use the first result as FILE_SOURCE
    if output_str == "" {
        let mut cmd = Command::new("grep");
        cmd.arg("-Rl");
        cmd.arg(args.functions[0].clone());
        cmd.arg("musl/src/"); // cmd | head -1
        let output = cmd.output().expect("failed to execute process");
        let output_str = String::from_utf8_lossy(&output.stdout); // use only the first line of the output
        // be graceful and allow None
        let output_str = output_str.lines().next().unwrap_or("");
        file_source = output_str.to_string();
    }

    let decls = extract_decls();
    info!("Found {} functions.", decls.len());

    // Figure out what functions the user wants to fuzz, which ones are missing, and sanity check
    let to_fuzz: Vec<FunctionDecl> = decls
        .into_iter()
        .filter(|f| -> bool { args.functions.contains(&f.name) })
        .collect();

    let missing: Vec<String> = args
        .functions
        .into_iter()
        .filter(|f| -> bool {
            to_fuzz
                .clone()
                .into_iter()
                .filter(|tf| -> bool { tf.name == f.as_str() })
                .count()
                == 0
        })
        .collect();

    for funcname in missing {
        warn!(
            "Missing function {}, not generating a fuzzer for it.",
            funcname
        );
    }

    if to_fuzz.is_empty() {
        warn!("No functions to fuzz in headers!");
        //return Err(Error::new(ErrorKind::Other, "No functions to fuzz!"));
    }
    
    // Generate harnesses and compile them
    for (funcname, proto, func) in to_fuzz
        .iter()
        .map(|f| -> (String, String, FunctionDecl) { (f.name.clone(), f.proto(), f.clone()) })
    {
        info!("Generating fuzzer for {}: {}", funcname, proto);
        let manual_harness = func.harness("template_manual.cc".to_string(), file_source.to_string());
        info!("Harness code:\n{}", manual_harness.clone());

        write(format!("harness-{}.cc", funcname), manual_harness)
            .expect("Could not write harness file.");

        /* Replicate the musl-clang script for afl-clang-lto++ also */
        let cwd = current_dir().unwrap();
        let fdp_hdr_path = cwd.join("fuzzed_data_provider");
        
        //  afl-clang-fast++ -O0 harness-atoi.cc -I musl/install/include musl/install/lib/libc.so -o harness-atoi
        Command::new("afl-clang-fast++")
            //.arg("-m32")
            .arg("-I")
            .arg(fdp_hdr_path.to_string_lossy().to_string())
            .arg("-I")
            .arg("./musl/install/include/")
            .arg("musl/lib/libc.so")
            .arg("-g")
            .arg("-O0")
            .arg("-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1")
            .arg("-o")
            .arg(format!("harness-{}", funcname))
            .arg(format!("harness-{}.cc", funcname))
            .env("AR", "llvm-ar-14")
            .env("RANLIB", "llvm-ranlib-14")
            .env("CC", which("clang-14").expect("clang-14 is not installed."))
            .env(
                "CXX",
                which("clang++-14").expect("clang++-14 is not installed."),
            )
            .current_dir(cwd.clone())
            .status()
            .expect("Could not compile harness.");
    }

    Ok(())
}
