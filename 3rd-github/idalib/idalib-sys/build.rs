use std::env;
use std::path::{Path, PathBuf};

use autocxx_bindgen::Builder as BindgenBuilder;

fn normalize_sdk_root(path: impl AsRef<Path>) -> Option<PathBuf> {
    let path = path.as_ref();

    if path.join("include").join("pro.h").exists() {
        return Some(path.to_path_buf());
    }

    let src = path.join("src");
    if src.join("include").join("pro.h").exists() {
        return Some(src);
    }

    if path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.eq_ignore_ascii_case("include"))
        .unwrap_or(false)
        && path.join("pro.h").exists()
    {
        return path.parent().map(Path::to_path_buf);
    }

    None
}

fn candidate_sdk_paths() -> Vec<PathBuf> {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR should be set"));
    let third_party_dir = manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf);

    let mut candidates = Vec::new();

    for key in ["IDALIB_SDK", "IDASDKDIR", "IDASDK"] {
        if let Some(path) = env::var_os(key).map(PathBuf::from) {
            candidates.push(path);
        }
    }

    candidates.push(manifest_dir.join("sdk/src"));
    candidates.push(manifest_dir.join("sdk"));

    if let Some(third_party_dir) = third_party_dir {
        candidates.push(third_party_dir.join("ida-sdk"));
        candidates.push(third_party_dir.join("idasdk"));
        candidates.push(third_party_dir.join("ida-sdk").join("src"));
        candidates.push(third_party_dir.join("idasdk").join("src"));
    }

    candidates
}

fn resolve_sdk_root() -> PathBuf {
    let candidates = candidate_sdk_paths();

    for candidate in &candidates {
        if let Some(root) = normalize_sdk_root(candidate) {
            return root;
        }
    }

    let tried = candidates
        .iter()
        .map(|path| format!("  - {}", path.display()))
        .collect::<Vec<_>>()
        .join("\n");

    panic!(
        "Could not locate a usable IDA SDK.\n\
         Set IDASDKDIR (or IDALIB_SDK) to an SDK root containing include/pro.h and lib/...\n\
         Tried:\n{}",
        tried
    );
}

/// Get the target OS from Cargo's environment (supports cross-compilation)
fn target_os() -> String {
    env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| {
        if cfg!(target_os = "linux") {
            "linux".to_string()
        } else if cfg!(target_os = "macos") {
            "macos".to_string()
        } else if cfg!(target_os = "windows") {
            "windows".to_string()
        } else {
            panic!("unsupported host platform")
        }
    })
}

/// Get the target arch from Cargo's environment (supports cross-compilation)
fn target_arch() -> String {
    env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| {
        if cfg!(target_arch = "x86_64") {
            "x86_64".to_string()
        } else if cfg!(target_arch = "aarch64") {
            "aarch64".to_string()
        } else {
            panic!("unsupported host architecture")
        }
    })
}

/// Get platform-specific clang args for the target
fn platform_clang_args() -> Vec<&'static str> {
    let os = target_os();
    let arch = target_arch();

    if os == "linux" {
        vec!["-std=c++17", "-w", "-D__LINUX__=1", "-D__EA64__=1"]
    } else if os == "macos" && arch == "aarch64" {
        vec!["-std=c++17", "-D__MACOS__=1", "-D__ARM__=1", "-D__EA64__=1"]
    } else if os == "macos" {
        vec!["-std=c++17", "-D__MACOS__=1", "-D__EA64__=1"]
    } else if os == "windows" {
        vec!["-std=c++17", "-D__NT__=1", "-D__EA64__=1"]
    } else {
        panic!("unsupported platform: {}", os)
    }
}

fn configure_and_generate(builder: BindgenBuilder, ida: &Path, output: impl AsRef<Path>) {
    let rs = PathBuf::from(env::var("OUT_DIR").unwrap()).join(output.as_ref());

    let mut builder = builder
        .clang_arg("-xc++")
        .clang_arg(format!("-I{}", ida.display()));

    for arg in platform_clang_args() {
        builder = builder.clang_arg(arg);
    }

    let bindings = builder
        .respect_cxx_access_specs(true)
        .generate()
        .expect("generate bindings");

    bindings.write_to_file(rs).expect("write bindings");
}

fn main() {
    println!("cargo::rerun-if-env-changed=IDASDKDIR");
    println!("cargo::rerun-if-env-changed=IDALIB_SDK");
    println!("cargo::rerun-if-env-changed=IDASDK");

    let sdk_path = resolve_sdk_root();
    let ida = sdk_path.join("include");

    println!("cargo::warning=Using IDA SDK at {}", sdk_path.display());

    cxx_build::CFG.exported_header_dirs.push(&ida);

    let ffi_path = Path::new("src");

    let clang_args = platform_clang_args();

    let mut builder = autocxx_build::Builder::new(ffi_path.join("lib.rs"), [ffi_path, &*ida])
        .extra_clang_args(&clang_args)
        .build()
        .expect("parsed correctly");

    builder.file(ffi_path.join("udt_extras.cc"));
    builder.file(ffi_path.join("types_extras.cc"));
    builder.file(ffi_path.join("frame_extras.cc"));
    builder.file(ffi_path.join("expr_extras.cc"));

    let os = target_os();
    let arch = target_arch();

    if os == "linux" {
        builder
            .cargo_warnings(false)
            .warnings(false)
            .extra_warnings(false)
            .flag_if_supported("-std=c++17")
            .flag_if_supported("-Wno-nullability-completeness")
            .flag_if_supported("-Wno-nontrivial-memcall")
            .flag_if_supported("-Wno-varargs")
            .flag_if_supported("-fpermissive") // Allow non-conforming code
            .define("__LINUX__", "1")
            .define("__EA64__", "1")
            .compile("libida-stubs");
    } else if os == "macos" {
        let mut b = builder;
        b.cargo_warnings(false);
        b.warnings(false);
        b.flag_if_supported("-std=c++17");
        b.flag_if_supported("-Wno-nullability-completeness");
        b.flag_if_supported("-Wno-nontrivial-memcall");
        b.flag_if_supported("-Wno-varargs");
        b.define("__MACOS__", "1");
        b.define("__EA64__", "1");

        if arch == "aarch64" {
            b.define("__ARM__", "1");
        }

        b.compile("libida-stubs");
    } else if os == "windows" {
        // Note: MSVC linker may report LNK2005 duplicate symbol errors due to
        // cxx-generated wrappers conflicting with manual implementations.
        // This is worked around with /FORCE:MULTIPLE linker flag.
        println!("cargo::rustc-link-arg=/FORCE:MULTIPLE");
        builder
            .cargo_warnings(false)
            .warnings(false)
            .cpp(true)
            .std("c++17")
            .flag("/w") // Suppress all warnings on MSVC
            .define("__NT__", "1")
            .define("__EA64__", "1")
            .compile("libida-stubs");
    }

    let pod = autocxx_bindgen::builder()
        .header(ida.join("pro.h").to_str().expect("path is valid string"))
        .header(ida.join("ua.hpp").to_str().expect("path is valid string"))
        .allowlist_type("insn_t")
        .allowlist_type("op_t")
        .allowlist_type("optype_t")
        .allowlist_item("OF_.*");

    configure_and_generate(pod, &ida, "pod.rs");

    let idp = autocxx_bindgen::builder()
        .header(ida.join("pro.h").to_str().expect("path is valid string"))
        .header(ida.join("idp.hpp").to_str().expect("path is valid string"))
        .allowlist_item("PLFM_.*");

    configure_and_generate(idp, &ida, "idp.rs");

    let inf = autocxx_bindgen::builder()
        .header(ida.join("pro.h").to_str().expect("path is valid string"))
        .header(ida.join("ida.hpp").to_str().expect("path is valid string"))
        .header(
            ida.join("typeinf.hpp")
                .to_str()
                .expect("path is valid string"),
        )
        .allowlist_item("AF_.*")
        .allowlist_item("AF2_.*")
        .allowlist_item("CM_.*")
        .allowlist_item("COMP_.*")
        .allowlist_item("INFFL_.*")
        .allowlist_item("LFLG_.*")
        .allowlist_item("STT_.*")
        .allowlist_item("SW_.*")
        .allowlist_item("compiler_info_t");

    configure_and_generate(inf, &ida, "inf.rs");

    let insn_consts = [
        ("ARM_.*", "insn_arm.rs"),
        ("NN_.*", "insn_x86.rs"),
        ("MIPS_.*", "insn_mips.rs"),
    ];

    for (prefix, output) in insn_consts {
        let arch = autocxx_bindgen::builder()
            .header(ida.join("pro.h").to_str().expect("path is valid string"))
            .header(
                ida.join("allins.hpp")
                    .to_str()
                    .expect("path is a valid string"),
            )
            .clang_arg("-fshort-enums")
            .allowlist_item(prefix);

        configure_and_generate(arch, &ida, output);
    }

    let hexrays = autocxx_bindgen::builder()
        .header(ida.join("pro.h").to_str().expect("path is valid string"))
        .header(
            ida.join("hexrays.hpp")
                .to_str()
                .expect("path is valid string"),
        )
        .opaque_type("std::.*")
        .opaque_type("carglist_t")
        // Block iterator types that conflict across multiple template instantiations in IDA 9.3
        .blocklist_type("iterator")
        .blocklist_type("const_iterator")
        .blocklist_type(".*_iterator")
        .blocklist_type(".*_const_iterator")
        .allowlist_item("cfunc_t")
        .allowlist_item("citem_t")
        .allowlist_item("cexpr_t")
        .allowlist_item("cinsn_t")
        .allowlist_item("cblock_t")
        .allowlist_item("cswitch_t")
        .allowlist_item("ctry_t")
        .allowlist_item("cthrow_t")
        .allowlist_item("cnumber_t")
        .allowlist_item("lvar_t")
        .allowlist_item("lvar_locator_t")
        .allowlist_item("vdloc_t")
        .allowlist_item("CV_.*")
        .allowlist_item("DECOMP_.*");

    configure_and_generate(hexrays, &ida, "hexrays.rs");

    println!("cargo::metadata=sdk={}", sdk_path.display());

    // Track changes to source files that affect compilation
    // Primary FFI entry point
    println!(
        "cargo::rerun-if-changed={}",
        ffi_path.join("lib.rs").display()
    );

    // Track all header files in src/ (extras and core definitions)
    let header_files = [
        "auto_extras.h",
        "bookmarks_extras.h",
        "bytes_extras.h",
        "comments_extras.h",
        "entry_extras.h",
        "expr_extras.h",
        "fixups.h",
        "frame_extras.h",
        "func_extras.h",
        "hexrays_extras.h",
        "idalib_extras.h",
        "inf_extras.h",
        "kernwin_extras.h",
        "lines_extras.h",
        "loader_extras.h",
        "nalt_extras.h",
        "ph_extras.h",
        "search_extras.h",
        "segm_extras.h",
        "strings_extras.h",
        "types.h",
        "udt_extras.h",
    ];

    for header in &header_files {
        println!(
            "cargo::rerun-if-changed={}",
            ffi_path.join(header).display()
        );
    }

    // Track all C++ implementation files in src/
    let cc_files = [
        "expr_extras.cc",
        "frame_extras.cc",
        "types_extras.cc",
        "udt_extras.cc",
    ];

    for cc_file in &cc_files {
        println!(
            "cargo::rerun-if-changed={}",
            ffi_path.join(cc_file).display()
        );
    }
}
