load("//:bazel/private/utils.bzl", "expand_header_deps")

EbpfProgram = provider(
    "Describe an EBPF program along with its dependencies",
    fields = {
        "deps": "A list of cc_library target containing the required headers",
    }
)

def _ebpf_compile_flags(ctx):
    debug = ctx.attr.debug
    flags = [
        '-emit-llvm',
        '-D__TARGET_ARCH_x86',
        '-D__x86_64__',
    ]
    if ctx.attr.core:
        flags.extend([
            '-target',
            'bpf',
            '-DCOMPILE_CORE',
            '-g',
        ])
    else:
        flags.extend([
            '-DCONFIG_64BIT',
            '-DCOMPILE_PREBUILT',
        ])
    flags.extend(
        [
            '-D__KERNEL__',
            '-D__BPF_TRACING__',
            '-DKBUILD_MODNAME="ddsysprobe"',
        ]
    )
    # if arch is not None:
    #     if arch.kernel_arch is None:
    #         raise Exit(f"eBPF architecture not supported for {arch}")
    #     flags.append(f"-D__TARGET_ARCH_{arch.kernel_arch}")
    #     flags.append(f"-D__{arch.gcc_arch.replace('-', '_')}__")

    # if unit_test:
    #     flags.extend(['-D__BALOUM__'])
    flags.extend(
        [
            '-Wno-unused-value',
            '-Wno-pointer-sign',
            '-Wno-compare-distinct-pointer-types',
            '-Wunused',
            '-Wall',
            # '-Werror',
        ]
    )
    flags.extend(["-O2"])
    if not ctx.attr.core:
        flags.extend(["-include", "pkg/ebpf/c/asm_goto_workaround.h"])
    flags.extend(
        [
            # Some linux distributions enable stack protector by default which is not available on eBPF
            '-fno-stack-protector',
            '-fno-color-diagnostics',
            '-fno-unwind-tables',
            '-fno-asynchronous-unwind-tables',
            '-fno-jump-tables',
            '-fmerge-all-constants',
        ]
    )
    if debug:
        flags.extend(['-DDEBUG=1'])
    return flags

def _ebpf_replace_extension(file, new_ext):
    extension = file.extension
    return file.basename.removesuffix(extension) + new_ext

def _ebpf_linux_kernel_include_dirs(header_files):
    linux_headers_root = header_files[0].dirname

    kernel_folders = ["/usr/src/linux-headers-5.10.0-0.deb10.30-amd64", "/usr/src/linux-headers-5.10.0-0.deb10.30-common/"]
    # kernel_folders = ["/usr/src/linux-headers-5.15.0-47", "/usr/src/linux-headers-5.15.0-47-generic/"]
    subdirs = [
        "include",
        "include/uapi",
        "include/generated/uapi",
        "arch/x86/include",
        "arch/x86/include/uapi",
        "arch/x86/include/generated",
        "arch/x86/include/generated/uapi",
    ]
    linux_headers_dirs = []
    for kf in kernel_folders:
        linux_headers_dirs += [linux_headers_root + "/" + kf + "/" + d for d in subdirs]
    return linux_headers_dirs

def _ebpf_build_bytecode(ctx, file, extra_deps, deps_include_dirs):
    bc_file_name = ctx.label.name + ".bc"
    bc_file = ctx.actions.declare_file(bc_file_name)

    flags = _ebpf_compile_flags(ctx)
    flags.extend(ctx.attr.extra_flags)

    if ctx.attr.core:
        # The existing build system doesn't pass the kernel headers when building in CORE mode
        linux_headers_files = []
        linux_headers_dirs = []
    else:
        linux_headers_files = ctx.files._linux_headers
        linux_headers_dirs = _ebpf_linux_kernel_include_dirs(linux_headers_files)

    args = ctx.actions.args()
    # args.add("-v")
    args.add_all(deps_include_dirs, before_each="-I")
    args.add_all(flags)
    args.add_all(linux_headers_dirs, before_each="-isystem")
    args.add_all(["-c", file.short_path])
    args.add_all(["-o", bc_file])

    # name="ebpfcoreclang",
    # command=f"{compiler} -MD -MF $out.d -target bpf $ebpfcoreflags $flags -c $in -o $out",
    ctx.actions.run(
        inputs = [file] + extra_deps + linux_headers_files,
        outputs = [bc_file],
        arguments = [args],
        # executable = "clang",
        executable = ctx.file._clang,
        # use_default_shell_env = True,
    )
    return bc_file

def _ebpf_build_object(ctx, bc_file):
    """
    Compile an EBPF bytecode object to an actual object file
    This step is common for all EBPF programs, regardless of the CO-RE mode
    """
    obj_file = ctx.actions.declare_file(_ebpf_replace_extension(bc_file, "o.tmp"))
    stripped_obj_file = ctx.actions.declare_file(_ebpf_replace_extension(bc_file, "o"))
    # llc -march=bpf -filetype=obj -o pkg/ebpf/bytecode/build/x86_64/co-re/conntrack.o pkg/ebpf/bytecode/build/x86_64/co-re/conntrack.bc && llvm-strip -g pkg/ebpf/bytecode/build/x86_64/co-re/conntrack.o
    args = ctx.actions.args()
    args.add_all(["-march=bpf", "-filetype=obj"])
    args.add_all(["-o", obj_file])
    args.add(bc_file)
    ctx.actions.run(
        inputs = [bc_file],
        outputs = [obj_file],
        arguments = [args],
        executable = ctx.file._llc,
    )
    strip_args = ctx.actions.args()
    strip_args.add_all(["--strip-debug", obj_file, "-o", stripped_obj_file])
    ctx.actions.run(
        inputs = [obj_file],
        outputs = [stripped_obj_file],
        arguments = [strip_args],
        executable = ctx.file._llvm_strip,
    )
    return stripped_obj_file

def _ebpf_prog_impl(ctx):
    header_deps, include_dirs = expand_header_deps(ctx.attr.deps)

    bc_file = _ebpf_build_bytecode(ctx, ctx.file.src, header_deps, include_dirs)
    obj_file = _ebpf_build_object(ctx, bc_file)

    return [
        DefaultInfo(files = depset([obj_file])),
        EbpfProgram(
            # transitive = [depset([bc_file])],
            deps = header_deps,
        ),
    ]

ebpf_prog = rule(
    implementation = _ebpf_prog_impl,
    attrs = {
        "src": attr.label(allow_single_file = [".c"]),
        "deps": attr.label_list(
            providers=[CcInfo],
            doc="A list of cc_library target listing all headers needed for EBPF compilation"
        ),
        "debug": attr.bool(
            doc="Should debug code be included",
        ),
        # FIXME: add a strip flag
        "core": attr.bool(
            default = False,
            doc="Should CO-RE mode be enabled",
        ),
        "extra_flags": attr.string_list(),
        "_clang": attr.label(default = "@ebpf_clang//:bin/clang", allow_single_file=True),
        "_llc": attr.label(default = "@ebpf_clang//:bin/llc", allow_single_file=True),
        "_llvm_strip": attr.label(default = "@ebpf_clang//:bin/llvm-strip", allow_single_file=True),
        "_linux_headers": attr.label(default = "@linux_headers//:all", allow_files = True),
        # "_linux_headers": attr.label(default = "//deps/linux-headers", providers=[CcInfo]),
    },
)
