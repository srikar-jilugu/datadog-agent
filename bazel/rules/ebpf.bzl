load("//:bazel/private/utils.bzl", "expand_header_deps")

EbpfProgram = provider(
    "Describe an EBPF program along with its dependencies",
    fields = {
        "deps": "A list of cc_library target containing the required headers",
    }
)

def _ebpf_compile_flags():
    flags = []
    flags.extend(
        [
            '-D__KERNEL__',
            '-DCONFIG_64BIT',
            '-D__BPF_TRACING__',
            '-DKBUILD_MODNAME="ddsysprobe"',
            '-DCOMPILE_PREBUILT',
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
            '-Werror',
        ]
    )
    flags.extend(["-include", "pkg/ebpf/c/asm_goto_workaround.h"])
    flags.extend(["-O2"])
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
    return flags

def _ebpf_prog_impl(ctx):
    ebpf_core_flags = []
    flags = _ebpf_compile_flags()

    header_deps, include_dirs = expand_header_deps(ctx.attr.deps)

    linux_headers_info = ctx.attr._linux_headers
    print(linux_headers_info)
    print(linux_headers_info[OutputGroupInfo])
    linux_headers_files = ctx.files._linux_headers
    linux_headers_root = ctx.files._linux_headers[0].dirname

    subdirs = [
        # "include",
        # "include/uapi",
        # "include/x86_64-linux-gnu/",
        "include/generated/uapi",
        "src/linux-headers-4.9.0-9-amd64/arch/x86/include/",
        "src/linux-headers-4.9.0-9-amd64/arch/x86/include/generated/",
        "src/linux-headers-4.9.0-9-amd64/arch/x86/include/generated/uapi",
        "src/linux-headers-4.9.0-9-common/include/",
        "src/linux-headers-4.9.0-9-common/arch/x86/include/",
        "src/linux-headers-4.9.0-9-common/arch/x86/include/uapi/",
    ]
    linux_headers_dirs = [linux_headers_root + "/" + d for d in subdirs]

    for f in ctx.files.srcs:
        bc_file = ctx.actions.declare_file(f.basename + ".bc")
        out_file = ctx.actions.declare_file(f.basename + ".o")

        args = ctx.actions.args()
        args.add("-v")
        args.add_all(["-MD", "-MF", out_file.short_path, "-target", "bpf"])
        args.add_all(ebpf_core_flags)
        args.add_all(flags)
        args.add_all(include_dirs, before_each="-I")
        args.add_all(["-c", f.short_path])
        args.add_all(["-o", bc_file.short_path])
        args.add_all(linux_headers_dirs, before_each="-I")
        # args.add_all(linux_headers_info.system_includes, before_each="-isystem")
        # args.add("-I", linux_headers_info.headers.to_list()[0].short_path)

        # name="ebpfcoreclang",
        # command=f"{compiler} -MD -MF $out.d -target bpf $ebpfcoreflags $flags -c $in -o $out",
        ctx.actions.run(
            inputs = [f] + header_deps + linux_headers_files,
            outputs = [bc_file],
            arguments = [args],
            # executable = "clang",
            executable = ctx.file._clang,
            use_default_shell_env = True,
        )

        ctx.actions.run_shell(
            inputs = [bc_file],
            outputs = [out_file],
            command = "LOLNOPE",
        )
    return [
        DefaultInfo(files = depset(
            direct = [bc_file, out_file],
        )),
        EbpfProgram(
            # transitive = [depset([bc_file])],
            deps = header_deps,
        ),
    ]

ebpf_prog = rule(
    implementation = _ebpf_prog_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = [".c"]),
        "deps": attr.label_list(
            providers=[CcInfo],
            doc="A list of cc_library target listing all headers needed for EBPF compilation"
        ),
        "_clang": attr.label(default = "@ebpf_clang//:bin/clang", allow_single_file=True),
        "_linux_headers": attr.label(default = "@linux-headers//:all", allow_files = True),
        # "_linux_headers": attr.label(default = "//deps/linux-headers", providers=[CcInfo]),
    },
)
