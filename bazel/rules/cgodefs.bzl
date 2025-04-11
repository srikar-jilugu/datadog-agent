# Rule to generate cgo defs files

CgoGodefsProvider = provider(
    "Forward files needed to generate a godefs file to bazel",
    fields = {
        "deps": "A list of cc_library target containing the required headers",
        "headers": "depset of additional required headers",
    }
)

def _cgo_godefs_impl(ctx):
    in_file = ctx.files.src[0]
    # Compute the output file name with the platform name appended
    extension = in_file.extension
    out_file_path = in_file.short_path.removesuffix("." + extension)
    out_file_path = out_file_path + "_" + ctx.attr.target_platform + "." + extension
    out_file = ctx.actions.declare_file(out_file_path)

    include_dirs = ["-I " + path.dirname for path in ctx.files.headers]

    deps = [dep[CcInfo] for dep in ctx.attr.deps]
    # Temporary set to ensure we're not passing the same "-I folder" 15 times
    header_dirs = set([
        h.dirname
        for d in deps
            for h in d.compilation_context.direct_headers
    ])
    include_dirs += ["-I " + h for h in header_dirs]

    ctx.actions.run_shell(
        outputs = [out_file],
        inputs = [in_file] + ctx.files.headers + [h for d in deps for h in d.compilation_context.direct_headers],
        command = "%s tool cgo -godefs -- %s -fsigned-char %s > %s" % (
            # This doesn't work as expected:
            # Error in fail: //go is only meant to be used with 'bazel run', not as a tool.
            # If you need to use it as a tool (e.g. in a genrule), please open an issue at
            # https://github.com/bazelbuild/rules_go/issues/new explaining your use case.
            # For now let's just use the system wide go.
            # ctx.attr._go,
            "go",
            " ".join(include_dirs),
            in_file.path,
            out_file.path
        ),
        # FIXME: THis should be false, but we currently need the system's go
        use_default_shell_env = True,
    )

    headers_deps = [depset([h]) for h in ctx.files.headers]

    return [
        DefaultInfo(files = depset([out_file])),
        CgoGodefsProvider(
            headers = headers_deps,
            deps = deps,
        )
    ]

cgo_godefs = rule(
    implementation = _cgo_godefs_impl,
    attrs = {
        "src": attr.label(
            allow_single_file = [".go"],
            doc = "A single input file to generate godefs from",
            mandatory = True,
        ),
        "deps": attr.label_list(providers=[CcInfo]),
        "target_platform": attr.string(),
        "headers": attr.label_list(allow_files = True),
        "_go": attr.label(
            # default = Label("@rules_go//go"),
            allow_single_file = True,
            executable = True,
            cfg = "exec",
        ),
    },
    provides = [CgoGodefsProvider],
)
