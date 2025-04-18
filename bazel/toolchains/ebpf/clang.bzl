load("@bazel_tools//tools/build_defs/repo:cache.bzl", "get_default_canonical_id")

def _ebpf_clang_impl(rctx):
    # clang_url = f"https://dd-agent-omnibus.s3.amazonaws.com/llvm/clang-{CLANG_VERSION_RUNTIME}.{arch.name}"
    rctx.report_progress("Downloading EBPF compilers")
    url = "https://github.com/llvm/llvm-project/releases/download/llvmorg-{0}/clang+llvm-{0}-{1}-linux-gnu-ubuntu-16.04.tar.xz".format(rctx.attr.version, rctx.attr.arch)
    rctx.download_and_extract(
        url = url,
        sha256=rctx.attr.sha256,
        canonical_id = get_default_canonical_id(rctx, [url]),
        strip_prefix = "clang+llvm-{0}-{1}-linux-gnu-ubuntu-".format(rctx.attr.version, rctx.attr.arch),
    )
    rctx.file("BUILD.bazel", 'exports_files(["bin/clang"])')

# def _ebpf_custom_clang(rctx):
    # https://dd-agent-omnibus.s3.amazonaws.com/llvm/clang-12.0.1.amd64

ebpf_clang_repo = repository_rule(
    implementation = _ebpf_clang_impl,
    attrs = {
        "version": attr.string(default="12.0.1"),
        "arch": attr.string(),
        "sha256": attr.string(),
    }
)
