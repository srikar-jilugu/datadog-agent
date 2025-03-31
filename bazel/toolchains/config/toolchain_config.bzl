# Defines the C++ settings that tell Bazel precisely how to construct C++
# commands. This is unique to C++ toolchains: other languages don't require
# anything like this.
#
# See
# https://bazel.build/docs/cc-toolchain-config-reference
# for all the gory details.
#
# This file is more about C++-specific toolchain configuration than how to
# declare toolchains and match them to platforms. It's important if you want to
# write your own custom C++ toolchains. But if you want to write toolchains for
# other languages or figure out how to select toolchains for custom CPU types,
# OSes, etc., the BUILD file is much more interesting.

load(
    "@bazel_tools//tools/cpp:cc_toolchain_config_lib.bzl",
    "artifact_name_pattern",
    "tool_path",
)

def _impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.write(out, "executable")

    GCC_VERSION = ctx.attr.gcc_version
    TOOLCHAIN_ARCH = ctx.attr.arch
    TOOLCHAIN_PATH = ctx.attr.path

    return [
        cc_common.create_cc_toolchain_config_info(
            ctx = ctx,
            toolchain_identifier = "glibc-toolchain",
            host_system_name = "nothing",
            target_system_name = "nothing",
            target_cpu = TOOLCHAIN_ARCH,
            target_libc = "nothing",
            cc_target_os = "linux",
            compiler = "gcc",
            abi_version = "gcc-" + GCC_VERSION,
            abi_libc_version = "nothing",
            tool_paths = [
                tool_path(
                    name = "ar",
                    path = TOOLCHAIN_PATH + "/bin/ar",
                ),
                tool_path(
                    name = "cpp",
                    path = TOOLCHAIN_PATH + "/bin/cpp",
                ),
                tool_path(
                    name = "gcc",
                    path = TOOLCHAIN_PATH + "/bin/g++",
                ),
                tool_path(
                    name = "gcov",
                    path = TOOLCHAIN_PATH + "/bin/gcov",
                ),
                tool_path(
                    name = "ld",
                    path = TOOLCHAIN_PATH + "/bin/ld",
                ),
                tool_path(
                    name = "nm",
                    path = TOOLCHAIN_PATH + "/bin/nm",
                ),
                tool_path(
                    name = "objdump",
                    path = TOOLCHAIN_PATH + "/bin/objdump",
                ),
                tool_path(
                    name = "strip",
                    path = TOOLCHAIN_PATH + "/bin/strip",
                ),
            ],
            cxx_builtin_include_directories = [
                TOOLCHAIN_PATH + "/include",
                TOOLCHAIN_PATH + "/lib/gcc/" + TOOLCHAIN_ARCH + "-unknown-linux-gnu/" + GCC_VERSION + "/include-fixed",
                TOOLCHAIN_PATH + "/lib/gcc/" + TOOLCHAIN_ARCH + "-unknown-linux-gnu/" + GCC_VERSION + "/include",
                TOOLCHAIN_PATH + "/lib/gcc/" + TOOLCHAIN_ARCH + "-unknown-linux-gnu/" + GCC_VERSION + "/install-tools/include",
                TOOLCHAIN_PATH + "/" + TOOLCHAIN_ARCH + "-unknown-linux-gnu/include",
            ],
        ),
        DefaultInfo(
            executable = out,
        ),
    ]

glibc_cc_toolchain_config = rule(
    implementation = _impl,
    provides = [CcToolchainConfigInfo],
    executable = True,
    attrs = {
        "arch": attr.string(mandatory=True),
        "gcc_version": attr.string(mandatory=True),
        "path": attr.string(mandatory=True),
    },
)
