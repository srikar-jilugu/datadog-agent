def _linux_header_impl(rctx):
    rctx.download_and_extract(
        "https://security.debian.org/debian-security/pool/updates/main/l/linux-5.10/linux-headers-5.10.0-0.deb10.30-amd64_5.10.218-1~deb10u1_amd64.deb",
        output = "intermediate",
    )
    rctx.extract(
        "intermediate/data.tar.xz",
    )
    rctx.delete("intermediate")

    rctx.download_and_extract(
        "https://security.debian.org/debian-security/pool/updates/main/l/linux-5.10/linux-headers-5.10.0-0.deb10.30-common_5.10.218-1~deb10u1_all.deb",
        output = "intermediate",
    )
    rctx.extract(
        "intermediate/data.tar.xz",
    )
    rctx.delete("intermediate")


    rctx.delete("Makefile")
    rctx.delete("scripts")
    rctx.delete("tools")
    rctx.file("BUILD", """filegroup(name = "all", srcs = glob(["**"]), visibility = ["//visibility:public"])""")

linux_headers = repository_rule(
    implementation = _linux_header_impl,
)
