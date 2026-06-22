load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "fuse_host",
    srcs = ["fuse_host.go"],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
