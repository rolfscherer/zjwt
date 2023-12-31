const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to sel.
    const optimize = b.standardOptimizeOption(.{});

    // lib
    const lib = b.addStaticLibrary(.{
        .name = "zjwt",
        .root_source_file = .{ .path = "src/zjwt.zig" },
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    // Example exe
    const example = b.addExecutable(.{
        .name = "example",
        .root_source_file = .{ .path = "example/src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    const zjwt_module = b.addModule("zjwt", .{
        .source_file = .{ .path = "src/zjwt.zig" },
    });

    example.addModule("zjwt", zjwt_module);

    b.installArtifact(example);
    const run_cmd = b.addRunArtifact(example);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Tests
    const main_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    const run_main_tests = b.addRunArtifact(main_tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
}
