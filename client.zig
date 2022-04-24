const std = @import("std");
const Packet = @import("packet.zig").Packet;
const X25519 = std.crypto.dh.X25519;
const Chacha20 = std.crypto.stream.chacha.ChaCha20IETF;

const ClientState = struct {
    peer_name: ?[]const u8 = null,
    allocator: std.mem.Allocator,
    key_pair: ?X25519.KeyPair = null,
    shared_key: ?[X25519.shared_length]u8 = null,
    msg_idx: u64 = 0,

    pub fn deinit(state: ClientState) void {
        if(state.peer_name) |name| state.allocator.free(name);
    }
};

fn readThread(stream: std.net.Stream, stdout: std.fs.File.Writer, state: *ClientState, shutdown_semaphore: *std.Thread.Semaphore) void {
    const reader = stream.reader();
    while(true) {
        const packet = Packet.deserialize(reader, state.allocator) catch return;
        defer packet.free(state.allocator);
        switch(packet) {
            .Connect => |name| {
                stdout.print("{s} has connected\n", .{name}) catch return;
                state.peer_name = state.allocator.dupe(u8, name) catch return;
            },
            .Disconnect => {
                const name = @as([]const u8, state.peer_name orelse "Peer");
                stdout.print("{s} has disconnected\n", .{name}) catch return;
                shutdown_semaphore.post();
            },
            .Message => |message| {
                const name = @as([]const u8, state.peer_name orelse "Peer");
                stdout.print("{s}: {s}\n", .{name, message}) catch return;
            },
            .SetName => |new_name| {
                const name = @as([]const u8, state.peer_name orelse "Peer");
                stdout.print("{s} changed their name to {s}\n", .{name, new_name}) catch return;
                if(state.peer_name) |old_name| {
                    state.allocator.free(old_name);
                }
                state.peer_name = state.allocator.dupe(u8, new_name) catch return;
            },
            .Broadcast => |message| {
                stdout.print("BROADCAST: {s}\n", .{message}) catch return;
            },
            .KeyExchg => |public_key| {
                const name = @as([]const u8, state.peer_name orelse "Peer");
                std.log.info("{s} has requested key exchange", .{name});
                if(state.key_pair == null) {
                    state.key_pair = X25519.KeyPair.create(null) catch return;
                    Packet.serialize(Packet{ .KeyExchg = state.key_pair.?.public_key }, stream.writer()) catch return;
                }
                state.shared_key = X25519.scalarmult(state.key_pair.?.secret_key, public_key) catch unreachable;
            },
            .EncryptedMsg => |message| {
                const name = @as([]const u8, state.peer_name orelse "Peer");
                var decrypted = state.allocator.alloc(u8, message.data.len) catch return;
                defer state.allocator.free(decrypted);
                Chacha20.xor(decrypted, message.data, 1, state.shared_key.?, message.nonce);
                stdout.print("{s}: {s}\n", .{name, decrypted}) catch return;
            }
        }
    }
}

fn writeThread(stream: std.net.Stream, stdin: std.fs.File.Reader, state: *ClientState) void {
    const writer = stream.writer();
    var buffer: [65536]u8 = undefined;
    while(true) {
        const in = stdin.readUntilDelimiter(buffer[0..], '\n') catch return;
        if(in.len >= 2 and in[0] == '\\') {
            //Command
            switch(in[1]) {
                'e' => {
                    if(state.key_pair != null) {
                        std.log.info("Already exchanging keys", .{});
                    } else {
                        //Begin key exchange
                        state.key_pair = X25519.KeyPair.create(null) catch return;
                        Packet.serialize(Packet{ .KeyExchg = state.key_pair.?.public_key }, writer) catch return;
                    }
                },
                'n' => {
                    //Change username
                    if(in[2] != ' ' or in.len < 4) {
                        std.log.err("Usage: \\n <name>", .{});
                        continue;
                    }
                    const name = in[3..];
                    if(name.len > 16) {
                        std.log.err("Name must be less that 16 characters", .{});
                        continue;
                    }
                    Packet.serialize(Packet{ .SetName = name }, writer) catch return;
                },
                else => {
                    std.log.err("Unrecognized command {c}", .{in[1]});
                }
            }
        } else {
            //Message
            if(state.shared_key) |shared_key| {
                var nonce: [Chacha20.nonce_length]u8 = undefined;
                std.mem.writeIntSliceBig(u64, nonce[4..], state.msg_idx);
                state.msg_idx += 1;
                std.crypto.random.bytes(nonce[0..4]);
                var encrypted = state.allocator.alloc(u8, in.len) catch return;
                defer state.allocator.free(encrypted);
                Chacha20.xor(encrypted, in, 1, shared_key, nonce);
                Packet.serialize(Packet{ .EncryptedMsg = .{ .nonce = nonce, .data = encrypted }}, writer) catch return;
            } else {
                Packet.serialize(Packet{ .Message = in }, writer) catch return;
            }
        }
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();
    var stdin = std.io.getStdIn();
    var stdout = std.io.getStdOut();

    var args_iter = std.process.args();
    std.debug.assert(args_iter.skip()); //Skip executable path
    const name = try (args_iter.next(allocator) orelse {
        std.log.err("Please provide a name.", .{});
        std.process.exit(1);
    });
    defer allocator.free(name);

    const stream = try std.net.tcpConnectToAddress(std.net.Address.parseIp4("127.0.0.1", 43302) catch unreachable);
    defer stream.close();

    try Packet.serialize(Packet{ .Connect = name }, stream.writer());

    var shutdown_semaphore = std.Thread.Semaphore{};
    var state: ClientState = .{
        .allocator = allocator
    };
    defer state.deinit();

    var read_thread = try std.Thread.spawn(.{}, readThread, .{stream, stdout.writer(), &state, &shutdown_semaphore});
    _ = read_thread;
    var write_thread = try std.Thread.spawn(.{}, writeThread, .{stream, stdin.reader(), &state});
    _ = write_thread;

    shutdown_semaphore.wait();
}