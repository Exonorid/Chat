const std = @import("std");
const Packet = @import("packet.zig").Packet;

const Client = struct {
    name: ?[]const u8 = null,
    conn: *std.net.StreamServer.Connection,
    peer: *std.net.StreamServer.Connection,
    allocator: std.mem.Allocator,

    pub fn handler(self: *Client) void {
        const reader = self.conn.stream.reader();
        const writer = self.peer.stream.writer();
        var sent_packet = false;
        while(true) {
            const packet = Packet.deserialize(reader, self.allocator) catch |err| switch(err) {
                error.EndOfStream => {
                    std.log.info("{} has disconnected", .{self.conn.address});
                    Packet.serialize(.{ .Disconnect = {} }, writer) catch {};
                    return;
                },
                else => {
                    std.log.err("{s}", .{@errorName(err)});
                    Packet.serialize(.{ .Disconnect = {} }, writer) catch {};
                    return;
                }
            };
            defer packet.free(self.allocator);
            switch(packet) {
                .SetName => |new_name| {
                    if(self.name) |old_name| {
                        std.log.info("{s} changed their name to {s}", .{old_name, new_name});
                        self.allocator.free(old_name);
                    } else {
                        std.log.info("{} changed their name to {s}", .{self.conn.address, new_name});
                    }
                    self.name = self.allocator.dupe(u8, new_name) catch |err| {
                        std.log.err("{s}", .{@errorName(err)});
                        std.log.info("{} has disconnected", .{self.conn.address});
                        Packet.serialize(.{ .Disconnect = {} }, writer) catch {};
                        return;
                    };
                },
                .Message => |message| {
                    if(self.name) |name| {
                        std.log.info("Message from {s}: '{s}'", .{name, message});
                    } else {
                        std.log.info("Message from {}: '{s}'", .{self.conn.address, message});
                    }
                },
                .Connect => |name|{
                    if(sent_packet) {
                        std.log.err("Connect must be the first message sent.", .{});
                        std.log.info("{} has disconnected", .{self.conn.address});
                        Packet.serialize(.{ .Disconnect = {} }, writer) catch {};
                        std.log.info("{} has disconnected", .{self.peer.address});
                        Packet.serialize(.{ .Disconnect = {} }, self.conn.stream.writer()) catch {};
                        return;
                    }
                    self.name = self.allocator.dupe(u8, name) catch return;
                    std.log.info("{s} has connected", .{name});
                },
                .Disconnect => {
                    std.log.info("{} has disconnected", .{self.conn.address});
                    Packet.serialize(.{ .Disconnect = {} }, writer) catch {};
                    return;
                },
                .Broadcast => {
                    //Naughty client
                    std.log.err("Clients aren't allowed to broadcast lol", .{});
                    std.log.info("{} has disconnected", .{self.conn.address});
                    Packet.serialize(.{ .Disconnect = {} }, writer) catch {};
                    std.log.info("{} has disconnected", .{self.peer.address});
                    Packet.serialize(.{ .Disconnect = {} }, self.conn.stream.writer()) catch {};
                    return;
                },
                .KeyExchg => |key| {
                    std.log.info("{s}'s public key is {}", .{self.name.?, std.fmt.fmtSliceHexUpper(key[0..])});
                },
                .EncryptedMsg => {
                    std.log.info("{s}: [ENCRYPTED]", .{self.name.?});
                }
            }
            packet.serialize(writer) catch return;
            sent_packet = true;
        }
    }

    pub fn deinit(self: Client) void {
        if(self.name) |name| self.allocator.free(name);
    }
};

fn handleCmds(conn_a: *std.net.StreamServer.Connection, conn_b: *std.net.StreamServer.Connection, stdin: std.fs.File.Reader, shutdown_semaphore: *std.Thread.Semaphore) void {
    var cmd_buf: [65536]u8 = undefined;
    while(true) {
        const in = stdin.readUntilDelimiter(cmd_buf[0..], '\n') catch return;
        if(in[0] == '!') {
            Packet.serialize(Packet{ .Broadcast = in[1..] }, conn_a.stream.writer()) catch return;
            Packet.serialize(Packet{ .Broadcast = in[1..] }, conn_b.stream.writer()) catch return;
        } else if(in[0] == 'd') {
            std.log.info("Shutting down", .{});
            Packet.serialize(Packet{ .Disconnect = {} }, conn_a.stream.writer()) catch {};
            Packet.serialize(Packet{ .Disconnect = {} }, conn_b.stream.writer()) catch {};
            shutdown_semaphore.post();
            return;
        }
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{.thread_safe = true}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();
    var stdin = std.io.getStdIn();

    var server = std.net.StreamServer.init(.{});
    defer server.deinit();
    defer server.close();
    try server.listen(std.net.Address.parseIp4("127.0.0.1", 43302) catch unreachable);

    std.log.info("Waiting for clients...", .{});

    var conn_a: std.net.StreamServer.Connection = try server.accept();
    defer conn_a.stream.close();
    std.log.info("{} has connected", .{conn_a.address});

    var conn_b: std.net.StreamServer.Connection = try server.accept();
    defer conn_b.stream.close();
    std.log.info("{} has connected", .{conn_b.address});

    var shutdown_semaphore = std.Thread.Semaphore{};

    var client_a = Client{
        .conn = &conn_a,
        .peer = &conn_b,
        .allocator = allocator
    };
    defer client_a.deinit();
    var client_b = Client{
        .conn = &conn_b,
        .peer = &conn_a,
        .allocator = allocator
    };
    defer client_b.deinit();

    var thread_a = try std.Thread.spawn(.{}, Client.handler, .{&client_a});
    var thread_b = try std.Thread.spawn(.{}, Client.handler, .{&client_b});
    _ = thread_a;
    _ = thread_b;

    var cmd_thread = try std.Thread.spawn(.{}, handleCmds, .{&conn_a, &conn_b, stdin.reader(), &shutdown_semaphore});
    _ = cmd_thread;

    shutdown_semaphore.wait();
}