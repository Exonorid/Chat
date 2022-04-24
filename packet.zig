const std = @import("std");
const X25519 = std.crypto.dh.X25519;
const Chacha20 = std.crypto.stream.chacha.ChaCha20IETF;

const PacketType = enum(u8) {
    Connect = 0,
    Disconnect = 1,
    Message = 2,
    SetName = 3,
    Broadcast = 4,
    KeyExchg = 5,
    EncryptedMsg = 6,
};

pub const Packet = union(PacketType) {
    Connect: []const u8,
    Disconnect: void,
    Message: []const u8,
    SetName: []const u8,
    Broadcast: []const u8,
    KeyExchg: [X25519.public_length]u8,
    EncryptedMsg: struct {
        nonce: [Chacha20.nonce_length]u8,
        data: []const u8,
    },

    pub fn serialize(packet: Packet, writer: anytype) !void {
        switch(packet) {
            .Connect => |name| {
                try writer.writeByte(@enumToInt(PacketType.Connect));
                if(name.len > 16) {
                    return error.DataTooLong;
                }
                try writer.writeIntBig(u8, @intCast(u8, name.len));
                try writer.writeAll(name);
            },
            .Disconnect => {
                try writer.writeByte(@enumToInt(PacketType.Disconnect));
            },
            .Message => |message| {
                try writer.writeByte(@enumToInt(PacketType.Message));
                if(message.len > std.math.maxInt(u16)) {
                    return error.DataTooLong;
                }
                try writer.writeIntBig(u16, @intCast(u16, message.len));
                try writer.writeAll(message);
            },
            .SetName => |name| {
                try writer.writeByte(@enumToInt(PacketType.SetName));
                if(name.len > 16) {
                    return error.DataTooLong;
                }
                try writer.writeIntBig(u8, @intCast(u8, name.len));
                try writer.writeAll(name);
            },
            .Broadcast => |message| {
                try writer.writeByte(@enumToInt(PacketType.Broadcast));
                if(message.len > std.math.maxInt(u16)) {
                    return error.DataTooLong;
                }
                try writer.writeIntBig(u16, @intCast(u16, message.len));
                try writer.writeAll(message);
            },
            .KeyExchg => |key| {
                try writer.writeByte(@enumToInt(PacketType.KeyExchg));
                try writer.writeAll(key[0..]);
            },
            .EncryptedMsg => |msg| {
                try writer.writeByte(@enumToInt(PacketType.EncryptedMsg));
                try writer.writeAll(msg.nonce[0..]);
                try writer.writeIntBig(u32, @intCast(u32, msg.data.len));
                try writer.writeAll(msg.data);
            }
        }
    }

    pub fn deserialize(reader: anytype, allocator: std.mem.Allocator) !Packet {
        switch(try reader.readEnum(PacketType, .Big)) {
            .Connect => {
                const name_len = try reader.readIntBig(u8);
                var name = try allocator.alloc(u8, name_len);
                errdefer allocator.free(name);
                std.debug.assert((try reader.readAll(name)) == name_len);
                return Packet{ .Connect = name };
            },
            .Disconnect => {
                return Packet{ .Disconnect = {} };
            },
            .Message => {
                const message_len = try reader.readIntBig(u16);
                var message = try allocator.alloc(u8, message_len);
                errdefer allocator.free(message);
                std.debug.assert((try reader.readAll(message)) == message_len);
                return Packet{ .Message = message };
            },
            .SetName => {
                const name_len = try reader.readIntBig(u8);
                var name = try allocator.alloc(u8, name_len);
                errdefer allocator.free(name);
                std.debug.assert((try reader.readAll(name)) == name_len);
                return Packet{ .SetName = name };
            },
            .Broadcast => {
                const message_len = try reader.readIntBig(u16);
                var message = try allocator.alloc(u8, message_len);
                errdefer allocator.free(message);
                std.debug.assert((try reader.readAll(message)) == message_len);
                return Packet{ .Broadcast = message };
            },
            .KeyExchg => {
                var public_key: [X25519.public_length]u8 = undefined;
                std.debug.assert((try reader.readAll(public_key[0..])) == X25519.public_length);
                return Packet{ .KeyExchg = public_key };
            },
            .EncryptedMsg => {
                const nonce = try reader.readBytesNoEof(Chacha20.nonce_length);
                const data_len = try reader.readIntBig(u32);
                var data = try allocator.alloc(u8, data_len);
                errdefer allocator.free(data);
                std.debug.assert((try reader.readAll(data)) == data_len);
                return Packet{ .EncryptedMsg = .{ .nonce = nonce, .data = data } };
            }
        }
    }

    pub fn free(packet: Packet, allocator: std.mem.Allocator) void {
        switch(packet) {
            .Message => |message| {
                allocator.free(message);
            },
            .SetName => |name| {
                allocator.free(name);
            },
            .Connect => |name| {
                allocator.free(name);
            },
            .Disconnect => {},
            .Broadcast => |message| {
                allocator.free(message);
            },
            .KeyExchg => {},
            .EncryptedMsg => |message| {
                allocator.free(message.data);
            }
        }
    }
};