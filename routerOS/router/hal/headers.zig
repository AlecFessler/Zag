/// Network protocol header definitions.
/// Packed extern structs that overlay directly onto packet byte buffers.
/// All multi-byte fields are stored in network byte order (big-endian).
/// Use accessor methods (e.g. totalLen(), srcPort()) for host-order values.
pub const EthernetHeader = extern struct {
    dst_mac: [6]u8,
    src_mac: [6]u8,
    ether_type_raw: u16 align(1),

    pub const LEN: usize = 14;
    pub const IPv4: u16 = 0x0800;
    pub const IPv6: u16 = 0x86DD;
    pub const ARP: u16 = 0x0806;

    pub fn etherType(self: *const @This()) u16 {
        return toHost16(self.ether_type_raw);
    }

    pub fn setEtherType(self: *@This(), val: u16) void {
        self.ether_type_raw = fromHost16(val);
    }

    pub fn parse(buf: []const u8) ?*const @This() {
        if (buf.len < LEN) return null;
        return @ptrCast(buf.ptr);
    }

    pub fn parseMut(buf: []u8) ?*@This() {
        if (buf.len < LEN) return null;
        return @ptrCast(buf.ptr);
    }

    comptime {
        if (@sizeOf(EthernetHeader) != 14) unreachable;
    }
};

pub const ArpHeader = extern struct {
    hw_type_raw: u16 align(1),
    proto_type_raw: u16 align(1),
    hw_len: u8,
    proto_len: u8,
    opcode_raw: u16 align(1),
    sender_mac: [6]u8,
    sender_ip: [4]u8,
    target_mac: [6]u8,
    target_ip: [4]u8,

    pub const LEN: usize = 28;
    pub const OP_REQUEST: u16 = 1;
    pub const OP_REPLY: u16 = 2;

    pub fn opcode(self: *const @This()) u16 {
        return toHost16(self.opcode_raw);
    }

    pub fn setOpcode(self: *@This(), val: u16) void {
        self.opcode_raw = fromHost16(val);
    }

    pub fn hwType(self: *const @This()) u16 {
        return toHost16(self.hw_type_raw);
    }

    pub fn protoType(self: *const @This()) u16 {
        return toHost16(self.proto_type_raw);
    }

    pub fn parse(buf: []const u8) ?*const @This() {
        if (buf.len < LEN) return null;
        return @ptrCast(buf.ptr);
    }

    pub fn parseMut(buf: []u8) ?*@This() {
        if (buf.len < LEN) return null;
        return @ptrCast(buf.ptr);
    }

    comptime {
        if (@sizeOf(ArpHeader) != 28) unreachable;
    }
};

pub const Ipv4Header = extern struct {
    ver_ihl: u8,
    tos: u8,
    total_len_raw: u16 align(1),
    identification_raw: u16 align(1),
    flags_frag_raw: u16 align(1),
    ttl: u8,
    protocol: u8,
    checksum_raw: u16 align(1),
    src_ip: [4]u8,
    dst_ip: [4]u8,

    pub const MIN_LEN: usize = 20;
    pub const PROTO_ICMP: u8 = 1;
    pub const PROTO_TCP: u8 = 6;
    pub const PROTO_UDP: u8 = 17;

    pub fn ihl(self: *const @This()) u4 {
        return @truncate(self.ver_ihl & 0x0F);
    }

    pub fn headerLen(self: *const @This()) u16 {
        return @as(u16, self.ihl()) * 4;
    }

    pub fn totalLen(self: *const @This()) u16 {
        return toHost16(self.total_len_raw);
    }

    pub fn setTotalLen(self: *@This(), val: u16) void {
        self.total_len_raw = fromHost16(val);
    }

    pub fn identification(self: *const @This()) u16 {
        return toHost16(self.identification_raw);
    }

    pub fn setIdentification(self: *@This(), val: u16) void {
        self.identification_raw = fromHost16(val);
    }

    pub fn zeroChecksum(self: *@This()) void {
        self.checksum_raw = 0;
    }

    pub fn setChecksum(self: *@This(), val: u16) void {
        self.checksum_raw = fromHost16(val);
    }

    /// Compute and set the IP header checksum.
    /// `pkt` must be the full packet starting at the Ethernet header.
    pub fn computeAndSetChecksum(self: *@This(), pkt: []u8) void {
        self.checksum_raw = 0;
        const hdr_len = self.headerLen();
        const cs = computeChecksum(pkt[EthernetHeader.LEN..][0..hdr_len]);
        self.checksum_raw = fromHost16(cs);
    }

    pub fn parse(buf: []const u8) ?*const @This() {
        if (buf.len < MIN_LEN) return null;
        return @ptrCast(buf.ptr);
    }

    pub fn parseMut(buf: []u8) ?*@This() {
        if (buf.len < MIN_LEN) return null;
        return @ptrCast(buf.ptr);
    }

    comptime {
        if (@sizeOf(Ipv4Header) != 20) unreachable;
        if (@offsetOf(Ipv4Header, "protocol") != 9) unreachable;
        if (@offsetOf(Ipv4Header, "src_ip") != 12) unreachable;
        if (@offsetOf(Ipv4Header, "dst_ip") != 16) unreachable;
    }
};

pub const Ipv6Header = extern struct {
    ver_tc_fl: [4]u8,
    payload_len_raw: u16 align(1),
    next_header: u8,
    hop_limit: u8,
    src_ip: [16]u8,
    dst_ip: [16]u8,

    pub const LEN: usize = 40;

    pub fn payloadLen(self: *const @This()) u16 {
        return toHost16(self.payload_len_raw);
    }

    pub fn setPayloadLen(self: *@This(), val: u16) void {
        self.payload_len_raw = fromHost16(val);
    }

    pub fn parse(buf: []const u8) ?*const @This() {
        if (buf.len < LEN) return null;
        return @ptrCast(buf.ptr);
    }

    pub fn parseMut(buf: []u8) ?*@This() {
        if (buf.len < LEN) return null;
        return @ptrCast(buf.ptr);
    }

    comptime {
        if (@sizeOf(Ipv6Header) != 40) unreachable;
        if (@offsetOf(Ipv6Header, "next_header") != 6) unreachable;
        if (@offsetOf(Ipv6Header, "hop_limit") != 7) unreachable;
        if (@offsetOf(Ipv6Header, "src_ip") != 8) unreachable;
        if (@offsetOf(Ipv6Header, "dst_ip") != 24) unreachable;
    }
};

pub const TcpHeader = extern struct {
    src_port_raw: u16 align(1),
    dst_port_raw: u16 align(1),
    seq_raw: u32 align(1),
    ack_raw: u32 align(1),
    data_off_rsvd: u8,
    flags: u8,
    window_raw: u16 align(1),
    checksum_raw: u16 align(1),
    urgent_raw: u16 align(1),

    pub const MIN_LEN: usize = 20;

    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;

    pub fn srcPort(self: *const @This()) u16 {
        return toHost16(self.src_port_raw);
    }

    pub fn setSrcPort(self: *@This(), val: u16) void {
        self.src_port_raw = fromHost16(val);
    }

    pub fn dstPort(self: *const @This()) u16 {
        return toHost16(self.dst_port_raw);
    }

    pub fn setDstPort(self: *@This(), val: u16) void {
        self.dst_port_raw = fromHost16(val);
    }

    pub fn seq(self: *const @This()) u32 {
        return toHost32(self.seq_raw);
    }

    pub fn setSeq(self: *@This(), val: u32) void {
        self.seq_raw = fromHost32(val);
    }

    pub fn ack(self: *const @This()) u32 {
        return toHost32(self.ack_raw);
    }

    pub fn setAck(self: *@This(), val: u32) void {
        self.ack_raw = fromHost32(val);
    }

    pub fn dataOffset(self: *const @This()) u16 {
        return @as(u16, self.data_off_rsvd >> 4) * 4;
    }

    pub fn isSyn(self: *const @This()) bool {
        return self.flags & SYN != 0;
    }

    pub fn isAck(self: *const @This()) bool {
        return self.flags & ACK != 0;
    }

    pub fn isFin(self: *const @This()) bool {
        return self.flags & FIN != 0;
    }

    pub fn isRst(self: *const @This()) bool {
        return self.flags & RST != 0;
    }

    pub fn setWindow(self: *@This(), val: u16) void {
        self.window_raw = fromHost16(val);
    }

    pub fn parse(buf: []const u8) ?*const @This() {
        if (buf.len < MIN_LEN) return null;
        return @ptrCast(buf.ptr);
    }

    pub fn parseMut(buf: []u8) ?*@This() {
        if (buf.len < MIN_LEN) return null;
        return @ptrCast(buf.ptr);
    }

    comptime {
        if (@sizeOf(TcpHeader) != 20) unreachable;
        if (@offsetOf(TcpHeader, "flags") != 13) unreachable;
    }
};

pub const UdpHeader = extern struct {
    src_port_raw: u16 align(1),
    dst_port_raw: u16 align(1),
    length_raw: u16 align(1),
    checksum_raw: u16 align(1),

    pub const LEN: usize = 8;

    pub fn srcPort(self: *const @This()) u16 {
        return toHost16(self.src_port_raw);
    }

    pub fn setSrcPort(self: *@This(), val: u16) void {
        self.src_port_raw = fromHost16(val);
    }

    pub fn dstPort(self: *const @This()) u16 {
        return toHost16(self.dst_port_raw);
    }

    pub fn setDstPort(self: *@This(), val: u16) void {
        self.dst_port_raw = fromHost16(val);
    }

    pub fn length(self: *const @This()) u16 {
        return toHost16(self.length_raw);
    }

    pub fn setLength(self: *@This(), val: u16) void {
        self.length_raw = fromHost16(val);
    }

    pub fn zeroChecksum(self: *@This()) void {
        self.checksum_raw = 0;
    }

    pub fn parse(buf: []const u8) ?*const @This() {
        if (buf.len < LEN) return null;
        return @ptrCast(buf.ptr);
    }

    pub fn parseMut(buf: []u8) ?*@This() {
        if (buf.len < LEN) return null;
        return @ptrCast(buf.ptr);
    }

    comptime {
        if (@sizeOf(UdpHeader) != 8) unreachable;
    }
};

pub const IcmpHeader = extern struct {
    icmp_type: u8,
    code: u8,
    checksum_raw: u16 align(1),
    id_raw: u16 align(1),
    seq_raw: u16 align(1),

    pub const LEN: usize = 8;
    pub const TYPE_ECHO_REPLY: u8 = 0;
    pub const TYPE_ECHO_REQUEST: u8 = 8;
    pub const TYPE_TIME_EXCEEDED: u8 = 11;

    pub fn id(self: *const @This()) u16 {
        return toHost16(self.id_raw);
    }

    pub fn setId(self: *@This(), val: u16) void {
        self.id_raw = fromHost16(val);
    }

    pub fn sequence(self: *const @This()) u16 {
        return toHost16(self.seq_raw);
    }

    pub fn setSeq(self: *@This(), val: u16) void {
        self.seq_raw = fromHost16(val);
    }

    pub fn zeroChecksum(self: *@This()) void {
        self.checksum_raw = 0;
    }

    pub fn setChecksum(self: *@This(), val: u16) void {
        self.checksum_raw = fromHost16(val);
    }

    /// Compute and set the ICMP checksum over the given data slice.
    pub fn computeAndSetChecksum(self: *@This(), icmp_data: []u8) void {
        self.checksum_raw = 0;
        const cs = computeChecksum(icmp_data);
        self.checksum_raw = fromHost16(cs);
    }

    pub fn parse(buf: []const u8) ?*const @This() {
        if (buf.len < LEN) return null;
        return @ptrCast(buf.ptr);
    }

    pub fn parseMut(buf: []u8) ?*@This() {
        if (buf.len < LEN) return null;
        return @ptrCast(buf.ptr);
    }

    comptime {
        if (@sizeOf(IcmpHeader) != 8) unreachable;
    }
};

pub const Icmpv6Header = extern struct {
    icmp_type: u8,
    code: u8,
    checksum_raw: u16 align(1),

    pub const LEN: usize = 4;
    pub const TYPE_ECHO_REQUEST: u8 = 128;
    pub const TYPE_ECHO_REPLY: u8 = 129;
    pub const TYPE_NS: u8 = 135;
    pub const TYPE_NA: u8 = 136;
    pub const TYPE_RS: u8 = 133;
    pub const TYPE_RA: u8 = 134;

    pub fn setChecksum(self: *@This(), val: u16) void {
        self.checksum_raw = fromHost16(val);
    }

    pub fn zeroChecksum(self: *@This()) void {
        self.checksum_raw = 0;
    }

    pub fn parse(buf: []const u8) ?*const @This() {
        if (buf.len < LEN) return null;
        return @ptrCast(buf.ptr);
    }

    pub fn parseMut(buf: []u8) ?*@This() {
        if (buf.len < LEN) return null;
        return @ptrCast(buf.ptr);
    }

    comptime {
        if (@sizeOf(Icmpv6Header) != 4) unreachable;
    }
};

// ── Endianness helpers ──────────────────────────────────────────────────

fn toHost16(val: u16) u16 {
    const bytes: [2]u8 = @bitCast(val);
    return @as(u16, bytes[0]) << 8 | bytes[1];
}

fn fromHost16(val: u16) u16 {
    return toHost16(val); // symmetric for byte-swap
}

fn toHost32(val: u32) u32 {
    const bytes: [4]u8 = @bitCast(val);
    return @as(u32, bytes[0]) << 24 | @as(u32, bytes[1]) << 16 | @as(u32, bytes[2]) << 8 | bytes[3];
}

fn fromHost32(val: u32) u32 {
    return toHost32(val);
}

/// RFC 1071 one's complement checksum.
fn computeChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += @as(u32, data[i]) << 8 | data[i + 1];
    }
    if (i < data.len) sum += @as(u32, data[i]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return @truncate(~sum);
}
