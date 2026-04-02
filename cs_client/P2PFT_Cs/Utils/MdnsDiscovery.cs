using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace P2PFT_Cs
{
    /// <summary>
    /// Minimal mDNS/DNS-SD implementation for peer discovery.
    /// Advertises and browses for <c>_p2pshare._tcp.local.</c> services,
    /// compatible with the Python client's zeroconf-based discovery.
    ///
    /// Uses raw UDP sockets on the standard mDNS multicast group
    /// 224.0.0.251:5353. No NuGet dependencies required.
    /// </summary>
    internal sealed class MdnsDiscovery : IDisposable
    {
        // ── Constants ──────────────────────────────────────────────
        private static readonly IPAddress MdnsMulticast = IPAddress.Parse("224.0.0.251");
        private const int MdnsPort = 5353;
        private const string ServiceType = "_p2pshare._tcp.local.";
        private const int AnnounceIntervalMs = 5000;
        private const int PeerTimeoutMs = 30000;
        private const int DefaultTtl = 120;

        // DNS record types
        private const ushort TypeA = 1;
        private const ushort TypePTR = 12;
        private const ushort TypeTXT = 16;
        private const ushort TypeSRV = 33;

        // DNS classes
        private const ushort ClassIN = 1;
        private const ushort ClassFlush = 0x8001; // cache-flush flag

        // DNS flags
        private const ushort FlagResponse = 0x8400; // QR=1, AA=1

        // ── Identity ───────────────────────────────────────────────
        private readonly string _peerId;
        private readonly int _tcpPort;
        private readonly string _serviceName;   // "{peerId}._p2pshare._tcp.local."
        private readonly string _hostName;       // "{peerId}.local."

        // ── Threads / sockets ──────────────────────────────────────
        private Socket _socket;
        private Thread _receiveThread;
        private Thread _announceThread;
        private Thread _reapThread;
        private volatile bool _running;

        // ── Discovered peers ───────────────────────────────────────
        private readonly ConcurrentDictionary<string, PeerRecord> _peers =
            new ConcurrentDictionary<string, PeerRecord>();

        private class PeerRecord
        {
            public string Address;
            public int Port;
            public double LastSeen;
        }

        /// <summary>
        /// Raised when a new peer is discovered.
        /// Parameters: peerId, address, port.
        /// </summary>
        public event Action<string, string, int> PeerFound;

        /// <summary>
        /// Raised when a peer has not been seen within the timeout.
        /// </summary>
        public event Action<string> PeerLost;

        // ── Constructor ────────────────────────────────────────────
        public MdnsDiscovery(string peerId, int tcpPort)
        {
            _peerId = peerId;
            _tcpPort = tcpPort;
            _serviceName = peerId + "." + ServiceType;
            _hostName = peerId + ".local.";
        }

        // ── Start / Stop ───────────────────────────────────────────
        public void Start()
        {
            if (_running) return;
            _running = true;

            _socket = new Socket(AddressFamily.InterNetwork,
                                 SocketType.Dgram, ProtocolType.Udp);
            _socket.SetSocketOption(SocketOptionLevel.Socket,
                                    SocketOptionName.ReuseAddress, true);
            _socket.ExclusiveAddressUse = false;
            _socket.Bind(new IPEndPoint(IPAddress.Any, MdnsPort));

            // Join multicast group on all interfaces
            try
            {
                _socket.SetSocketOption(SocketOptionLevel.IP,
                    SocketOptionName.AddMembership,
                    new MulticastOption(MdnsMulticast, IPAddress.Any));
            }
            catch { /* may fail if already joined */ }

            // Also join on each specific interface for reliability
            try
            {
                foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (iface.OperationalStatus != OperationalStatus.Up) continue;
                    if (iface.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                    foreach (var addr in iface.GetIPProperties().UnicastAddresses)
                    {
                        if (addr.Address.AddressFamily != AddressFamily.InterNetwork)
                            continue;
                        try
                        {
                            _socket.SetSocketOption(SocketOptionLevel.IP,
                                SocketOptionName.AddMembership,
                                new MulticastOption(MdnsMulticast, addr.Address));
                        }
                        catch { }
                    }
                }
            }
            catch { }

            // Set multicast TTL
            _socket.SetSocketOption(SocketOptionLevel.IP,
                SocketOptionName.MulticastTimeToLive, 255);

            _receiveThread = new Thread(ReceiveLoop)
            { IsBackground = true, Name = "mDNS-Recv" };
            _receiveThread.Start();

            _announceThread = new Thread(AnnounceLoop)
            { IsBackground = true, Name = "mDNS-Announce" };
            _announceThread.Start();

            _reapThread = new Thread(ReapLoop)
            { IsBackground = true, Name = "mDNS-Reap" };
            _reapThread.Start();
        }

        public void Stop()
        {
            if (!_running) return;
            _running = false;

            // Send goodbye (TTL=0)
            try
            {
                byte[] goodbye = BuildAnnouncement(0);
                SendMulticast(goodbye);
            }
            catch { }

            try { _socket?.Close(); } catch { }

            _receiveThread?.Join(2000);
            _announceThread?.Join(2000);
            _reapThread?.Join(2000);
        }

        public void Dispose()
        {
            Stop();
        }

        // ── Announce loop ──────────────────────────────────────────
        private void AnnounceLoop()
        {
            // Initial burst: send 3 announcements quickly
            for (int i = 0; i < 3 && _running; i++)
            {
                try
                {
                    byte[] packet = BuildAnnouncement(DefaultTtl);
                    SendMulticast(packet);
                }
                catch { }
                Thread.Sleep(1000);
            }

            // Then announce periodically
            while (_running)
            {
                Thread.Sleep(AnnounceIntervalMs);
                if (!_running) break;

                try
                {
                    byte[] packet = BuildAnnouncement(DefaultTtl);
                    SendMulticast(packet);

                    // Also send a browse query to discover new peers
                    byte[] query = BuildQuery();
                    SendMulticast(query);
                }
                catch (ObjectDisposedException) { break; }
                catch { }
            }
        }

        // ── Receive loop ───────────────────────────────────────────
        private void ReceiveLoop()
        {
            byte[] buffer = new byte[9000]; // typical mDNS max
            EndPoint remoteEp = new IPEndPoint(IPAddress.Any, 0);

            while (_running)
            {
                try
                {
                    int len = _socket.ReceiveFrom(buffer, ref remoteEp);
                    if (len < 12) continue; // DNS header is 12 bytes

                    string senderAddr = ((IPEndPoint)remoteEp).Address.ToString();
                    ParsePacket(buffer, len, senderAddr);
                }
                catch (ObjectDisposedException) { break; }
                catch (SocketException) { if (!_running) break; }
                catch { }
            }
        }

        // ── Reap loop ──────────────────────────────────────────────
        private void ReapLoop()
        {
            while (_running)
            {
                Thread.Sleep(AnnounceIntervalMs);

                double now = GetUnixTimestamp();
                double cutoff = now - (PeerTimeoutMs / 1000.0);

                foreach (var kvp in _peers.ToArray())
                {
                    if (kvp.Value.LastSeen < cutoff)
                    {
                        PeerRecord removed;
                        if (_peers.TryRemove(kvp.Key, out removed))
                        {
                            PeerLost?.Invoke(kvp.Key);
                        }
                    }
                }
            }
        }

        // ================================================================
        //  DNS WIRE FORMAT — PACKET BUILDING
        // ================================================================

        /// <summary>
        /// Builds an mDNS announcement (response) containing:
        ///   Answer: PTR  _p2pshare._tcp.local. → {peerId}._p2pshare._tcp.local.
        ///   Additional: SRV {peerId}._p2pshare._tcp.local. → {peerId}.local. port
        ///   Additional: TXT {peerId}._p2pshare._tcp.local. → "peer_id={peerId}"
        ///   Additional: A   {peerId}.local. → {localIP}
        /// </summary>
        private byte[] BuildAnnouncement(int ttl)
        {
            var packet = new List<byte>();

            // DNS header (12 bytes)
            packet.AddRange(new byte[] { 0, 0 });        // Transaction ID
            packet.AddRange(ToBytes((ushort)FlagResponse)); // Flags: QR=1, AA=1
            packet.AddRange(ToBytes((ushort)0));           // Questions: 0
            packet.AddRange(ToBytes((ushort)1));           // Answers: 1 (PTR)
            packet.AddRange(ToBytes((ushort)0));           // Authority: 0
            packet.AddRange(ToBytes((ushort)3));           // Additional: 3 (SRV+TXT+A)

            // Answer: PTR record
            // _p2pshare._tcp.local. → {peerId}._p2pshare._tcp.local.
            packet.AddRange(EncodeName(ServiceType));
            packet.AddRange(ToBytes(TypePTR));
            packet.AddRange(ToBytes(ClassIN));
            packet.AddRange(ToBytes32(ttl));
            byte[] ptrData = EncodeName(_serviceName);
            packet.AddRange(ToBytes((ushort)ptrData.Length));
            packet.AddRange(ptrData);

            // Additional: SRV record
            // {peerId}._p2pshare._tcp.local. → priority=0 weight=0 port={tcpPort} {peerId}.local.
            packet.AddRange(EncodeName(_serviceName));
            packet.AddRange(ToBytes(TypeSRV));
            packet.AddRange(ToBytes(ClassFlush));
            packet.AddRange(ToBytes32(ttl));
            byte[] hostNameEncoded = EncodeName(_hostName);
            ushort srvDataLen = (ushort)(6 + hostNameEncoded.Length);
            packet.AddRange(ToBytes(srvDataLen));
            packet.AddRange(ToBytes((ushort)0));           // Priority
            packet.AddRange(ToBytes((ushort)0));           // Weight
            packet.AddRange(ToBytes((ushort)_tcpPort));    // Port
            packet.AddRange(hostNameEncoded);

            // Additional: TXT record
            // {peerId}._p2pshare._tcp.local. → "peer_id={peerId}"
            packet.AddRange(EncodeName(_serviceName));
            packet.AddRange(ToBytes(TypeTXT));
            packet.AddRange(ToBytes(ClassFlush));
            packet.AddRange(ToBytes32(ttl));
            byte[] txtEntry = EncodeTxtEntry("peer_id=" + _peerId);
            packet.AddRange(ToBytes((ushort)txtEntry.Length));
            packet.AddRange(txtEntry);

            // Additional: A record
            // {peerId}.local. → local IP
            packet.AddRange(EncodeName(_hostName));
            packet.AddRange(ToBytes(TypeA));
            packet.AddRange(ToBytes(ClassFlush));
            packet.AddRange(ToBytes32(ttl));
            byte[] ipBytes = GetLocalIPBytes();
            packet.AddRange(ToBytes((ushort)ipBytes.Length));
            packet.AddRange(ipBytes);

            return packet.ToArray();
        }

        /// <summary>
        /// Builds an mDNS query for PTR records of _p2pshare._tcp.local.
        /// </summary>
        private byte[] BuildQuery()
        {
            var packet = new List<byte>();

            // DNS header
            packet.AddRange(new byte[] { 0, 0 });          // Transaction ID
            packet.AddRange(ToBytes((ushort)0));            // Flags (standard query)
            packet.AddRange(ToBytes((ushort)1));            // Questions: 1
            packet.AddRange(ToBytes((ushort)0));            // Answers
            packet.AddRange(ToBytes((ushort)0));            // Authority
            packet.AddRange(ToBytes((ushort)0));            // Additional

            // Question: _p2pshare._tcp.local. PTR IN
            packet.AddRange(EncodeName(ServiceType));
            packet.AddRange(ToBytes(TypePTR));
            packet.AddRange(ToBytes(ClassIN));

            return packet.ToArray();
        }

        // ================================================================
        //  DNS WIRE FORMAT — PACKET PARSING
        // ================================================================

        private void ParsePacket(byte[] data, int length, string senderAddr)
        {
            if (length < 12) return;

            ushort flags = ReadUInt16(data, 2);
            bool isResponse = (flags & 0x8000) != 0;
            ushort qdCount = ReadUInt16(data, 4);
            ushort anCount = ReadUInt16(data, 6);
            // arCount at offset 10 (authority at offset 8)
            ushort nsCount = ReadUInt16(data, 8);
            ushort arCount = ReadUInt16(data, 10);

            int offset = 12;

            // Skip questions
            for (int i = 0; i < qdCount && offset < length; i++)
            {
                SkipName(data, ref offset, length);
                offset += 4; // type + class
            }

            // If this is a query for our service type, respond to it
            if (!isResponse && qdCount > 0)
            {
                // Re-parse questions to check if it's asking for our service
                int qOffset = 12;
                for (int i = 0; i < qdCount && qOffset < length; i++)
                {
                    string qname = ReadName(data, ref qOffset, length);
                    if (qOffset + 4 > length) break;
                    ushort qtype = ReadUInt16(data, qOffset);
                    qOffset += 4;

                    if (qtype == TypePTR && NamesEqual(qname, ServiceType))
                    {
                        // Someone is looking for our service — respond
                        try
                        {
                            byte[] response = BuildAnnouncement(DefaultTtl);
                            SendMulticast(response);
                        }
                        catch { }
                    }
                }
            }

            // Parse answers + additional records
            int totalRecords = anCount + nsCount + arCount;
            var ptrTargets = new List<string>();
            var srvRecords = new Dictionary<string, SrvData>(StringComparer.OrdinalIgnoreCase);
            var txtRecords = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var aRecords = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            bool hasGoodbye = false;

            for (int i = 0; i < totalRecords && offset < length; i++)
            {
                string rrName = ReadName(data, ref offset, length);
                if (offset + 10 > length) break;

                ushort rrType = ReadUInt16(data, offset); offset += 2;
                ushort rrClass = ReadUInt16(data, offset); offset += 2;
                int rrTtl = ReadInt32(data, offset); offset += 4;
                ushort rdLen = ReadUInt16(data, offset); offset += 2;

                if (offset + rdLen > length) break;
                int rdEnd = offset + rdLen;

                switch (rrType)
                {
                    case TypePTR:
                        if (NamesEqual(rrName, ServiceType))
                        {
                            string target = ReadName(data, ref offset, length);
                            ptrTargets.Add(target);
                            if (rrTtl == 0) hasGoodbye = true;
                        }
                        break;

                    case TypeSRV:
                        if (rdLen >= 6)
                        {
                            // ushort priority = ReadUInt16(data, offset);
                            // ushort weight = ReadUInt16(data, offset + 2);
                            ushort port = ReadUInt16(data, offset + 4);
                            int hostOffset = offset + 6;
                            string host = ReadName(data, ref hostOffset, length);
                            srvRecords[rrName] = new SrvData { Host = host, Port = port };
                        }
                        break;

                    case TypeTXT:
                        {
                            string txtValue = ParseTxt(data, offset, rdLen);
                            if (txtValue != null)
                                txtRecords[rrName] = txtValue;
                        }
                        break;

                    case TypeA:
                        if (rdLen == 4)
                        {
                            string ip = data[offset] + "." + data[offset + 1] + "." +
                                        data[offset + 2] + "." + data[offset + 3];
                            aRecords[rrName] = ip;
                        }
                        break;
                }

                offset = rdEnd;
            }

            // Process discovered services
            foreach (string ptrTarget in ptrTargets)
            {
                string peerId = ExtractPeerIdFromServiceName(ptrTarget);
                if (string.IsNullOrEmpty(peerId)) continue;
                if (peerId == _peerId) continue; // ignore self

                // Try to get peer_id from TXT record first
                string txtPeerId;
                if (txtRecords.TryGetValue(ptrTarget, out txtPeerId) &&
                    !string.IsNullOrEmpty(txtPeerId))
                {
                    peerId = txtPeerId;
                }
                if (peerId == _peerId) continue;

                if (hasGoodbye)
                {
                    PeerRecord removed;
                    if (_peers.TryRemove(peerId, out removed))
                        PeerLost?.Invoke(peerId);
                    continue;
                }

                // Get address + port
                string address = senderAddr;
                int port = 0;

                SrvData srv;
                if (srvRecords.TryGetValue(ptrTarget, out srv))
                {
                    port = srv.Port;
                    // Try to resolve host from A records
                    string resolvedIp;
                    if (aRecords.TryGetValue(srv.Host, out resolvedIp))
                        address = resolvedIp;
                }

                if (port <= 0) continue;

                double now = GetUnixTimestamp();
                bool isNew = !_peers.ContainsKey(peerId);

                _peers[peerId] = new PeerRecord
                {
                    Address = address,
                    Port = port,
                    LastSeen = now
                };

                if (isNew)
                    PeerFound?.Invoke(peerId, address, port);
            }
        }

        private struct SrvData
        {
            public string Host;
            public int Port;
        }

        // ================================================================
        //  DNS WIRE FORMAT — ENCODING
        // ================================================================

        /// <summary>
        /// Encodes a DNS name into wire format (label-length encoding).
        /// Example: "_p2pshare._tcp.local." → [10]_p2pshare[4]_tcp[5]local[0]
        /// </summary>
        private static byte[] EncodeName(string name)
        {
            var result = new List<byte>();
            // Remove trailing dot if present
            if (name.EndsWith("."))
                name = name.Substring(0, name.Length - 1);

            string[] labels = name.Split('.');
            foreach (string label in labels)
            {
                byte[] labelBytes = Encoding.UTF8.GetBytes(label);
                if (labelBytes.Length > 63)
                    throw new ArgumentException("DNS label too long: " + label);
                result.Add((byte)labelBytes.Length);
                result.AddRange(labelBytes);
            }
            result.Add(0); // root label
            return result.ToArray();
        }

        /// <summary>
        /// Encodes a TXT record entry. Format: length-prefixed string.
        /// </summary>
        private static byte[] EncodeTxtEntry(string entry)
        {
            byte[] entryBytes = Encoding.UTF8.GetBytes(entry);
            if (entryBytes.Length > 255)
                throw new ArgumentException("TXT entry too long");
            var result = new byte[1 + entryBytes.Length];
            result[0] = (byte)entryBytes.Length;
            Buffer.BlockCopy(entryBytes, 0, result, 1, entryBytes.Length);
            return result;
        }

        // ================================================================
        //  DNS WIRE FORMAT — DECODING
        // ================================================================

        /// <summary>
        /// Reads a DNS name from the packet, handling pointer compression.
        /// </summary>
        private static string ReadName(byte[] data, ref int offset, int length)
        {
            var parts = new List<string>();
            int maxJumps = 64; // prevent infinite loops
            int jumps = 0;
            bool jumped = false;
            int savedOffset = -1;

            while (offset < length && jumps < maxJumps)
            {
                byte b = data[offset];
                if (b == 0)
                {
                    offset++;
                    break;
                }

                if ((b & 0xC0) == 0xC0)
                {
                    // Pointer
                    if (offset + 1 >= length) break;
                    int pointer = ((b & 0x3F) << 8) | data[offset + 1];
                    if (!jumped)
                        savedOffset = offset + 2;
                    offset = pointer;
                    jumped = true;
                    jumps++;
                    continue;
                }

                // Regular label
                int labelLen = b;
                offset++;
                if (offset + labelLen > length) break;
                parts.Add(Encoding.UTF8.GetString(data, offset, labelLen));
                offset += labelLen;
            }

            if (jumped && savedOffset >= 0)
                offset = savedOffset;

            return string.Join(".", parts) + ".";
        }

        /// <summary>
        /// Skips a DNS name without building the string.
        /// </summary>
        private static void SkipName(byte[] data, ref int offset, int length)
        {
            while (offset < length)
            {
                byte b = data[offset];
                if (b == 0) { offset++; return; }
                if ((b & 0xC0) == 0xC0) { offset += 2; return; }
                offset += 1 + b;
            }
        }

        /// <summary>
        /// Parses the TXT record data to extract peer_id value.
        /// TXT format: one or more length-prefixed strings, each "key=value".
        /// </summary>
        private static string ParseTxt(byte[] data, int offset, int rdLen)
        {
            int end = offset + rdLen;
            while (offset < end)
            {
                int entryLen = data[offset];
                offset++;
                if (offset + entryLen > end) break;

                string entry = Encoding.UTF8.GetString(data, offset, entryLen);
                offset += entryLen;

                // Look for peer_id=...
                if (entry.StartsWith("peer_id=", StringComparison.OrdinalIgnoreCase))
                    return entry.Substring(8);
            }
            return null;
        }

        // ================================================================
        //  HELPERS
        // ================================================================

        private static string ExtractPeerIdFromServiceName(string serviceName)
        {
            // Format: "peer-abc._p2pshare._tcp.local."
            string suffix = "." + ServiceType;
            if (serviceName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                return serviceName.Substring(0, serviceName.Length - suffix.Length);

            // Also try without trailing dot
            string suffixNoDot = "._p2pshare._tcp.local.";
            int idx = serviceName.IndexOf(suffixNoDot, StringComparison.OrdinalIgnoreCase);
            if (idx > 0) return serviceName.Substring(0, idx);

            return null;
        }

        private static bool NamesEqual(string a, string b)
        {
            // DNS names are case-insensitive
            return string.Equals(
                a.TrimEnd('.'), b.TrimEnd('.'),
                StringComparison.OrdinalIgnoreCase);
        }

        private void SendMulticast(byte[] packet)
        {
            var ep = new IPEndPoint(MdnsMulticast, MdnsPort);
            _socket.SendTo(packet, ep);
        }

        private static byte[] GetLocalIPBytes()
        {
            try
            {
                using (var s = new Socket(AddressFamily.InterNetwork,
                                          SocketType.Dgram, ProtocolType.Udp))
                {
                    s.Connect("8.8.8.8", 80);
                    var ip = ((IPEndPoint)s.LocalEndPoint).Address;
                    return ip.GetAddressBytes();
                }
            }
            catch
            {
                return new byte[] { 127, 0, 0, 1 };
            }
        }

        private static ushort ReadUInt16(byte[] data, int offset)
        {
            return (ushort)((data[offset] << 8) | data[offset + 1]);
        }

        private static int ReadInt32(byte[] data, int offset)
        {
            return (data[offset] << 24) | (data[offset + 1] << 16) |
                   (data[offset + 2] << 8) | data[offset + 3];
        }

        private static byte[] ToBytes(ushort value)
        {
            return new byte[] { (byte)(value >> 8), (byte)(value & 0xFF) };
        }

        private static byte[] ToBytes32(int value)
        {
            return new byte[]
            {
                (byte)((value >> 24) & 0xFF),
                (byte)((value >> 16) & 0xFF),
                (byte)((value >> 8) & 0xFF),
                (byte)(value & 0xFF)
            };
        }

        private static double GetUnixTimestamp()
        {
            return (DateTime.UtcNow -
                    new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
        }
    }
}
