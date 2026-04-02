using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Threading;
using P2PFT_Cs.DataObj;

namespace P2PFT_Cs
{
    /// <summary>
    /// UDP broadcast peer discovery + TCP listener for incoming messages.
    ///
    /// Discovery flow:
    ///   1. Broadcasts a PEER_ANNOUNCE every <see cref="AnnounceIntervalMs"/>
    ///      on UDP port <see cref="DiscoveryPort"/>.
    ///   2. Listens for PEER_ANNOUNCE from other peers on the same port.
    ///   3. When a new peer is found, registers it with
    ///      <see cref="FileTransfer.RegisterPeer"/> and raises
    ///      <see cref="PeerDiscovered"/>.
    ///   4. If a peer hasn't announced for <see cref="PeerTimeoutMs"/>,
    ///      it's marked offline.
    ///
    /// Also runs a TCP listener that receives protocol messages and
    /// dispatches them to <see cref="FileTransfer"/> and
    /// <see cref="PeerValidation"/>.
    /// </summary>
    internal class PeerDiscovery : IDisposable
    {
        // ©¤©¤ Constants ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤
        private const int DiscoveryPort = 9876;
        private const int AnnounceIntervalMs = 5000;
        private const int PeerTimeoutMs = 20000;
        private const int HeaderSize = 4;
        private const int MaxMessageSize = 64 * 1024 * 1024;
        private const int TcpReadTimeoutMs = 30000;

        // ©¤©¤ Identity ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤
        private readonly string _peerId;
        private readonly int _tcpPort;
        private readonly FileTransfer _fileTransfer;
        private readonly PeerValidation _validation;

        // ©¤©¤ Threads / sockets ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤
        private UdpClient _udpSender;
        private UdpClient _udpListener;
        private TcpListener _tcpListener;
        private Thread _announceThread;
        private Thread _udpListenThread;
        private Thread _tcpListenThread;
        private Thread _reapThread;
        private volatile bool _running;

        // ©¤©¤ Discovered peers (last-seen timestamp) ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤
        private readonly ConcurrentDictionary<string, double> _lastSeen =
            new ConcurrentDictionary<string, double>();

        /// <summary>
        /// Raised on the background thread when a new peer appears.
        /// Parameters: peerId, address, port.
        /// </summary>
        public event Action<string, string, int> PeerDiscovered;

        /// <summary>
        /// Raised on the background thread when a peer goes offline.
        /// </summary>
        public event Action<string> PeerOffline;

        // ©¤©¤ Constructor ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤

        public PeerDiscovery(string peerId, int tcpPort,
                             FileTransfer fileTransfer,
                             PeerValidation validation)
        {
            if (string.IsNullOrEmpty(peerId))
                throw new ArgumentException("PeerId is required.", nameof(peerId));
            if (fileTransfer == null)
                throw new ArgumentNullException(nameof(fileTransfer));
            if (validation == null)
                throw new ArgumentNullException(nameof(validation));

            _peerId = peerId;
            _tcpPort = tcpPort;
            _fileTransfer = fileTransfer;
            _validation = validation;
        }

        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T
        //  Start / Stop
        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T

        public void Start()
        {
            if (_running) return;
            _running = true;

            // UDP sender ¡ª uses an ephemeral port so it doesn't
            // conflict with the listener on the same machine.
            _udpSender = new UdpClient();
            _udpSender.EnableBroadcast = true;

            // UDP listener ¡ª binds to the discovery port.
            _udpListener = new UdpClient();
            _udpListener.Client.SetSocketOption(
                SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _udpListener.ExclusiveAddressUse = false;
            _udpListener.Client.Bind(new IPEndPoint(IPAddress.Any, DiscoveryPort));

            // TCP listener
            _tcpListener = new TcpListener(IPAddress.Any, _tcpPort);
            _tcpListener.Start();

            _announceThread = new Thread(AnnounceLoop)
            { IsBackground = true, Name = "P2P-Announce" };
            _announceThread.Start();

            _udpListenThread = new Thread(UdpListenLoop)
            { IsBackground = true, Name = "P2P-UdpListen" };
            _udpListenThread.Start();

            _tcpListenThread = new Thread(TcpListenLoop)
            { IsBackground = true, Name = "P2P-TcpListen" };
            _tcpListenThread.Start();

            _reapThread = new Thread(ReapLoop)
            { IsBackground = true, Name = "P2P-Reaper" };
            _reapThread.Start();
        }

        public void Stop()
        {
            _running = false;

            try { _udpSender?.Close(); } catch { }
            try { _udpListener?.Close(); } catch { }
            try { _tcpListener?.Stop(); } catch { }

            _announceThread?.Join(2000);
            _udpListenThread?.Join(2000);
            _tcpListenThread?.Join(2000);
            _reapThread?.Join(2000);
        }

        public void Dispose()
        {
            Stop();
        }

        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T
        //  UDP announce (broadcast PEER_ANNOUNCE)
        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T

        private void AnnounceLoop()
        {
            while (_running)
            {
                try
                {
                    // Build the JSON payload manually to avoid
                    // DataContractJsonSerializer issues with abstract types.
                    string json = BuildAnnounceJson(_peerId, _tcpPort);
                    byte[] payload = System.Text.Encoding.UTF8.GetBytes(json);
                    byte[] header = ToBigEndian(payload.Length);
                    byte[] packet = new byte[header.Length + payload.Length];
                    Buffer.BlockCopy(header, 0, packet, 0, header.Length);
                    Buffer.BlockCopy(payload, 0, packet, header.Length, payload.Length);

                    // Send to all subnet-directed broadcast addresses
                    // (more reliable than 255.255.255.255)
                    var broadcastAddresses = GetBroadcastAddresses();
                    foreach (var addr in broadcastAddresses)
                    {
                        try
                        {
                            var ep = new IPEndPoint(addr, DiscoveryPort);
                            _udpSender.Send(packet, packet.Length, ep);
                        }
                        catch { /* skip unreachable interface */ }
                    }

                    // Also send to limited broadcast as fallback
                    try
                    {
                        var fallback = new IPEndPoint(IPAddress.Broadcast, DiscoveryPort);
                        _udpSender.Send(packet, packet.Length, fallback);
                    }
                    catch { }
                }
                catch (ObjectDisposedException) { break; }
                catch { /* best effort */ }

                Thread.Sleep(AnnounceIntervalMs);
            }
        }

        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T
        //  UDP listen (receive PEER_ANNOUNCE from others)
        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T

        private void UdpListenLoop()
        {
            while (_running)
            {
                try
                {
                    var remoteEp = new IPEndPoint(IPAddress.Any, 0);
                    byte[] data = _udpListener.Receive(ref remoteEp);

                    if (data.Length < HeaderSize) continue;

                    int length = FromBigEndian(data, 0);
                    if (length <= 0 || length > MaxMessageSize) continue;
                    if (data.Length < HeaderSize + length) continue;

                    // Parse JSON manually ¡ª DataContractJsonSerializer
                    // cannot instantiate abstract jsonBody<T> base class.
                    string json = System.Text.Encoding.UTF8.GetString(
                        data, HeaderSize, length);

                    string remotePeerId = ExtractJsonString(json, "peer_id");
                    string portStr = ExtractJsonString(json, "port");
                    string msgType = ExtractJsonString(json, "type");

                    if (string.IsNullOrEmpty(remotePeerId)) continue;
                    if (msgType != "PEER_ANNOUNCE") continue;

                    int remoteTcpPort;
                    if (!int.TryParse(portStr, out remoteTcpPort))
                    {
                        // Try extracting port as a number (not quoted)
                        remoteTcpPort = ExtractJsonInt(json, "port");
                        if (remoteTcpPort <= 0) continue;
                    }

                    string remoteAddress = remoteEp.Address.ToString();

                    // Ignore our own announcements
                    if (remotePeerId == _peerId) continue;

                    double now = GetUnixTimestamp();
                    bool isNew = !_lastSeen.ContainsKey(remotePeerId);
                    _lastSeen[remotePeerId] = now;

                    if (isNew)
                    {
                        _fileTransfer.RegisterPeer(
                            remotePeerId, remoteAddress, remoteTcpPort,
                            remotePeerId, false);

                        PeerDiscovered?.Invoke(remotePeerId, remoteAddress, remoteTcpPort);
                    }
                }
                catch (ObjectDisposedException) { break; }
                catch (SocketException) { if (!_running) break; }
                catch { /* ignore malformed packets */ }
            }
        }

        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T
        //  TCP listen (receive all protocol messages)
        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T

        private void TcpListenLoop()
        {
            while (_running)
            {
                try
                {
                    TcpClient client = _tcpListener.AcceptTcpClient();
                    client.ReceiveTimeout = TcpReadTimeoutMs;
                    ThreadPool.QueueUserWorkItem(_ => HandleTcpClient(client));
                }
                catch (SocketException) { if (!_running) break; }
                catch (ObjectDisposedException) { break; }
                catch { }
            }
        }

        private void HandleTcpClient(TcpClient client)
        {
            try
            {
                using (client)
                using (NetworkStream stream = client.GetStream())
                {
                    string senderAddress =
                        ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();

                    byte[] headerBuf = ReadExactly(stream, HeaderSize);
                    if (headerBuf == null) return;
                    int length = FromBigEndian(headerBuf, 0);

                    if (length <= 0 || length > MaxMessageSize) return;

                    byte[] payloadBuf = ReadExactly(stream, length);
                    if (payloadBuf == null) return;

                    string json = System.Text.Encoding.UTF8.GetString(payloadBuf);
                    string messageType = ExtractJsonString(json, "type");
                    if (string.IsNullOrEmpty(messageType)) return;

                    DispatchMessage(messageType, payloadBuf, senderAddress);
                }
            }
            catch { }
        }

        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T
        //  Message dispatch
        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T

        private void DispatchMessage(string type, byte[] payload, string senderAddress)
        {
            switch (type)
            {
                case MessageType.FileRequest:
                    var fileReq = Deserialize<FileRequestPayload>(payload);
                    if (fileReq != null)
                    {
                        int senderPort = GetPeerPort(fileReq.Payload.PeerId);
                        _fileTransfer.HandleFileRequest(
                            fileReq.Payload, senderAddress, senderPort,
                            (name, hash) => LookupLocalFile(name, hash));
                    }
                    break;

                case MessageType.FileSend:
                    var fileSend = Deserialize<FileSendPayload>(payload);
                    if (fileSend != null)
                        _fileTransfer.HandleFileSend(fileSend.Payload);
                    break;

                case MessageType.ConsentRequest:
                    var consentReq = Deserialize<ConsentRequestPayload>(payload);
                    if (consentReq != null)
                        _fileTransfer.HandleConsentRequest(consentReq.Payload);
                    break;

                case MessageType.ConsentResponse:
                    var consentResp = Deserialize<ConsentResponsePayload>(payload);
                    if (consentResp != null)
                        _fileTransfer.HandleConsentResponse(consentResp.Payload);
                    break;

                case MessageType.KeyExchangeInit:
                    var kxInit = Deserialize<KeyExchangeInitPayload>(payload);
                    if (kxInit != null)
                        _validation.HandleKeyExchangeInit(kxInit.Payload, senderAddress);
                    break;

                case MessageType.KeyExchangeResponse:
                    var kxResp = Deserialize<KeyExchangeResponsePayload>(payload);
                    if (kxResp != null)
                        _validation.HandleKeyExchangeResponse(kxResp.Payload);
                    break;

                case MessageType.KeyExchangeConfirm:
                    var kxConfirm = Deserialize<KeyExchangeConfirmPayload>(payload);
                    if (kxConfirm != null)
                        _validation.HandleKeyExchangeConfirm(kxConfirm.Payload);
                    break;

                case MessageType.RevokeKey:
                    var revoke = Deserialize<RevokeKeyPayload>(payload);
                    if (revoke != null)
                        _validation.HandleKeyRevocation(revoke.Payload);
                    break;

                case MessageType.PeerAnnounce:
                    break; // Already handled by UDP
            }
        }

        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T
        //  Peer reaper
        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T

        private void ReapLoop()
        {
            while (_running)
            {
                Thread.Sleep(AnnounceIntervalMs);

                double now = GetUnixTimestamp();
                double cutoff = now - (PeerTimeoutMs / 1000.0);

                foreach (var kvp in _lastSeen.ToArray())
                {
                    if (kvp.Value < cutoff)
                    {
                        double removed;
                        if (_lastSeen.TryRemove(kvp.Key, out removed))
                        {
                            PeerOffline?.Invoke(kvp.Key);
                        }
                    }
                }
            }
        }

        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T
        //  JSON builders (avoid DataContractJsonSerializer for
        //  abstract base class)
        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T

        /// <summary>
        /// Builds a PEER_ANNOUNCE JSON string manually. This avoids the
        /// deserialization problem with <see cref="jsonBody{T}"/> being
        /// abstract and having no parameterless constructor.
        /// </summary>
        private static string BuildAnnounceJson(string peerId, int port)
        {
            double timestamp = GetUnixTimestamp();
            // Using string concat ¡ª no external JSON library needed on 4.8
            return "{" +
                "\"version\":\"1.0\"," +
                "\"type\":\"PEER_ANNOUNCE\"," +
                "\"timestamp\":" + timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture) + "," +
                "\"payload\":{" +
                    "\"peer_id\":\"" + EscapeJson(peerId) + "\"," +
                    "\"port\":" + port +
                "}" +
            "}";
        }

        private static string EscapeJson(string s)
        {
            if (s == null) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }

        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T
        //  JSON field extraction (lightweight, no full parse)
        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T

        /// <summary>
        /// Extracts a string value for a given key from a JSON string.
        /// Handles "key":"value" patterns.
        /// </summary>
        private static string ExtractJsonString(string json, string key)
        {
            string marker = "\"" + key + "\":\"";
            int idx = json.IndexOf(marker, StringComparison.Ordinal);
            if (idx < 0) return null;
            int start = idx + marker.Length;
            int end = json.IndexOf('"', start);
            if (end < 0) return null;
            return json.Substring(start, end - start);
        }

        /// <summary>
        /// Extracts an integer value for a given key from a JSON string.
        /// Handles "key":123 patterns (unquoted numbers).
        /// </summary>
        private static int ExtractJsonInt(string json, string key)
        {
            string marker = "\"" + key + "\":";
            int idx = json.IndexOf(marker, StringComparison.Ordinal);
            if (idx < 0) return -1;
            int start = idx + marker.Length;

            // Skip whitespace
            while (start < json.Length && json[start] == ' ') start++;

            int end = start;
            while (end < json.Length && char.IsDigit(json[end])) end++;

            if (end == start) return -1;

            int result;
            if (int.TryParse(json.Substring(start, end - start), out result))
                return result;
            return -1;
        }

        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T
        //  Network helpers
        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T

        /// <summary>
        /// Computes the subnet-directed broadcast address for each
        /// active IPv4 network interface. More reliable than
        /// <c>IPAddress.Broadcast</c> (255.255.255.255) which is
        /// blocked by many routers and firewalls.
        /// </summary>
        private static List<IPAddress> GetBroadcastAddresses()
        {
            var result = new List<IPAddress>();
            try
            {
                foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (iface.OperationalStatus != OperationalStatus.Up) continue;
                    if (iface.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                    var props = iface.GetIPProperties();
                    foreach (var unicast in props.UnicastAddresses)
                    {
                        if (unicast.Address.AddressFamily != AddressFamily.InterNetwork)
                            continue;

                        byte[] addr = unicast.Address.GetAddressBytes();
                        byte[] mask = unicast.IPv4Mask.GetAddressBytes();
                        byte[] broadcast = new byte[4];
                        for (int i = 0; i < 4; i++)
                            broadcast[i] = (byte)(addr[i] | ~mask[i]);

                        result.Add(new IPAddress(broadcast));
                    }
                }
            }
            catch { }

            if (result.Count == 0)
                result.Add(IPAddress.Broadcast); // fallback

            return result;
        }

        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T
        //  Helpers
        // ¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T¨T

        private FileTransfer.LocalFileInfo LookupLocalFile(string filename, string hash)
        {
            string sharedDir = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory, "shared");
            string filePath = Path.Combine(sharedDir, filename);

            if (!File.Exists(filePath)) return null;

            byte[] data = File.ReadAllBytes(filePath);
            string actualHash = Utils.TransmissionCrypto.ComputeSha256Hex(data);

            return new FileTransfer.LocalFileInfo
            {
                Filename = filename,
                FileHash = actualHash,
                FilePath = filePath,
            };
        }

        private int GetPeerPort(string peerId)
        {
            return _tcpPort;
        }

        private static byte[] ReadExactly(NetworkStream stream, int count)
        {
            byte[] buffer = new byte[count];
            int offset = 0;
            while (offset < count)
            {
                int read = stream.Read(buffer, offset, count - offset);
                if (read == 0) return null;
                offset += read;
            }
            return buffer;
        }

        private static byte[] ToBigEndian(int value)
        {
            byte[] bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            return bytes;
        }

        private static int FromBigEndian(byte[] data, int offset)
        {
            byte[] buf = new byte[4];
            Buffer.BlockCopy(data, offset, buf, 0, 4);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(buf);
            return BitConverter.ToInt32(buf, 0);
        }

        private static double GetUnixTimestamp()
        {
            return (DateTime.UtcNow -
                    new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
        }

        /// <summary>
        /// Deserializes TCP protocol messages using the concrete message
        /// types (not the abstract base). Used only for TCP dispatch where
        /// we know the specific message class.
        /// </summary>
        private static jsonBody<T> Deserialize<T>(byte[] payload)
            where T : BasePayload
        {
            try
            {
                // Use the concrete message types for deserialization.
                // jsonBody<T> is abstract, so we must use the known
                // subclass that DataContractJsonSerializer can instantiate.
                Type concreteType = GetConcreteMessageType<T>();
                if (concreteType == null) return null;

                var serializer = new DataContractJsonSerializer(concreteType);
                using (var ms = new MemoryStream(payload))
                {
                    return (jsonBody<T>)serializer.ReadObject(ms);
                }
            }
            catch { return null; }
        }

        /// <summary>
        /// Maps a payload type to the concrete <see cref="jsonBody{T}"/>
        /// subclass that <see cref="DataContractJsonSerializer"/> can
        /// instantiate.
        /// </summary>
        private static Type GetConcreteMessageType<T>() where T : BasePayload
        {
            Type payloadType = typeof(T);

            if (payloadType == typeof(PeerAnnouncePayload))
                return typeof(PeerAnnounceMessage);
            if (payloadType == typeof(PeerListRequestPayload))
                return typeof(PeerListRequestMessage);
            if (payloadType == typeof(PeerListResponsePayload))
                return typeof(PeerListResponseMessage);
            if (payloadType == typeof(KeyExchangeInitPayload))
                return typeof(KeyExchangeInitMessage);
            if (payloadType == typeof(KeyExchangeResponsePayload))
                return typeof(KeyExchangeResponseMessage);
            if (payloadType == typeof(KeyExchangeConfirmPayload))
                return typeof(KeyExchangeConfirmMessage);
            if (payloadType == typeof(FileListRequestPayload))
                return typeof(FileListRequestMessage);
            if (payloadType == typeof(FileListResponsePayload))
                return typeof(FileListResponseMessage);
            if (payloadType == typeof(FileRequestPayload))
                return typeof(FileRequestMessage);
            if (payloadType == typeof(FileSendPayload))
                return typeof(FileSendMessage);
            if (payloadType == typeof(ConsentRequestPayload))
                return typeof(ConsentRequestMessage);
            if (payloadType == typeof(ConsentResponsePayload))
                return typeof(ConsentResponseMessage);
            if (payloadType == typeof(RevokeKeyPayload))
                return typeof(RevokeKeyMessage);
            if (payloadType == typeof(ErrorPayload))
                return typeof(ErrorMessage);

            return null;
        }
    }
}