using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Serialization.Json;
using System.Threading;
using P2PFT_Cs.DataObj;
using P2PFT_Cs.Utils;

namespace P2PFT_Cs
{
    /// <summary>
    /// mDNS peer discovery + TCP listener for incoming messages.
    ///
    /// Discovery flow:
    ///   1. Advertises this peer via mDNS on _p2pshare._tcp.local.
    ///   2. Browses for other peers advertising the same service.
    ///   3. When a new peer is found, registers it with
    ///      <see cref="FileTransfer.RegisterPeer"/> and raises
    ///      <see cref="PeerDiscovered"/>.
    ///   4. When a peer stops advertising, raises <see cref="PeerOffline"/>.
    ///
    /// Also runs a TCP listener that receives protocol messages and
    /// dispatches them to <see cref="FileTransfer"/> and
    /// <see cref="PeerValidation"/>.
    /// </summary>
    internal class PeerDiscovery : IDisposable
    {
        //Constants 
        private const int HeaderSize = 4;
        private const int MaxMessageSize = 64 * 1024 * 1024;
        private const int TcpReadTimeoutMs = 30000;

        // Identity
        private readonly string _peerId;
        private readonly int _tcpPort;
        private readonly FileTransfer _fileTransfer;
        private readonly PeerValidation _validation;
        private ManifestStorage _manifests;
        private Func<List<DataObj.FileInfo>> _getSharedFiles;

        //Threads / sockets 
        private MdnsDiscovery _mdns;
        private TcpListener _tcpListener;
        private Thread _tcpListenThread;
        private volatile bool _running;

        /// <summary>
        /// Raised on the background thread when a new peer appears.
        /// Parameters: peerId, address, port.
        /// </summary>
        public event Action<string, string, int> PeerDiscovered;

        /// <summary>
        /// Raised on the background thread when a peer goes offline.
        /// </summary>
        public event Action<string> PeerOffline;

        //Constructor

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

        public void SetManifestStorage(ManifestStorage manifests)
        {
            _manifests = manifests;
        }

        public void SetSharedFilesCallback(Func<List<DataObj.FileInfo>> callback)
        {
            _getSharedFiles = callback;
        }

        //  Start / Stop
        
        public void Start()
        {
            if (_running) return;
            _running = true;

            // mDNS discovery — advertise + browse for _p2pshare._tcp.local.
            _mdns = new MdnsDiscovery(_peerId, _tcpPort);
            _mdns.PeerFound += OnMdnsPeerFound;
            _mdns.PeerLost += OnMdnsPeerLost;
            _mdns.Start();

            // TCP listener
            _tcpListener = new TcpListener(IPAddress.Any, _tcpPort);
            _tcpListener.Start();

            _tcpListenThread = new Thread(TcpListenLoop)
            { IsBackground = true, Name = "P2P-TcpListen" };
            _tcpListenThread.Start();
        }

        public void Stop()
        {
            _running = false;

            try { _mdns?.Stop(); } catch { }
            try { _tcpListener?.Stop(); } catch { }

            _tcpListenThread?.Join(2000);
        }

        public void Dispose()
        {
            Stop();
        }

        //mDNS event handlers

        private void OnMdnsPeerFound(string peerId, string address, int port)
        {
            _fileTransfer.RegisterPeer(peerId, address, port, peerId, false);
            PeerDiscovered?.Invoke(peerId, address, port);
        }

        private void OnMdnsPeerLost(string peerId)
        {
            PeerOffline?.Invoke(peerId);
        }

        //receive all protocol messages

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
                NetworkStream stream = client.GetStream();
                string senderAddress =
                    ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();

                byte[] headerBuf = ReadExactly(stream, HeaderSize);
                if (headerBuf == null) { client.Close(); return; }
                int length = FromBigEndian(headerBuf, 0);

                if (length <= 0 || length > MaxMessageSize) { client.Close(); return; }

                byte[] payloadBuf = ReadExactly(stream, length);
                if (payloadBuf == null) { client.Close(); return; }

                string json = System.Text.Encoding.UTF8.GetString(payloadBuf);
                string messageType = ExtractJsonString(json, "type");
                if (string.IsNullOrEmpty(messageType)) { client.Close(); return; }

                if (messageType == MessageType.KeyExchangeInit)
                {
                    // STS handshake: pass the socket so PeerValidation can
                    // send RESPONSE and read CONFIRM on the same connection.
                    // PeerValidation is responsible for closing the client.
                    var kxInit = Deserialize<KeyExchangeInitPayload>(payloadBuf);
                    if (kxInit != null)
                        _validation.HandleKeyExchangeInit(
                            kxInit.Payload, client, stream, senderAddress);
                    else
                        client.Close();
                }
                else if (messageType == MessageType.FileListRequest)
                {
                    
                    var flReq = Deserialize<FileListRequestPayload>(payloadBuf);
                    if (flReq != null && _getSharedFiles != null)
                        _fileTransfer.HandleFileListRequest(
                            flReq.Payload, stream, _getSharedFiles);
                    client.Close();
                }
                else
                {
                    
                    client.Close();
                    DispatchMessage(messageType, payloadBuf, senderAddress);
                }
            }
            catch
            {
                try { client.Close(); } catch { }
            }
        }

         //  Message dispatch
      
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

                    break;

                case MessageType.VerifyConfirm:
                    var verifyConf = Deserialize<VerifyConfirmPayload>(payload);
                    if (verifyConf != null)
                        _validation.HandleVerifyConfirm(verifyConf.Payload);
                    break;

                case MessageType.VerifyReject:
                    var verifyRej = Deserialize<VerifyRejectPayload>(payload);
                    if (verifyRej != null)
                        _validation.HandleVerifyReject(verifyRej.Payload);
                    break;

                case MessageType.FileListResponse:
                    var flResp = Deserialize<FileListResponsePayload>(payload);
                    if (flResp != null && _manifests != null)
                        _fileTransfer.HandleFileListResponse(flResp.Payload, _manifests);
                    break;

                case MessageType.RevokeKey:
                    var revoke = Deserialize<RevokeKeyPayload>(payload);
                    if (revoke != null)
                        _validation.HandleKeyRevocation(revoke.Payload);
                    break;

                case MessageType.PeerAnnounce:
                    break; 
            }
        }

        //JSON field extraction

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

        // Helpers

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
            if (payloadType == typeof(VerifyConfirmPayload))
                return typeof(VerifyConfirmMessage);
            if (payloadType == typeof(VerifyRejectPayload))
                return typeof(VerifyRejectMessage);
            if (payloadType == typeof(ErrorPayload))
                return typeof(ErrorMessage);

            return null;
        }
    }
}