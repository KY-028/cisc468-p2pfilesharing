using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.Serialization.Json;
using P2PFT_Cs.DataObj;
using P2PFT_Cs.Utils;

namespace P2PFT_Cs
{
    /// <summary>
    /// Consent-based file transfer logic.
    ///
    /// This class manages the consent / file-transfer workflow:
    ///   1. Peer A requests a file from Peer B (FILE_REQUEST).
    ///   2. Peer B shows a consent prompt to the user.
    ///   3. User accepts or denies.
    ///   4. If accepted, Peer B encrypts and sends the file (FILE_SEND).
    ///      If denied, Peer B notifies Peer A with a CONSENT_RESPONSE(denied).
    ///   5. File is received, decrypted, hash-verified, and encrypted
    ///      at rest using PBKDF2-HMAC-SHA256 derived key via
    ///      <see cref="LocalFileCrypto"/>.
    ///
    /// Also handles push offers (CONSENT_REQUEST) where a peer offers to
    /// send you a file and you must approve first.
    /// </summary>
    internal class FileTransfer
    {
        // ── Wire protocol constants (must match transport.py) ────────
        private const int HeaderSize = 4; // 4-byte big-endian length prefix
        private const int MaxMessageSize = 64 * 1024 * 1024; // 64 MB
        private const int DefaultTimeout = 10_000; // milliseconds

        // ── Received-files directory ─────────────────────────────────
        private static readonly string ReceivedDir =
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "received");

        // ── Identity & state ─────────────────────────────────────────
        private readonly string _peerId;
        private readonly string _password;
        private readonly string _userId;

        /// <summary>Discovered peers keyed by peer_id.</summary>
        private readonly ConcurrentDictionary<string, PeerEndpoint> _peers =
            new ConcurrentDictionary<string, PeerEndpoint>();

        /// <summary>Transfer records (active + completed).</summary>
        private readonly List<TransferRecord> _transfers = new List<TransferRecord>();
        private readonly object _transferLock = new object();

        /// <summary>Pending consent requests awaiting user decision.</summary>
        private readonly ConcurrentDictionary<string, ConsentRecord> _pendingConsents =
            new ConcurrentDictionary<string, ConsentRecord>();

        /// <summary>Pending outgoing sends waiting for remote approval.</summary>
        private readonly ConcurrentDictionary<string, PendingSendInfo> _pendingOutgoing =
            new ConcurrentDictionary<string, PendingSendInfo>();

        /// <summary>Pending incoming sends (file data buffered, awaiting local consent).</summary>
        private readonly ConcurrentDictionary<string, PendingReceiveInfo> _pendingReceives =
            new ConcurrentDictionary<string, PendingReceiveInfo>();

        /// <summary>Filenames we already approved to receive from a given peer.</summary>
        private readonly ConcurrentDictionary<string, byte> _approvedReceives =
            new ConcurrentDictionary<string, byte>();

        /// <summary>Resolved consent info keyed by request_id (for consent offers).</summary>
        private readonly ConcurrentDictionary<string, ResolvedConsent> _resolvedConsents =
            new ConcurrentDictionary<string, ResolvedConsent>();

        /// <summary>Session keys per peer (32-byte AES keys from STS handshake).</summary>
        private readonly ConcurrentDictionary<string, byte[]> _sessionKeys =
            new ConcurrentDictionary<string, byte[]>();

        /// <summary>Status/error messages for the UI.</summary>
        private readonly List<StatusEntry> _statusLog = new List<StatusEntry>();
        private readonly object _statusLock = new object();

        /// <summary>
        /// Raised immediately when a new consent request is received
        /// (file_request or file_send). Passes the ConsentRecord.
        /// </summary>
        public event Action<ConsentRecord> ConsentReceived;

        // ── Constructor ──────────────────────────────────────────────

        /// <param name="peerId">This peer's unique identifier.</param>
        /// <param name="password">Password used for at-rest encryption via PBKDF2.</param>
        /// <param name="userId">User identifier embedded in encrypted file headers.</param>
        public FileTransfer(string peerId, string password, string userId)
        {
            if (string.IsNullOrEmpty(peerId))
                throw new ArgumentException("PeerId must not be null or empty.", nameof(peerId));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password must not be null or empty.", nameof(password));
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentException("UserId must not be null or empty.", nameof(userId));

            _peerId = peerId;
            _password = password;
            _userId = userId;
        }

        // ── Peer management ──────────────────────────────────────────

        /// <summary>Registers or updates a known peer.</summary>
        public void RegisterPeer(string peerId, string address, int port,
                                 string displayName = null, bool trusted = false)
        {
            _peers[peerId] = new PeerEndpoint
            {
                PeerId = peerId,
                Address = address,
                Port = port,
                DisplayName = displayName ?? peerId,
                Trusted = trusted,
                Online = true,
            };
        }

        /// <summary>Stores a session key for a peer (set after STS handshake).</summary>
        public void SetSessionKey(string peerId, byte[] sessionKey)
        {
            if (sessionKey == null || sessionKey.Length != 32)
                throw new ArgumentException("Session key must be exactly 32 bytes.", nameof(sessionKey));

            _sessionKeys[peerId] = sessionKey;
        }

        // ================================================================
        //  File list exchange
        // ================================================================

        /// <summary>
        /// Opens a TCP connection to a peer, sends FILE_LIST_REQUEST,
        /// and reads the FILE_LIST_RESPONSE on the same socket (matching
        /// Python's request_file_list_from_peer flow).
        /// </summary>
        public void RequestFileListFromPeer(string peerId, ManifestStorage manifests)
        {
            PeerEndpoint peer;
            if (!_peers.TryGetValue(peerId, out peer) || !peer.Online)
            {
                AddStatus("Cannot fetch file list: peer " + peerId + " is not online.", "warning");
                return;
            }

            try
            {
                var msg = new FileListRequestMessage(new FileListRequestPayload
                {
                    PeerId = _peerId,
                });

                var serializer = new DataContractJsonSerializer(typeof(FileListRequestMessage));
                byte[] payload;
                using (var ms = new MemoryStream())
                {
                    serializer.WriteObject(ms, msg);
                    payload = ms.ToArray();
                }

                byte[] header = BitConverter.GetBytes(payload.Length);
                if (BitConverter.IsLittleEndian) Array.Reverse(header);

                using (var client = new TcpClient())
                {
                    client.Connect(peer.Address, peer.Port);
                    client.SendTimeout = DefaultTimeout;
                    client.ReceiveTimeout = DefaultTimeout;
                    NetworkStream stream = client.GetStream();

                    // Send request
                    stream.Write(header, 0, header.Length);
                    stream.Write(payload, 0, payload.Length);
                    stream.Flush();

                    // Read response on same socket
                    byte[] respHeader = ReadExactly(stream, HeaderSize);
                    if (respHeader == null) { AddStatus("File list: no response from " + peerId, "warning"); return; }
                    int respLen = FromBigEndian(respHeader, 0);
                    if (respLen <= 0 || respLen > MaxMessageSize) { AddStatus("File list: invalid response size from " + peerId, "warning"); return; }

                    byte[] respPayload = ReadExactly(stream, respLen);
                    if (respPayload == null) { AddStatus("File list: incomplete response from " + peerId, "warning"); return; }

                    var respSerializer = new DataContractJsonSerializer(typeof(FileListResponseMessage));
                    using (var rms = new MemoryStream(respPayload))
                    {
                        var respMsg = (FileListResponseMessage)respSerializer.ReadObject(rms);
                        if (respMsg != null && respMsg.Payload != null && respMsg.Payload.Files != null)
                        {
                            manifests.Store(peerId, respMsg.Payload.Files);
                            AddStatus("Received file list from " + peerId + " (" + respMsg.Payload.Files.Count + " files)", "info");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AddStatus("Failed to fetch file list from " + peerId + ": " + ex.Message, "error");
            }
        }

        /// <summary>
        /// Handles an incoming FILE_LIST_REQUEST by responding with our
        /// shared file list on the same TCP socket.
        /// </summary>
        public void HandleFileListRequest(FileListRequestPayload request,
                                          NetworkStream stream,
                                          Func<List<DataObj.FileInfo>> getSharedFiles)
        {
            try
            {
                var files = getSharedFiles();
                var resp = new FileListResponseMessage(new FileListResponsePayload
                {
                    PeerId = _peerId,
                    Files = files,
                });

                var serializer = new DataContractJsonSerializer(typeof(FileListResponseMessage));
                byte[] payload;
                using (var ms = new MemoryStream())
                {
                    serializer.WriteObject(ms, resp);
                    payload = ms.ToArray();
                }

                byte[] header = BitConverter.GetBytes(payload.Length);
                if (BitConverter.IsLittleEndian) Array.Reverse(header);

                stream.Write(header, 0, header.Length);
                stream.Write(payload, 0, payload.Length);
                stream.Flush();

                AddStatus("Sent file list to " + request.PeerId, "info");
            }
            catch (Exception ex)
            {
                AddStatus("Failed to send file list: " + ex.Message, "error");
            }
        }

        /// <summary>
        /// Handles an incoming FILE_LIST_RESPONSE (dispatched from
        /// PeerDiscovery when received as a standalone message).
        /// </summary>
        public void HandleFileListResponse(FileListResponsePayload response,
                                           ManifestStorage manifests)
        {
            if (response.Files == null) return;
            manifests.Store(response.PeerId, response.Files);
            AddStatus("Received file list from " + response.PeerId +
                      " (" + response.Files.Count + " files)", "info");
        }

        // ── File list helpers ────────────────────────────────────────

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

        private static int FromBigEndian(byte[] data, int offset)
        {
            byte[] buf = new byte[4];
            Buffer.BlockCopy(data, offset, buf, 0, 4);
            if (BitConverter.IsLittleEndian) Array.Reverse(buf);
            return BitConverter.ToInt32(buf, 0);
        }

        // ================================================================
        //  Outgoing: we initiate
        // ================================================================

        /// <summary>
        /// Sends a FILE_REQUEST to a peer asking for a specific file.
        /// If the peer is offline, broadcasts the request to all online
        /// trusted peers that may have the file.
        /// </summary>
        /// <param name="peerId">Target peer id.</param>
        /// <param name="filename">Name of the requested file.</param>
        /// <param name="fileHash">Optional SHA-256 hash for verification.</param>
        /// <returns>The <see cref="TransferRecord"/>, or null if the peer is unknown.</returns>
        public TransferRecord RequestFileFromPeer(string peerId, string filename, string fileHash = "")
        {
            PeerEndpoint peer;
            if (!_peers.TryGetValue(peerId, out peer))
            {
                AddStatus("Unknown peer: " + peerId, "error");
                return null;
            }

            string transferId = Guid.NewGuid().ToString("N").Substring(0, 12);
            var record = new TransferRecord
            {
                TransferId = transferId,
                Filename = filename,
                PeerId = peerId,
                Direction = "incoming",
                Status = "pending",
                Timestamp = GetUnixTimestamp(),
            };

            lock (_transferLock)
            {
                _transfers.Add(record);
            }

            // Direct request if peer is online
            if (peer.Online)
            {
                try
                {
                    var msg = new FileRequestMessage(new FileRequestPayload
                    {
                        PeerId = _peerId,
                        Filename = filename,
                        FileHash = string.IsNullOrEmpty(fileHash)
                            ? new string('0', 64)
                            : fileHash,
                    });
                    SendToPeer(peer.Address, peer.Port, msg);
                    AddStatus("Requested '" + filename + "' from " + peerId, "info");
                    return record;
                }
                catch (Exception ex)
                {
                    AddStatus("Direct request to " + peerId + " failed, searching other peers…",
                              "warning");
                }
            }

            // Peer offline or direct failed — broadcast to online trusted peers
            if (string.IsNullOrEmpty(fileHash))
            {
                record.Status = "failed";
                record.Error = "Peer is offline and file hash is unknown";
                AddStatus("Cannot request '" + filename + "': " + peerId +
                          " is offline and no cached file hash available.", "error");
                return record;
            }

            var sentTo = new List<string>();
            foreach (var kvp in _peers)
            {
                if (kvp.Key == peerId || kvp.Key == _peerId)
                    continue;
                if (!kvp.Value.Online || !kvp.Value.Trusted)
                    continue;

                try
                {
                    var msg = new FileRequestMessage(new FileRequestPayload
                    {
                        PeerId = _peerId,
                        Filename = filename,
                        FileHash = fileHash,
                    });
                    SendToPeer(kvp.Value.Address, kvp.Value.Port, msg);
                    sentTo.Add(kvp.Value.DisplayName);
                }
                catch
                {
                    // Skip unreachable peers
                }
            }

            if (sentTo.Count > 0)
            {
                AddStatus("File request broadcast to " + sentTo.Count +
                          " online peer(s): " + string.Join(", ", sentTo) +
                          ". Waiting for responses…", "info");
            }
            else
            {
                record.Status = "failed";
                record.Error = "No online trusted peers available";
                AddStatus("Cannot retrieve '" + filename + "': " + peerId +
                          " is offline and no other trusted peers are online.", "error");
            }

            return record;
        }

        /// <summary>
        /// Sends a CONSENT_REQUEST to the receiving peer, asking them to
        /// approve before we push a file. The file is only sent after they
        /// reply with CONSENT_RESPONSE(approved=True).
        /// </summary>
        /// <param name="peerId">Target peer id.</param>
        /// <param name="filename">Filename to offer.</param>
        /// <param name="fileHash">SHA-256 hash of the file.</param>
        /// <param name="filePath">Full path to the file on disk.</param>
        /// <returns>True if the consent offer was sent successfully.</returns>
        public bool SendConsentOffer(string peerId, string filename,
                                     string fileHash, string filePath)
        {
            PeerEndpoint peer;
            if (!_peers.TryGetValue(peerId, out peer))
            {
                AddStatus("Unknown peer: " + peerId, "error");
                return false;
            }

            try
            {
                var msg = new ConsentRequestMessage(new ConsentRequestPayload
                {
                    PeerId = _peerId,
                    Action = "file_send",
                    Filename = filename,
                });
                SendToPeer(peer.Address, peer.Port, msg);

                string key = peerId + ":" + filename;
                _pendingOutgoing[key] = new PendingSendInfo
                {
                    PeerId = peerId,
                    Address = peer.Address,
                    Port = peer.Port,
                    Filename = filename,
                    FileHash = fileHash,
                    FilePath = filePath,
                };

                AddStatus("Consent request sent to " + peerId + " for '" +
                          filename + "'. Waiting for approval…", "info");
                return true;
            }
            catch (Exception ex)
            {
                AddStatus("Failed to send consent request to " + peerId + ": " + ex.Message, "error");
                return false;
            }
        }

        // ================================================================
        //  Incoming message handlers
        // ================================================================

        /// <summary>
        /// Handles an incoming FILE_REQUEST: creates a consent prompt for the
        /// local user to approve or deny.
        /// </summary>
        /// <param name="payload">The deserialized FILE_REQUEST payload.</param>
        /// <param name="senderAddress">IP address of the requesting peer.</param>
        /// <param name="senderPort">TCP port of the requesting peer.</param>
        /// <param name="localFileLookup">
        /// Delegate that resolves a filename/hash to a local file path.
        /// Returns null if the file is not found.
        /// </param>
        public void HandleFileRequest(FileRequestPayload payload, string senderAddress,
                                      int senderPort,
                                      Func<string, string, LocalFileInfo> localFileLookup)
        {
            string remotePeerId = payload.PeerId;
            string filename = payload.Filename;
            string fileHash = payload.FileHash ?? "";

            LocalFileInfo localFile = localFileLookup(filename, fileHash);
            if (localFile == null)
            {
                // Send FILE_NOT_FOUND error back
                try
                {
                    var err = new ErrorMessage(new ErrorPayload
                    {
                        PeerId = _peerId,
                        Code = "FILE_NOT_FOUND",
                        Description = "File '" + filename + "' not found in shared files",
                    });
                    SendToPeer(senderAddress, senderPort, err);
                }
                catch
                {
                    // Best effort
                }

                AddStatus("Peer " + remotePeerId + " requested unknown file: " + filename, "warning");
                return;
            }

            PeerEndpoint peerInfo;
            string peerName = _peers.TryGetValue(remotePeerId, out peerInfo)
                ? peerInfo.DisplayName
                : remotePeerId;

            string requestId = Guid.NewGuid().ToString("N").Substring(0, 12);
            _pendingConsents[requestId] = new ConsentRecord
            {
                RequestId = requestId,
                PeerId = remotePeerId,
                PeerName = peerName,
                Action = "file_request",
                Filename = localFile.Filename,
                FileHash = localFile.FileHash,
                Timestamp = GetUnixTimestamp(),
            };

            // Remember where to send the file when user approves
            _pendingOutgoing[requestId] = new PendingSendInfo
            {
                PeerId = remotePeerId,
                Address = senderAddress,
                Port = _peers.ContainsKey(remotePeerId) ? _peers[remotePeerId].Port : senderPort,
                Filename = localFile.Filename,
                FileHash = localFile.FileHash,
                FilePath = localFile.FilePath,
            };

            AddStatus("Peer " + peerName + " wants '" + filename + "' — awaiting your consent", "warning");
            ConsentReceived?.Invoke(_pendingConsents[requestId]);
        }

        /// <summary>
        /// Handles an incoming FILE_SEND: decrypts, hash-verifies, and either
        /// saves immediately (if prior consent exists) or buffers data and
        /// prompts the user.
        /// </summary>
        /// <param name="payload">The deserialized FILE_SEND payload.</param>
        public void HandleFileSend(FileSendPayload payload)
        {
            string remotePeerId = payload.PeerId;
            string filename = payload.Filename;
            string fileHash = payload.FileHash ?? "";
            string encryptedBase64 = payload.Data;

            // Decrypt using session key
            byte[] sessionKey;
            if (!_sessionKeys.TryGetValue(remotePeerId, out sessionKey))
            {
                AddStatus("Rejected '" + filename + "' from " + remotePeerId +
                          ": no active session. Handshake required before file transfer.", "error");
                return;
            }

            byte[] fileData;
            try
            {
                fileData = TransmissionCrypto.Decrypt(sessionKey, encryptedBase64, filename, fileHash);
            }
            catch (Exception ex)
            {
                AddStatus("Decryption FAILED for '" + filename + "' from " + remotePeerId +
                          ": " + ex.Message + ". File may have been tampered with!", "error");
                return;
            }

            // Verify SHA-256 hash of the decrypted plaintext
            string actualHash = TransmissionCrypto.ComputeSha256Hex(fileData);
            if (!string.IsNullOrEmpty(fileHash) &&
                !string.Equals(actualHash, fileHash, StringComparison.OrdinalIgnoreCase))
            {
                AddStatus("Hash mismatch for '" + filename + "' from " + remotePeerId +
                          "! File rejected.", "error");
                return;
            }

            // Check if user already consented (they requested the file earlier)
            bool hasConsent = CheckPriorConsent(remotePeerId, filename);

            if (hasConsent)
            {
                SaveReceivedFile(remotePeerId, filename, fileData, actualHash);
            }
            else
            {
                // Buffer decrypted data and prompt user
                PeerEndpoint peerInfo;
                string peerName = _peers.TryGetValue(remotePeerId, out peerInfo)
                    ? peerInfo.DisplayName
                    : remotePeerId;

                string requestId = Guid.NewGuid().ToString("N").Substring(0, 12);
                _pendingConsents[requestId] = new ConsentRecord
                {
                    RequestId = requestId,
                    PeerId = remotePeerId,
                    PeerName = peerName,
                    Action = "file_send",
                    Filename = filename,
                    FileHash = fileHash,
                    Timestamp = GetUnixTimestamp(),
                };

                _pendingReceives[requestId] = new PendingReceiveInfo
                {
                    PeerId = remotePeerId,
                    Filename = filename,
                    FileData = fileData,
                    FileHash = actualHash,
                };

                AddStatus("Peer " + peerName + " is sending '" + filename + "' (" +
                          fileData.Length + " bytes) — awaiting your consent to save", "warning");
            }
        }

        /// <summary>
        /// Handles an incoming CONSENT_REQUEST (push offer from a peer).
        /// Creates a consent prompt for the local user.
        /// </summary>
        public void HandleConsentRequest(ConsentRequestPayload payload)
        {
            string remotePeerId = payload.PeerId;
            string filename = payload.Filename;
            string action = payload.Action;

            PeerEndpoint peerInfo;
            string peerName = _peers.TryGetValue(remotePeerId, out peerInfo)
                ? peerInfo.DisplayName
                : remotePeerId;

            string requestId = Guid.NewGuid().ToString("N").Substring(0, 12);
            _pendingConsents[requestId] = new ConsentRecord
            {
                RequestId = requestId,
                PeerId = remotePeerId,
                PeerName = peerName,
                Action = action,
                Filename = filename,
                Timestamp = GetUnixTimestamp(),
            };

            AddStatus("Peer " + peerName + " wants to " +
                      action.Replace("_", " ") + " '" + filename + "'", "warning");
            ConsentReceived?.Invoke(_pendingConsents[requestId]);
        }

        /// <summary>
        /// Handles an incoming CONSENT_RESPONSE (peer approved/denied our request).
        /// If approved and we have a pending outgoing file, sends it now.
        /// </summary>
        public void HandleConsentResponse(ConsentResponsePayload payload)
        {
            string remotePeerId = payload.PeerId;
            bool approved = payload.Approved;

            if (approved)
            {
                AddStatus("Peer " + remotePeerId + " approved the request", "success");

                // Find a pending outgoing file for this peer
                PendingSendInfo sendInfo = null;
                foreach (string key in _pendingOutgoing.Keys.ToArray())
                {
                    if (key.StartsWith(remotePeerId + ":"))
                    {
                        PendingSendInfo info;
                        if (_pendingOutgoing.TryRemove(key, out info))
                        {
                            sendInfo = info;
                            break;
                        }
                    }
                }

                if (sendInfo != null)
                {
                    SendFileToPeer(sendInfo);
                }
            }
            else
            {
                AddStatus("Peer " + remotePeerId + " denied the request", "warning");

                // Clean up pending outgoing
                foreach (string key in _pendingOutgoing.Keys.ToArray())
                {
                    if (key.StartsWith(remotePeerId + ":"))
                    {
                        PendingSendInfo removed;
                        _pendingOutgoing.TryRemove(key, out removed);
                        break;
                    }
                }

                // Mark pending transfers as denied
                lock (_transferLock)
                {
                    foreach (var t in _transfers)
                    {
                        if (t.PeerId == remotePeerId && t.Status == "pending")
                        {
                            t.Status = "denied";
                        }
                    }
                }
            }
        }

        // ================================================================
        //  Consent resolution (user clicks accept / deny in UI)
        // ================================================================

        /// <summary>
        /// Called when the local user approves a consent request.
        /// <list type="bullet">
        ///   <item>Buffered receive → saves the file encrypted at rest.</item>
        ///   <item>File request → encrypts and sends the file to the peer.</item>
        ///   <item>Consent offer → sends CONSENT_RESPONSE(approved) back.</item>
        /// </list>
        /// </summary>
        public void OnConsentApproved(string requestId)
        {
            ConsentRecord consent;
            _pendingConsents.TryRemove(requestId, out consent);

            // Case 1: Buffered file data waiting to be saved
            PendingReceiveInfo recvInfo;
            if (_pendingReceives.TryRemove(requestId, out recvInfo))
            {
                SaveReceivedFile(recvInfo.PeerId, recvInfo.Filename,
                                 recvInfo.FileData, recvInfo.FileHash);
                return;
            }

            // Case 2: Someone requested our file — send it
            PendingSendInfo sendInfo;
            if (_pendingOutgoing.TryRemove(requestId, out sendInfo))
            {
                SendFileToPeer(sendInfo);
                return;
            }

            // Case 3: Consent offer — peer wants to push a file to us.
            //         Send CONSENT_RESPONSE(approved) so they proceed.
            ResolvedConsent resolved;
            if (_resolvedConsents.TryRemove(requestId, out resolved))
            {
                PeerEndpoint peer;
                if (_peers.TryGetValue(resolved.PeerId, out peer) && peer.Online)
                {
                    string key = resolved.PeerId + ":" + resolved.Filename;
                    _approvedReceives[key] = 1;

                    try
                    {
                        var resp = new ConsentResponseMessage(new ConsentResponsePayload
                        {
                            PeerId = _peerId,
                            RequestId = requestId,
                            Approved = true,
                        });
                        SendToPeer(peer.Address, peer.Port, resp);
                        AddStatus("Approved receiving '" + resolved.Filename +
                                  "' from " + resolved.PeerId + ". Waiting for file…", "info");
                    }
                    catch (Exception ex)
                    {
                        AddStatus("Failed to send approval to " + resolved.PeerId +
                                  ": " + ex.Message, "error");
                    }
                }
            }
        }

        /// <summary>
        /// Called when the local user denies a consent request.
        /// Cleans up buffered data and sends denial back if needed.
        /// </summary>
        public void OnConsentDenied(string requestId)
        {
            ConsentRecord consent;
            _pendingConsents.TryRemove(requestId, out consent);

            // Clean up buffered file data
            PendingReceiveInfo recvRemoved;
            _pendingReceives.TryRemove(requestId, out recvRemoved);

            // Clean up pending sends
            PendingSendInfo sendRemoved;
            _pendingOutgoing.TryRemove(requestId, out sendRemoved);

            // Send CONSENT_RESPONSE(denied) back if this was a consent offer
            ResolvedConsent resolved;
            if (_resolvedConsents.TryRemove(requestId, out resolved))
            {
                PeerEndpoint peer;
                if (_peers.TryGetValue(resolved.PeerId, out peer) && peer.Online)
                {
                    try
                    {
                        var resp = new ConsentResponseMessage(new ConsentResponsePayload
                        {
                            PeerId = _peerId,
                            RequestId = requestId,
                            Approved = false,
                        });
                        SendToPeer(peer.Address, peer.Port, resp);
                    }
                    catch
                    {
                        // Best effort
                    }
                }
            }
        }

        // ================================================================
        //  Accessors (for UI / tests)
        // ================================================================

        /// <summary>Returns a snapshot of all pending consent requests.</summary>
        public IReadOnlyList<ConsentRecord> GetPendingConsents()
        {
            return _pendingConsents.Values.ToList().AsReadOnly();
        }

        /// <summary>Returns a snapshot of all transfer records.</summary>
        public IReadOnlyList<TransferRecord> GetTransfers()
        {
            lock (_transferLock)
            {
                return _transfers.ToList().AsReadOnly();
            }
        }

        /// <summary>Returns a snapshot of recent status messages.</summary>
        public IReadOnlyList<StatusEntry> GetStatusLog()
        {
            lock (_statusLock)
            {
                return _statusLog.ToList().AsReadOnly();
            }
        }

        // ================================================================
        //  Private helpers
        // ================================================================

        /// <summary>
        /// Checks whether the user already gave consent to receive this file
        /// (e.g. they initiated the request, or approved a push offer).
        /// </summary>
        private bool CheckPriorConsent(string peerId, string filename)
        {
            // Check 1: We have a pending transfer record (we requested it)
            lock (_transferLock)
            {
                foreach (var t in _transfers)
                {
                    if (t.Filename == filename && t.Status == "pending")
                        return true;
                }
            }

            // Check 2: We recently approved a consent offer from this peer
            string key = peerId + ":" + filename;
            byte removed;
            return _approvedReceives.TryRemove(key, out removed);
        }

        /// <summary>
        /// Encrypts received file data at rest using <see cref="LocalFileCrypto"/>
        /// (AES-256-GCM + PBKDF2-HMAC-SHA256) and saves to the received directory.
        /// </summary>
        private void SaveReceivedFile(string peerId, string filename,
                                      byte[] fileData, string actualHash)
        {
            string receivedDir = GetReceivedDir();
            string savePath = Path.Combine(receivedDir, filename);

            // Handle filename collisions
            if (File.Exists(savePath))
            {
                string name = Path.GetFileNameWithoutExtension(filename);
                string ext = Path.GetExtension(filename);
                string suffix = Guid.NewGuid().ToString("N").Substring(0, 6);
                savePath = Path.Combine(receivedDir, name + "_" + suffix + ext);
            }

            // Encrypt at rest: PBKDF2-HMAC-SHA256 → AES-256-GCM
            string encryptedPath = savePath + ".p2pf";
            LocalFileCrypto.EncryptToFile(fileData, _password, _userId, encryptedPath);

            // Update matching transfer records
            lock (_transferLock)
            {
                bool matched = false;
                foreach (var t in _transfers)
                {
                    if (t.Filename == filename && t.Status == "pending")
                    {
                        t.Status = "complete";
                        if (t.PeerId != peerId)
                        {
                            AddStatus("File '" + filename + "' originally requested from " +
                                      t.PeerId + " was served by " + peerId +
                                      " (cross-peer retrieval) ✓", "success");
                        }
                        matched = true;
                        break;
                    }
                }

                if (!matched)
                {
                    foreach (var t in _transfers)
                    {
                        if (t.Filename == filename && t.PeerId == peerId &&
                            t.Status == "pending")
                        {
                            t.Status = "complete";
                            break;
                        }
                    }
                }
            }

            AddStatus("Received '" + filename + "' (" + fileData.Length +
                      " bytes) from " + peerId +
                      ". Decrypted ✓ Hash verified ✓ Encrypted at rest ✓", "success");
        }

        /// <summary>
        /// Encrypts and sends a file to a peer over TCP.
        /// Steps: read file → encrypt with AES-256-GCM → send FILE_SEND.
        /// </summary>
        private void SendFileToPeer(PendingSendInfo info)
        {
            byte[] sessionKey;
            if (!_sessionKeys.TryGetValue(info.PeerId, out sessionKey))
            {
                AddStatus("Cannot send '" + info.Filename +
                          "': no active session with " + info.PeerId +
                          ". Handshake required.", "error");
                return;
            }

            try
            {
                // Read file
                byte[] fileData = File.ReadAllBytes(info.FilePath);

                // Encrypt: AES-256-GCM, AAD = "filename:hash"
                string encryptedBase64 = TransmissionCrypto.Encrypt(
                    sessionKey, fileData, info.Filename, info.FileHash);

                // Send FILE_SEND
                var msg = new FileSendMessage(new FileSendPayload
                {
                    PeerId = _peerId,
                    Filename = info.Filename,
                    FileHash = info.FileHash,
                    Data = encryptedBase64,
                });
                SendToPeer(info.Address, info.Port, msg);

                AddStatus("Sent '" + info.Filename + "' (" + fileData.Length +
                          " bytes, encrypted) to " + info.PeerId + " ✓", "success");
            }
            catch (Exception ex)
            {
                AddStatus("Failed to send '" + info.Filename + "' to " +
                          info.PeerId + ": " + ex.Message, "error");
            }
        }

        // ── Wire-level send (4-byte length prefix + JSON) ────────────

        /// <summary>
        /// Serializes a message to JSON, prepends a 4-byte big-endian length
        /// header, and sends to the peer over TCP (matching transport.py wire
        /// format).
        /// </summary>
        private void SendToPeer<TPayload>(string address, int port,
                                          jsonBody<TPayload> message)
            where TPayload : BasePayload
        {
            var serializer = new DataContractJsonSerializer(message.GetType());
            byte[] payload;
            using (var ms = new MemoryStream())
            {
                serializer.WriteObject(ms, message);
                payload = ms.ToArray();
            }

            // Big-endian 4-byte length header
            byte[] header = BitConverter.GetBytes(payload.Length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(header);

            using (var client = new TcpClient())
            {
                client.Connect(address, port);
                client.SendTimeout = DefaultTimeout;
                using (NetworkStream stream = client.GetStream())
                {
                    stream.Write(header, 0, header.Length);
                    stream.Write(payload, 0, payload.Length);
                    stream.Flush();
                }
            }
        }

        // ── Broadcast ─────────────────────────────────────────────────

        /// <summary>
        /// Sends a message to all online peers (used for REVOKE_KEY broadcast).
        /// </summary>
        public void BroadcastToAllPeers<TPayload>(jsonBody<TPayload> message)
            where TPayload : BasePayload
        {
            foreach (var kvp in _peers)
            {
                if (kvp.Key == _peerId || !kvp.Value.Online) continue;
                try
                {
                    SendToPeer(kvp.Value.Address, kvp.Value.Port, message);
                }
                catch { /* best-effort broadcast */ }
            }
        }

        /// <summary>
        /// Clears all session keys (used after key rotation).
        /// </summary>
        public void ClearAllSessionKeys()
        {
            _sessionKeys.Clear();
        }

        // ── Helpers ──────────────────────────────────────────────────

        private static string GetReceivedDir()
        {
            if (!Directory.Exists(ReceivedDir))
                Directory.CreateDirectory(ReceivedDir);
            return ReceivedDir;
        }

        private void AddStatus(string message, string level)
        {
            lock (_statusLock)
            {
                _statusLog.Add(new StatusEntry
                {
                    Message = message,
                    Level = level,
                    Timestamp = GetUnixTimestamp(),
                });

                // Keep only the last 50 messages
                if (_statusLog.Count > 50)
                    _statusLog.RemoveRange(0, _statusLog.Count - 50);
            }
        }

        private static double GetUnixTimestamp()
        {
            return (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
        }

        // ================================================================
        //  Internal data types
        // ================================================================

        internal class PeerEndpoint
        {
            public string PeerId { get; set; }
            public string DisplayName { get; set; }
            public string Address { get; set; }
            public int Port { get; set; }
            public bool Trusted { get; set; }
            public bool Online { get; set; }
        }

        internal class TransferRecord
        {
            public string TransferId { get; set; }
            public string Filename { get; set; }
            public string PeerId { get; set; }
            public string Direction { get; set; }
            public string Status { get; set; }
            public string Error { get; set; }
            public double Timestamp { get; set; }
        }

        internal class ConsentRecord
        {
            public string RequestId { get; set; }
            public string PeerId { get; set; }
            public string PeerName { get; set; }
            public string Action { get; set; }
            public string Filename { get; set; }
            public string FileHash { get; set; }
            public double Timestamp { get; set; }
        }

        internal class StatusEntry
        {
            public string Message { get; set; }
            public string Level { get; set; }
            public double Timestamp { get; set; }
        }

        internal class PendingSendInfo
        {
            public string PeerId { get; set; }
            public string Address { get; set; }
            public int Port { get; set; }
            public string Filename { get; set; }
            public string FileHash { get; set; }
            public string FilePath { get; set; }
        }

        internal class PendingReceiveInfo
        {
            public string PeerId { get; set; }
            public string Filename { get; set; }
            public byte[] FileData { get; set; }
            public string FileHash { get; set; }
        }

        internal class ResolvedConsent
        {
            public string PeerId { get; set; }
            public string Filename { get; set; }
        }

        /// <summary>
        /// Returned by the file lookup delegate to describe a locally available file.
        /// </summary>
        internal class LocalFileInfo
        {
            public string Filename { get; set; }
            public string FileHash { get; set; }
            public string FilePath { get; set; }
        }
    }
}
