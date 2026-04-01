using System.Collections.Generic;
using System.Runtime.Serialization;

namespace P2PFT_Cs.DataObj
{
    // ©¤©¤ Base Payload (shared peer_id across all messages) ©¤©¤©¤©¤©¤©¤©¤

    [DataContract]
    internal abstract class BasePayload
    {
        [DataMember(Name = "peer_id", IsRequired = true)]
        public string PeerId { get; set; }
    }

    // ©¤©¤ Peer Discovery ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤

    [DataContract]
    internal class PeerAnnouncePayload : BasePayload
    {
        [DataMember(Name = "port", IsRequired = true)]
        public int Port { get; set; }
    }

    [DataContract]
    internal class PeerListRequestPayload : BasePayload
    {
    }

    [DataContract]
    internal class PeerInfo
    {
        [DataMember(Name = "peer_id")]
        public string PeerId { get; set; }

        [DataMember(Name = "address")]
        public string Address { get; set; }

        [DataMember(Name = "port")]
        public int Port { get; set; }
    }

    [DataContract]
    internal class PeerListResponsePayload : BasePayload
    {
        [DataMember(Name = "peers", IsRequired = true)]
        public List<PeerInfo> Peers { get; set; }
    }

    // ©¤©¤ Key Exchange ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤

    [DataContract]
    internal class KeyExchangeInitPayload : BasePayload
    {
        [DataMember(Name = "ephemeral_public_key", IsRequired = true)]
        public string EphemeralPublicKey { get; set; }
    }

    [DataContract]
    internal class KeyExchangeResponsePayload : BasePayload
    {
        [DataMember(Name = "ephemeral_public_key", IsRequired = true)]
        public string EphemeralPublicKey { get; set; }

        [DataMember(Name = "long_term_public_key", IsRequired = true)]
        public string LongTermPublicKey { get; set; }

        [DataMember(Name = "signature", IsRequired = true)]
        public string Signature { get; set; }
    }

    [DataContract]
    internal class KeyExchangeConfirmPayload : BasePayload
    {
        [DataMember(Name = "long_term_public_key", IsRequired = true)]
        public string LongTermPublicKey { get; set; }

        [DataMember(Name = "signature", IsRequired = true)]
        public string Signature { get; set; }
    }

    // ©¤©¤ File Operations ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤

    [DataContract]
    internal class FileListRequestPayload : BasePayload
    {
    }

    [DataContract]
    internal class FileInfo
    {
        [DataMember(Name = "filename")]
        public string Filename { get; set; }

        [DataMember(Name = "file_hash")]
        public string FileHash { get; set; }

        [DataMember(Name = "size")]
        public long Size { get; set; }
    }

    [DataContract]
    internal class FileListResponsePayload : BasePayload
    {
        [DataMember(Name = "files", IsRequired = true)]
        public List<FileInfo> Files { get; set; }
    }

    [DataContract]
    internal class FileRequestPayload : BasePayload
    {
        [DataMember(Name = "filename", IsRequired = true)]
        public string Filename { get; set; }

        [DataMember(Name = "file_hash", IsRequired = true)]
        public string FileHash { get; set; }
    }

    [DataContract]
    internal class FileSendPayload : BasePayload
    {
        [DataMember(Name = "filename", IsRequired = true)]
        public string Filename { get; set; }

        [DataMember(Name = "file_hash", IsRequired = true)]
        public string FileHash { get; set; }

        /// <summary>
        /// Base64-encoded AES-256-GCM encrypted file data.
        /// </summary>
        [DataMember(Name = "data", IsRequired = true)]
        public string Data { get; set; }
    }

    // ©¤©¤ Consent ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤

    [DataContract]
    internal class ConsentRequestPayload : BasePayload
    {
        [DataMember(Name = "action", IsRequired = true)]
        public string Action { get; set; }

        [DataMember(Name = "filename", IsRequired = true)]
        public string Filename { get; set; }
    }

    [DataContract]
    internal class ConsentResponsePayload : BasePayload
    {
        [DataMember(Name = "request_id", IsRequired = true)]
        public string RequestId { get; set; }

        [DataMember(Name = "approved", IsRequired = true)]
        public bool Approved { get; set; }
    }

    // ©¤©¤ Key Revocation ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤

    [DataContract]
    internal class RevokeKeyPayload : BasePayload
    {
        [DataMember(Name = "new_public_key", IsRequired = true)]
        public string NewPublicKey { get; set; }
    }

    // ©¤©¤ Error ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤

    [DataContract]
    internal class ErrorPayload : BasePayload
    {
        [DataMember(Name = "code", IsRequired = true)]
        public int Code { get; set; }

        [DataMember(Name = "description", IsRequired = true)]
        public string Description { get; set; }
    }
}