using System.Runtime.Serialization;

namespace P2PFT_Cs.DataObj
{

    [DataContract]
    internal class PeerAnnounceMessage : jsonBody<PeerAnnouncePayload>
    {
        public PeerAnnounceMessage(PeerAnnouncePayload payload)
            : base("PEER_ANNOUNCE", payload) { }
    }

    [DataContract]
    internal class PeerListRequestMessage : jsonBody<PeerListRequestPayload>
    {
        public PeerListRequestMessage(PeerListRequestPayload payload)
            : base("PEER_LIST_REQUEST", payload) { }
    }

    [DataContract]
    internal class PeerListResponseMessage : jsonBody<PeerListResponsePayload>
    {
        public PeerListResponseMessage(PeerListResponsePayload payload)
            : base("PEER_LIST_RESPONSE", payload) { }
    }

 
    [DataContract]
    internal class KeyExchangeInitMessage : jsonBody<KeyExchangeInitPayload>
    {
        public KeyExchangeInitMessage(KeyExchangeInitPayload payload)
            : base("KEY_EXCHANGE_INIT", payload) { }
    }

    [DataContract]
    internal class KeyExchangeResponseMessage : jsonBody<KeyExchangeResponsePayload>
    {
        public KeyExchangeResponseMessage(KeyExchangeResponsePayload payload)
            : base("KEY_EXCHANGE_RESPONSE", payload) { }
    }

    [DataContract]
    internal class KeyExchangeConfirmMessage : jsonBody<KeyExchangeConfirmPayload>
    {
        public KeyExchangeConfirmMessage(KeyExchangeConfirmPayload payload)
            : base("KEY_EXCHANGE_CONFIRM", payload) { }
    }


    [DataContract]
    internal class FileListRequestMessage : jsonBody<FileListRequestPayload>
    {
        public FileListRequestMessage(FileListRequestPayload payload)
            : base("FILE_LIST_REQUEST", payload) { }
    }

    [DataContract]
    internal class FileListResponseMessage : jsonBody<FileListResponsePayload>
    {
        public FileListResponseMessage(FileListResponsePayload payload)
            : base("FILE_LIST_RESPONSE", payload) { }
    }

    [DataContract]
    internal class FileRequestMessage : jsonBody<FileRequestPayload>
    {
        public FileRequestMessage(FileRequestPayload payload)
            : base("FILE_REQUEST", payload) { }
    }

    [DataContract]
    internal class FileSendMessage : jsonBody<FileSendPayload>
    {
        public FileSendMessage(FileSendPayload payload)
            : base("FILE_SEND", payload) { }
    }

    // Consent

    [DataContract]
    internal class ConsentRequestMessage : jsonBody<ConsentRequestPayload>
    {
        public ConsentRequestMessage(ConsentRequestPayload payload)
            : base("CONSENT_REQUEST", payload) { }
    }

    [DataContract]
    internal class ConsentResponseMessage : jsonBody<ConsentResponsePayload>
    {
        public ConsentResponseMessage(ConsentResponsePayload payload)
            : base("CONSENT_RESPONSE", payload) { }
    }

    // Key Revocation
    [DataContract]
    internal class RevokeKeyMessage : jsonBody<RevokeKeyPayload>
    {
        public RevokeKeyMessage(RevokeKeyPayload payload)
            : base("REVOKE_KEY", payload) { }
    }

    // Verification

    [DataContract]
    internal class VerifyConfirmMessage : jsonBody<VerifyConfirmPayload>
    {
        public VerifyConfirmMessage(VerifyConfirmPayload payload)
            : base("VERIFY_CONFIRM", payload) { }
    }

    [DataContract]
    internal class VerifyRejectMessage : jsonBody<VerifyRejectPayload>
    {
        public VerifyRejectMessage(VerifyRejectPayload payload)
            : base("VERIFY_REJECT", payload) { }
    }

    //Error

    [DataContract]
    internal class ErrorMessage : jsonBody<ErrorPayload>
    {
        public ErrorMessage(ErrorPayload payload)
            : base("ERROR", payload) { }
    }
}
