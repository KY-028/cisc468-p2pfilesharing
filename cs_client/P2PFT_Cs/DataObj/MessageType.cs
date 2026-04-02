namespace P2PFT_Cs.DataObj
{
    internal static class MessageType
    {
        public const string PeerAnnounce        = "PEER_ANNOUNCE";
        public const string PeerListRequest     = "PEER_LIST_REQUEST";
        public const string PeerListResponse    = "PEER_LIST_RESPONSE";
        public const string KeyExchangeInit     = "KEY_EXCHANGE_INIT";
        public const string KeyExchangeResponse = "KEY_EXCHANGE_RESPONSE";
        public const string KeyExchangeConfirm  = "KEY_EXCHANGE_CONFIRM";
        public const string FileListRequest     = "FILE_LIST_REQUEST";
        public const string FileListResponse    = "FILE_LIST_RESPONSE";
        public const string FileRequest         = "FILE_REQUEST";
        public const string FileSend            = "FILE_SEND";
        public const string ConsentRequest      = "CONSENT_REQUEST";
        public const string ConsentResponse     = "CONSENT_RESPONSE";
        public const string RevokeKey           = "REVOKE_KEY";
        public const string Error               = "ERROR";
    }
}