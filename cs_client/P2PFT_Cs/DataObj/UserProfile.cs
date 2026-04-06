using System.Runtime.Serialization;

namespace P2PFT_Cs.DataObj
{

    /// Serializable user profile stored encrypted on disk via <see cref="Utils.LocalFileCrypto"/>.
    /// Contains identity keys, credentials, and network info.

    [DataContract]
    internal class UserProfile
    {
        [DataMember(Name = "user_id")]
        public string UserId { get; set; }

        [DataMember(Name = "password_hash")]
        public string PasswordHash { get; set; }

        [DataMember(Name = "password_salt")]
        public string PasswordSalt { get; set; }


        [DataMember(Name = "private_key_pem")]
        public string PrivateKeyPem { get; set; }


        [DataMember(Name = "public_key_pem")]
        public string PublicKeyPem { get; set; }

  
        [DataMember(Name = "fingerprint")]
        public string Fingerprint { get; set; }

        [DataMember(Name = "ip_address")]
        public string IpAddress { get; set; }

        [DataMember(Name = "port")]
        public int Port { get; set; }

        [DataMember(Name = "created_utc")]
        public string CreatedUtc { get; set; }
    }
}