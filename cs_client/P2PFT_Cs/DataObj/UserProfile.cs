using System.Runtime.Serialization;

namespace P2PFT_Cs.DataObj
{
    /// <summary>
    /// Serializable user profile stored encrypted on disk via <see cref="Utils.LocalFileCrypto"/>.
    /// Contains identity keys, credentials, and network info.
    /// </summary>
    [DataContract]
    internal class UserProfile
    {
        [DataMember(Name = "user_id")]
        public string UserId { get; set; }

        [DataMember(Name = "password_hash")]
        public string PasswordHash { get; set; }

        [DataMember(Name = "password_salt")]
        public string PasswordSalt { get; set; }

        /// <summary>RSA-2048 private key in PKCS#8 PEM format.</summary>
        [DataMember(Name = "private_key_pem")]
        public string PrivateKeyPem { get; set; }

        /// <summary>RSA-2048 public key in X.509/SPKI PEM format.</summary>
        [DataMember(Name = "public_key_pem")]
        public string PublicKeyPem { get; set; }

        /// <summary>SHA-256 fingerprint of the DER-encoded public key (lowercase hex).</summary>
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