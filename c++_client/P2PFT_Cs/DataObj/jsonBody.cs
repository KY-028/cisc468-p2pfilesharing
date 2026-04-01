using System;
using System.Runtime.Serialization;

namespace P2PFT_Cs.DataObj
{
    [DataContract]
    internal abstract class jsonBody<TPayload> where TPayload : BasePayload
    {
        [DataMember(Name = "version", IsRequired = true)]
        public string Version { get; set; } = "1.0";

        [DataMember(Name = "type", IsRequired = true)]
        public string Type { get; set; }

        [DataMember(Name = "timestamp", IsRequired = true)]
        public double Timestamp { get; set; }

        [DataMember(Name = "payload", IsRequired = true)]
        public TPayload Payload { get; set; }

        protected jsonBody(string messageType, TPayload payload)
        {
            Type = messageType ?? throw new ArgumentNullException(nameof(messageType));
            Payload = payload ?? throw new ArgumentNullException(nameof(payload));
            Timestamp = (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
        }

        /// <summary>
        /// Validates that all required fields are present and well-formed.
        /// </summary>
        public virtual void Validate()
        {
            if (string.IsNullOrWhiteSpace(Version))
                throw new InvalidOperationException("Version is required.");

            if (string.IsNullOrWhiteSpace(Type))
                throw new InvalidOperationException("Type is required.");

            if (Timestamp <= 0)
                throw new InvalidOperationException("Timestamp must be a positive value.");

            if (Payload == null)
                throw new InvalidOperationException("Payload is required.");

            if (string.IsNullOrWhiteSpace(Payload.PeerId))
                throw new InvalidOperationException("Payload.PeerId is required.");
        }
    }
}
