namespace Firebase.Auth
{

    using System.Collections.Generic;
    using System.Text.Json.Serialization;

    /// <summary>
    /// More info at <see cref="https://developers.google.com/identity/toolkit/web/reference/relyingparty/createAuthUri"/>.
    /// </summary>
    public class ProviderQueryResult
    {
        internal ProviderQueryResult()
        {
            this.Providers = new List<FirebaseAuthType>();
        }

        public string Email
        {
            get;
            set;
        }

        [JsonPropertyName("registered")]
        public bool IsRegistered
        {
            get;
            set;
        }

        [JsonPropertyName("forExistingProvider")]
        public bool IsForExistingProvider
        {
            get;
            set;
        }

        [JsonPropertyName("authUri")]
        public string AuthUri
        {
            get;
            set;
        }

        [JsonConverter(typeof(JsonStringEnumConverter))]
        [JsonPropertyName("providerId")]
        public FirebaseAuthType? ProviderId
        {
            get;
            set;
        }

        [JsonPropertyName("allProviders")]
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public List<FirebaseAuthType> Providers
        {
            get;
            set;
        }
    }
}
