namespace Firebase.Auth
{

    using System.Collections.Generic;
    using System.Text.Json.Serialization;

    /// <summary>
    /// More info at <see cref="https://developers.google.com/identity/toolkit/web/reference/relyingparty/createAuthUri"/>.
    /// </summary>
    public class ProviderQueryResult
    {
        public ProviderQueryResult()
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

        [JsonPropertyName("providerId")]
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public FirebaseAuthType? ProviderId
        {
            get;
            set;
        }

        [JsonPropertyName("allProviders")]
        [JsonConverter(typeof(JsonStringListOfEnumConverter<FirebaseAuthType>))]
        public List<FirebaseAuthType> Providers
        {
            get;
            set;
        }
    }
}
