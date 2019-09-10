using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Firebase.Auth
{

    /// <summary>
    /// More info at <see cref="https://developers.google.com/identity/toolkit/web/reference/relyingparty/createAuthUri"/>.
    /// </summary>
    public class ProviderQueryResult
    {
        public ProviderQueryResult() => Providers = new List<FirebaseAuthType>();

        public string Email { get; set; }

        [JsonPropertyName("registered")]
        public bool IsRegistered { get; set; }

        [JsonPropertyName("allProviders")]
        public List<FirebaseAuthType> Providers { get; set; }
    }
}
