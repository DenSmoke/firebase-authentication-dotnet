using System.Text.Json.Serialization;

namespace Firebase.Auth
{

    internal class RefreshAuth
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }

        [JsonPropertyName("expires_in")]
        [JsonConverter(typeof(JsonStringIntConverter))]
        public int ExpiresIn { get; set; }

        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; }
    }
}
