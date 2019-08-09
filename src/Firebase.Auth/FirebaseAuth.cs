namespace Firebase.Auth
{
    using System;
    using System.Text.Json.Serialization;

    /// <summary>
    /// The firebase auth.
    /// </summary>
    public class FirebaseAuth
    {
        public FirebaseAuth()
        {
            this.Created = DateTime.Now;
        }

        /// <summary>
        /// Gets or sets the firebase token which can be used for authenticated queries. 
        /// </summary>
        [JsonPropertyName("idToken")]
        public string FirebaseToken
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the refresh token of the underlying service which can be used to get a new access token. 
        /// </summary>
        [JsonPropertyName("refreshToken")]
        public string RefreshToken
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the numbers of seconds since <see cref="Created"/> when the token expires.
        /// </summary>
        [JsonPropertyName("expiresIn")]
        public int ExpiresIn
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets when this token was created.
        /// </summary>
        public DateTime Created
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the user.
        /// </summary>
        public User User
        {
            get;
            set;
        }

        /// <summary>
        /// Specifies whether the token already expired. 
        /// </summary>
        public bool IsExpired()
        {
            // include a small 10s window when the token is technically valid but it's a good idea to refresh it already.
            return DateTime.Now > this.Created.AddSeconds(this.ExpiresIn - 10); 
        }
    }
}