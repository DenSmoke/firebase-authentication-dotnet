using System.ComponentModel;
using System.Text.Json.Serialization;

namespace Firebase.Auth
{

    /// <summary>
    /// Basic information about the logged in user.
    /// </summary>
    public class FirebaseUser
    {
        /// <summary>
        /// Gets or sets the local id.
        /// </summary>
        [JsonPropertyName("localId")]
        [DefaultValue("")]
        public string LocalId { get; set; }

        /// <summary>
        /// Gets or sets the federated id.
        /// </summary>
        [JsonPropertyName("federatedId")]
        [DefaultValue("")]
        public string FederatedId { get; set; }

        /// <summary>
        /// Gets or sets the first name.
        /// </summary>
        [JsonPropertyName("firstName")]
        [DefaultValue("")]
        public string FirstName { get; set; }

        /// <summary>
        /// Gets or sets the last name.
        /// </summary>
        [JsonPropertyName("lastName")]
        [DefaultValue("")]
        public string LastName { get; set; }

        /// <summary>
        /// Gets or sets the display name.
        /// </summary>
        [JsonPropertyName("displayName")]
        [DefaultValue("")]
        public string DisplayName { get; set; }

        /// <summary>
        /// Gets or sets the email.
        /// </summary>
        [JsonPropertyName("email")]
        [DefaultValue("")]
        public string Email { get; set; }

        /// <summary>
        /// Gets or sets the email verfication status.
        /// </summary>
        [JsonPropertyName("emailVerified")]
        [DefaultValue(false)]
        public bool IsEmailVerified { get; set; }

        /// <summary>
        /// Gets or sets the photo url.
        /// </summary>
        [JsonPropertyName("photoUrl")]
        [DefaultValue("")]
        public string PhotoUrl { get; set; }

        /// <summary>
        /// Gets or sets the phone number.
        /// </summary>
        [JsonPropertyName("phoneNumber")]
        [DefaultValue("")]
        public string PhoneNumber { get; set; }
    }
}
