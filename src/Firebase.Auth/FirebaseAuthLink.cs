using System;
using System.Threading.Tasks;

namespace Firebase.Auth
{

    /// <summary>
    /// The firebase auth which can be linked to another credentials.
    /// </summary>
    public class FirebaseAuthLink : FirebaseAuth
    {
        public FirebaseAuthLink() { }

        public FirebaseAuthLink(IFirebaseAuthProvider authProvider, FirebaseAuth auth) => CopyPropertiesLocally(authProvider, auth);

        public event EventHandler<FirebaseAuthEventArgs> FirebaseAuthRefreshed;

        internal IFirebaseAuthProvider AuthProvider { get; set; }

        /// <summary>
        /// Links the user with an email and password.  
        /// </summary>
        /// <param name="email"> The email. </param>
        /// <param name="password"> The password. </param>
        /// <returns> The <see cref="FirebaseAuthLink"/>. </returns>
        public async Task<FirebaseAuthLink> LinkToAsync(string email, string password)
        {
            var auth = await AuthProvider.LinkAccountsAsync(this, email, password).ConfigureAwait(false);

            CopyPropertiesLocally(auth.AuthProvider, auth);

            return this;
        }

        /// <summary>
        /// Links the user with an account from a third party provider.
        /// </summary> 
        /// <param name="authType"> The auth type.  </param>
        /// <param name="oauthAccessToken"> The access token retrieved from login provider of your choice. </param>
        /// <returns> The <see cref="FirebaseAuthLink"/>.  </returns>
        public async Task<FirebaseAuthLink> LinkToAsync(FirebaseAuthType authType, string oauthAccessToken)
        {
            var auth = await AuthProvider.LinkAccountsAsync(this, authType, oauthAccessToken).ConfigureAwait(false);

            CopyPropertiesLocally(auth.AuthProvider, auth);

            return this;
        }

        /// <summary>
        /// Unlinks the user from the given <see cref="authType"/> (provider).
        /// </summary> 
        /// <param name="authType"> The auth type.  </param>
        /// <returns> The <see cref="FirebaseAuthLink"/>.  </returns>
        public async Task<FirebaseAuthLink> UnlinkFromAsync(FirebaseAuthType authType)
        {
            var auth = await AuthProvider.UnlinkAccountsAsync(this, authType).ConfigureAwait(false);

            CopyPropertiesLocally(auth.AuthProvider, auth);

            return this;
        }

        public async Task RefreshUserDetails()
        {
            if (AuthProvider != null && !string.IsNullOrEmpty(FirebaseToken))
            {
                User = await AuthProvider.GetUserAsync(FirebaseToken).ConfigureAwait(false);
            }
        }

        public async Task<FirebaseAuthLink> GetFreshAuthAsync()
        {
            if (IsExpired())
            {
                var auth = await AuthProvider.RefreshAuthAsync(this).ConfigureAwait(false);
                CopyPropertiesLocally(auth.AuthProvider, auth);
                OnFirebaseAuthRefreshed(auth);
            }

            return this;
        }

        public async Task<FirebaseAuthLink> UpdateProfileAsync(string displayName, string photoUrl)
        {
            var auth = await AuthProvider.UpdateProfileAsync(FirebaseToken, displayName, photoUrl).ConfigureAwait(false);

            CopyPropertiesLocally(auth.AuthProvider, auth);

            return this;
        }

        protected void OnFirebaseAuthRefreshed(FirebaseAuth auth) => FirebaseAuthRefreshed?.Invoke(this, new FirebaseAuthEventArgs(auth));

        private void CopyPropertiesLocally(IFirebaseAuthProvider authProvider, FirebaseAuth auth)
        {
            AuthProvider = authProvider;

            if (auth != null)
            {
                User = auth.User;
                Created = auth.Created;
                ExpiresIn = auth.ExpiresIn;
                RefreshToken = auth.RefreshToken;
                FirebaseToken = auth.FirebaseToken;
            }
        }
    }
}
