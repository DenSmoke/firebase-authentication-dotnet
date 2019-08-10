using System;
using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Firebase.Auth
{

    /// <summary>
    /// The auth token provider.
    /// </summary>
    public class FirebaseAuthProvider : IDisposable, IFirebaseAuthProvider
    {
        private const string GoogleRefreshAuth = "https://securetoken.googleapis.com/v1/token?key={0}";
        private const string GoogleCustomAuthUrl = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key={0}";
        private const string GoogleGetUser = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo?key={0}";
        private const string GoogleIdentityUrl = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyAssertion?key={0}";
        private const string GoogleSignUpUrl = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser?key={0}";
        private const string GooglePasswordUrl = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key={0}";
        private const string GoogleDeleteUserUrl = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/deleteAccount?key={0}";
        private const string GoogleGetConfirmationCodeUrl = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode?key={0}";
        private const string GoogleSetAccountUrl = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/setAccountInfo?key={0}";
        private const string GoogleCreateAuthUrl = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/createAuthUri?key={0}";

        private const string ProfileDeleteDisplayName = "DISPLAY_NAME";
        private const string ProfileDeletePhotoUrl = "PHOTO_URL";

        private readonly FirebaseConfig authConfig;
        private readonly HttpClient client;

        /// <summary>
        /// Initializes a new instance of the <see cref="FirebaseAuthProvider"/> class.
        /// </summary>
        /// <param name="authConfig"> The auth config. </param>
        public FirebaseAuthProvider(FirebaseConfig authConfig)
        {
            this.authConfig = authConfig;
            client = new HttpClient();
        }


        /// <summary>
        /// Disposes all allocated resources. 
        /// </summary>
        public void Dispose() => client.Dispose();

        /// <summary>
        /// Sign in with a custom token. You would usually create and sign such a token on your server to integrate with your existing authentiocation system.
        /// </summary>
        /// <param name="customToken"> The access token retrieved from login provider of your choice. </param>
        /// <returns> The <see cref="FirebaseAuth"/>. </returns>
        public async Task<FirebaseAuthLink> SignInWithCustomTokenAsync(string customToken)
        {
            var content = $"{{\"token\":\"{customToken}\",\"returnSecureToken\":true}}";
            var firebaseAuthLink = await ExecuteWithPostContentAsync(GoogleCustomAuthUrl, content).ConfigureAwait(false);
            firebaseAuthLink.User = await GetUserAsync(firebaseAuthLink.FirebaseToken).ConfigureAwait(false);
            return firebaseAuthLink;
        }

        /// <summary>
        /// Using the idToken of an authenticated user, get the details of the user's account
        /// </summary>
        /// <param name="firebaseToken"> The FirebaseToken (idToken) of an authenticated user. </param>
        /// <returns> The <see cref="User"/>. </returns>
        public async Task<User> GetUserAsync(string firebaseToken)
        {
            var content = $"{{\"idToken\":\"{firebaseToken}\"}}";
            var responseData = "N/A";
            try
            {
                using var response = await client.PostAsync(new Uri(string.Format(GoogleGetUser, authConfig.ApiKey)), new StringContent(content, Encoding.UTF8, "application/json")).ConfigureAwait(false);
                responseData = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                response.EnsureSuccessStatusCode();

                var resultJson = JsonDocument.Parse(responseData);
                var user = JsonSerializer.Deserialize<User>(resultJson.RootElement.GetProperty("users").ToString());
                return user;
            }
            catch (Exception ex)
            {
                var errorReason = GetFailureReason(responseData);
                throw new FirebaseAuthException(GoogleDeleteUserUrl, content, responseData, ex, errorReason);
            }
        }

        /// <summary>
        /// Sends user an email with a link to verify his email address.
        /// </summary>
        /// <param name="auth"> The authenticated user to verify email address. </param>
        public async Task<User> GetUserAsync(FirebaseAuth auth) => await GetUserAsync(auth.FirebaseToken).ConfigureAwait(false);

        /// <summary>
        /// Using the provided access token from third party auth provider (google, facebook...), get the firebase auth with token and basic user credentials.
        /// </summary>
        /// <param name="authType"> The auth type. </param>
        /// <param name="oauthAccessToken"> The access token retrieved from login provider of your choice. </param>
        /// <returns> The <see cref="FirebaseAuth"/>. </returns>
        public async Task<FirebaseAuthLink> SignInWithOAuthAsync(FirebaseAuthType authType, string oauthAccessToken)
        {
            var providerId = GetProviderId(authType);
            var content = $"{{\"postBody\":\"access_token={oauthAccessToken}&providerId={providerId}\",\"requestUri\":\"http://localhost\",\"returnSecureToken\":true}}";

            return await ExecuteWithPostContentAsync(GoogleIdentityUrl, content).ConfigureAwait(false);
        }

        /// <summary>
        /// Using the provided Id token from google signin, get the firebase auth with token and basic user credentials.
        /// </summary>
        /// <param name="authType"> The auth type. </param>
        /// <param name="idToken"> The Id token retrieved from google signin </param>
        /// <returns> The <see cref="FirebaseAuth"/>. </returns>
        public async Task<FirebaseAuthLink> SignInWithGoogleIdTokenAsync(string idToken)
        {
            var providerId = GetProviderId(FirebaseAuthType.Google);
            var content = $"{{\"postBody\":\"id_token={idToken}&providerId={providerId}\",\"requestUri\":\"http://localhost\",\"returnSecureToken\":true}}";

            return await ExecuteWithPostContentAsync(GoogleIdentityUrl, content).ConfigureAwait(false);
        }

        /// <summary>
        /// Sign in user anonymously. He would still have a user id and access token generated, but name and other personal user properties will be null.
        /// </summary>
        /// <returns> The <see cref="FirebaseAuth"/>. </returns>
        public async Task<FirebaseAuthLink> SignInAnonymouslyAsync()
        {
            var content = $"{{\"returnSecureToken\":true}}";

            return await ExecuteWithPostContentAsync(GoogleSignUpUrl, content).ConfigureAwait(false);
        }

        /// <summary>
        /// Using the provided email and password, get the firebase auth with token and basic user credentials.
        /// </summary>
        /// <param name="email"> The email. </param>
        /// <param name="password"> The password. </param>
        /// <returns> The <see cref="FirebaseAuth"/>. </returns>
        public async Task<FirebaseAuthLink> SignInWithEmailAndPasswordAsync(string email, string password)
        {
            var content = $"{{\"email\":\"{email}\",\"password\":\"{password}\",\"returnSecureToken\":true}}";

            return await ExecuteWithPostContentAsync(GooglePasswordUrl, content).ConfigureAwait(false);
        }

        /// <summary>
        /// Creates new user with given credentials.
        /// </summary>
        /// <param name="email"> The email. </param>
        /// <param name="password"> The password. </param>
        /// <param name="displayName"> Optional display name. </param>
        /// <param name="sendVerificationEmail"> Optional. Whether to send user a link to verfiy his email address. </param>
        /// <returns> The <see cref="FirebaseAuth"/>. </returns>
        public async Task<FirebaseAuthLink> CreateUserWithEmailAndPasswordAsync(string email, string password, string displayName = "", bool sendVerificationEmail = false)
        {
            var content = $"{{\"email\":\"{email}\",\"password\":\"{password}\",\"returnSecureToken\":true}}";

            var signup = await ExecuteWithPostContentAsync(GoogleSignUpUrl, content).ConfigureAwait(false);

            if (!string.IsNullOrWhiteSpace(displayName))
            {
                // set display name
                content = $"{{\"displayName\":\"{displayName}\",\"idToken\":\"{signup.FirebaseToken}\",\"returnSecureToken\":true}}";

                await ExecuteWithPostContentAsync(GoogleSetAccountUrl, content).ConfigureAwait(false);

                signup.User.DisplayName = displayName;
            }

            if (sendVerificationEmail)
            {
                //send verification email
                await SendEmailVerificationAsync(signup).ConfigureAwait(false);
            }

            return signup;
        }

        /// <summary>
        /// Updates profile (displayName and photoUrl) of user tied to given user token.
        /// </summary>
        /// <param name="displayName"> The new display name. </param>
        /// <param name="photoUrl"> The new photo URL. </param>
        /// <returns> The <see cref="FirebaseAuthLink"/>. </returns>
        public async Task<FirebaseAuthLink> UpdateProfileAsync(string firebaseToken, string displayName, string photoUrl)
        {
            var sb = new StringBuilder($"{{\"idToken\":\"{firebaseToken}\"");
            if (!string.IsNullOrWhiteSpace(displayName) && !string.IsNullOrWhiteSpace(photoUrl))
            {
                sb.Append($",\"displayName\":\"{displayName}\",\"photoUrl\":\"{photoUrl}\"");
            }
            else if (!string.IsNullOrWhiteSpace(displayName))
            {
                sb.Append($",\"displayName\":\"{displayName}\"");
                sb.Append($",\"deleteAttribute\":[\"{ProfileDeletePhotoUrl}\"]");
            }
            else if (!string.IsNullOrWhiteSpace(photoUrl))
            {
                sb.Append($",\"photoUrl\":\"{photoUrl}\"");
                sb.Append($",\"deleteAttribute\":[\"{ProfileDeleteDisplayName}\"]");
            }
            else
            {
                sb.Append($",\"deleteAttribute\":[\"{ProfileDeleteDisplayName}\",\"{ProfileDeletePhotoUrl}\"]");
            }

            sb.Append($",\"returnSecureToken\":true}}");

            return await ExecuteWithPostContentAsync(GoogleSetAccountUrl, sb.ToString()).ConfigureAwait(false);
        }

        /// <summary>
        /// Deletes the user with a recent Firebase Token.
        /// </summary>
        /// <param name="token"> Recent Firebase Token. </param>
        public async Task DeleteUserAsync(string firebaseToken)
        {
            var content = $"{{ \"idToken\": \"{firebaseToken}\" }}";
            var responseData = "N/A";

            try
            {
                using var response = await client.PostAsync(new Uri(string.Format(GoogleDeleteUserUrl, authConfig.ApiKey)), new StringContent(content, Encoding.UTF8, "application/json")).ConfigureAwait(false);
                responseData = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                response.EnsureSuccessStatusCode();
            }
            catch (Exception ex)
            {
                var errorReason = GetFailureReason(responseData);
                throw new FirebaseAuthException(GoogleDeleteUserUrl, content, responseData, ex, errorReason);
            }
        }

        /// <summary>
        /// Sends user an email with a link to reset his password.
        /// </summary>
        /// <param name="email"> The email. </param>
        public async Task SendPasswordResetEmailAsync(string email)
        {
            var content = $"{{\"requestType\":\"PASSWORD_RESET\",\"email\":\"{email}\"}}";

            using var response = await client.PostAsync(new Uri(string.Format(GoogleGetConfirmationCodeUrl, authConfig.ApiKey)), new StringContent(content, Encoding.UTF8, "application/json")).ConfigureAwait(false);

            response.EnsureSuccessStatusCode();
        }

        /// <summary>
        /// Sends user an email with a link to verify his email address.
        /// </summary>
        /// <param name="firebaseToken"> The FirebaseToken (idToken) of an authenticated user. </param>
        public async Task SendEmailVerificationAsync(string firebaseToken)
        {
            var content = $"{{\"requestType\":\"VERIFY_EMAIL\",\"idToken\":\"{firebaseToken}\"}}";

            using var response = await client.PostAsync(new Uri(string.Format(GoogleGetConfirmationCodeUrl, authConfig.ApiKey)), new StringContent(content, Encoding.UTF8, "application/json")).ConfigureAwait(false);

            response.EnsureSuccessStatusCode();
        }

        /// <summary>
        /// Sends user an email with a link to verify his email address.
        /// </summary>
        /// <param name="auth"> The authenticated user to verify email address. </param>
        public async Task SendEmailVerificationAsync(FirebaseAuth auth) => await SendEmailVerificationAsync(auth.FirebaseToken).ConfigureAwait(false);

        /// <summary>
        /// Links the given <see cref="firebaseToken"/> with an email and password. 
        /// </summary>
        /// <param name="firebaseToken"> The FirebaseToken (idToken) of an authenticated user. </param>
        /// <param name="email"> The email. </param>
        /// <param name="password"> The password. </param>
        /// <returns> The <see cref="FirebaseAuthLink"/>. </returns>
        public async Task<FirebaseAuthLink> LinkAccountsAsync(string firebaseToken, string email, string password)
        {
            var content = $"{{\"idToken\":\"{firebaseToken}\",\"email\":\"{email}\",\"password\":\"{password}\",\"returnSecureToken\":true}}";

            return await ExecuteWithPostContentAsync(GoogleSetAccountUrl, content).ConfigureAwait(false);
        }

        /// <summary>
        /// Links the authenticated user represented by <see cref="auth"/> with an email and password. 
        /// </summary>
        /// <param name="auth"> The authenticated user to link with specified email and password. </param>
        /// <param name="email"> The email. </param>
        /// <param name="password"> The password. </param>
        /// <returns> The <see cref="FirebaseAuthLink"/>. </returns>
        public async Task<FirebaseAuthLink> LinkAccountsAsync(FirebaseAuth auth, string email, string password) => await LinkAccountsAsync(auth.FirebaseToken, email, password).ConfigureAwait(false);

        /// <summary>
        /// Links the given <see cref="firebaseToken"/> with an account from a third party provider.
        /// </summary>
        /// <param name="firebaseToken"> The FirebaseToken (idToken) of an authenticated user. </param>
        /// <param name="authType"> The auth type.  </param>
        /// <param name="oauthAccessToken"> The access token retrieved from login provider of your choice. </param>
        /// <returns> The <see cref="FirebaseAuthLink"/>.  </returns>
        public async Task<FirebaseAuthLink> LinkAccountsAsync(string firebaseToken, FirebaseAuthType authType, string oauthAccessToken)
        {
            var providerId = GetProviderId(authType);
            var content = $"{{\"idToken\":\"{firebaseToken}\",\"postBody\":\"access_token={oauthAccessToken}&providerId={providerId}\",\"requestUri\":\"http://localhost\",\"returnSecureToken\":true}}";

            return await ExecuteWithPostContentAsync(GoogleIdentityUrl, content).ConfigureAwait(false);
        }

        /// <summary>
        /// Links the authenticated user represented by <see cref="auth"/> with an account from a third party provider.
        /// </summary>
        /// <param name="auth"> The auth. </param>
        /// <param name="authType"> The auth type.  </param>
        /// <param name="oauthAccessToken"> The access token retrieved from login provider of your choice. </param>
        /// <returns> The <see cref="FirebaseAuthLink"/>.  </returns>
        public async Task<FirebaseAuthLink> LinkAccountsAsync(FirebaseAuth auth, FirebaseAuthType authType, string oauthAccessToken) => await LinkAccountsAsync(auth.FirebaseToken, authType, oauthAccessToken).ConfigureAwait(false);

        /// <summary>
        /// Unlinks the given <see cref="authType"/> from the account associated with <see cref="firebaseToken"/>.
        /// </summary>
        /// <param name="firebaseToken"> The FirebaseToken (idToken) of an authenticated user. </param>
        /// <param name="authType"> The auth type.  </param>
        /// <returns> The <see cref="FirebaseAuthLink"/>.  </returns>
        public async Task<FirebaseAuthLink> UnlinkAccountsAsync(string firebaseToken, FirebaseAuthType authType)
        {
            var providerId = authType == FirebaseAuthType.EmailAndPassword ? authType.ToEnumString() : GetProviderId(authType);

            var content = $"{{\"idToken\":\"{firebaseToken}\",\"deleteProvider\":[\"{providerId}\"]}}";

            return await ExecuteWithPostContentAsync(GoogleSetAccountUrl, content).ConfigureAwait(false);
        }

        /// <summary>
        /// Unlinks the given <see cref="authType"/> from the authenticated user represented by <see cref="auth"/>.
        /// </summary>
        /// <param name="auth"> The auth. </param>
        /// <param name="authType"> The auth type.  </param>
        /// <returns> The <see cref="FirebaseAuthLink"/>.  </returns>
        public async Task<FirebaseAuthLink> UnlinkAccountsAsync(FirebaseAuth auth, FirebaseAuthType authType) => await UnlinkAccountsAsync(auth.FirebaseToken, authType).ConfigureAwait(false);

        /// <summary>
        /// Gets a list of accounts linked to given email.
        /// </summary>
        /// <param name="email"> Email address. </param>
        /// <returns> The <see cref="ProviderQueryResult"/></returns>
        public async Task<ProviderQueryResult> GetLinkedAccountsAsync(string email)
        {
            var content = $"{{\"identifier\":\"{email}\", \"continueUri\": \"http://localhost\"}}";
            var responseData = "N/A";

            try
            {
                using var response = await client.PostAsync(new Uri(string.Format(GoogleCreateAuthUrl, authConfig.ApiKey)), new StringContent(content, Encoding.UTF8, "application/json")).ConfigureAwait(false);
                responseData = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                response.EnsureSuccessStatusCode();

                var options = new JsonSerializerOptions();
                options.Converters.Add(new JsonStringListOfEnumConverter<FirebaseAuthType>());
                var data = JsonSerializer.Deserialize<ProviderQueryResult>(responseData, options);
                data.Email = email;

                return data;
            }
            catch (Exception ex)
            {
                throw new FirebaseAuthException(GoogleCreateAuthUrl, content, responseData, ex);
            }
        }

        public async Task<FirebaseAuthLink> RefreshAuthAsync(FirebaseAuth auth)
        {
            var content = $"grant_type=refresh_token&refresh_token={auth.RefreshToken}";
            var responseData = "N/A";

            try
            {
                using var response = await client.PostAsync(new Uri(string.Format(GoogleRefreshAuth, authConfig.ApiKey)), new StringContent(content, Encoding.UTF8, "application/x-www-form-urlencoded")).ConfigureAwait(false);

                responseData = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                var refreshAuth = JsonSerializer.Deserialize<RefreshAuth>(responseData);

                return new FirebaseAuthLink
                {
                    AuthProvider = this,
                    User = auth.User,
                    ExpiresIn = refreshAuth.ExpiresIn,
                    RefreshToken = refreshAuth.RefreshToken,
                    FirebaseToken = refreshAuth.AccessToken
                };
            }
            catch (Exception ex)
            {
                throw new FirebaseAuthException(GoogleRefreshAuth, content, responseData, ex);
            }
        }

        private async Task<FirebaseAuthLink> ExecuteWithPostContentAsync(string googleUrl, string postContent)
        {
            var responseData = "N/A";

            try
            {
                using var response = await client.PostAsync(new Uri(string.Format(googleUrl, authConfig.ApiKey)), new StringContent(postContent, Encoding.UTF8, "application/json")).ConfigureAwait(false);
                responseData = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                response.EnsureSuccessStatusCode();

                var user = JsonSerializer.Deserialize<User>(responseData);
                var auth = JsonSerializer.Deserialize<FirebaseAuthLink>(responseData);

                auth.AuthProvider = this;
                auth.User = user;

                return auth;
            }
            catch (Exception ex)
            {
                var errorReason = GetFailureReason(responseData);
                throw new FirebaseAuthException(googleUrl, postContent, responseData, ex, errorReason);
            }
        }

        /// <summary>
        /// Resolves failure reason flags based on the returned error code.
        /// </summary>
        /// <remarks>Currently only provides support for failed email auth flags.</remarks>
        private static AuthErrorReason GetFailureReason(string responseData)
        {
            var failureReason = AuthErrorReason.Undefined;
            try
            {
                if (!string.IsNullOrEmpty(responseData) && responseData != "N/A")
                {
                    //create error data template and try to parse JSON
                    /*var errorData = new { error = new { code = 0, message = "errorid" } };
                    errorData = JsonConvert.DeserializeAnonymousType(responseData, errorData);*/

                    var errorData = JsonDocument.Parse(responseData);
                    //errorData is just null if different JSON was received
                    switch (errorData.RootElement.GetProperty("error").GetProperty("message").GetString())
                    {
                        //general errors
                        case "invalid access_token, error code 43.":
                            failureReason = AuthErrorReason.InvalidAccessToken;
                            break;

                        case "CREDENTIAL_TOO_OLD_LOGIN_AGAIN":
                            failureReason = AuthErrorReason.LoginCredentialsTooOld;
                            break;

                        //possible errors from Third Party Authentication using GoogleIdentityUrl
                        case "INVALID_PROVIDER_ID : Provider Id is not supported.":
                            failureReason = AuthErrorReason.InvalidProviderID;
                            break;
                        case "MISSING_REQUEST_URI":
                            failureReason = AuthErrorReason.MissingRequestURI;
                            break;
                        case "A system error has occurred - missing or invalid postBody":
                            failureReason = AuthErrorReason.SystemError;
                            break;

                        //possible errors from Email/Password Account Signup (via signupNewUser or setAccountInfo) or Signin
                        case "INVALID_EMAIL":
                            failureReason = AuthErrorReason.InvalidEmailAddress;
                            break;
                        case "MISSING_PASSWORD":
                            failureReason = AuthErrorReason.MissingPassword;
                            break;

                        //possible errors from Email/Password Account Signup (via signupNewUser or setAccountInfo)
                        case "WEAK_PASSWORD : Password should be at least 6 characters":
                            failureReason = AuthErrorReason.WeakPassword;
                            break;
                        case "EMAIL_EXISTS":
                            failureReason = AuthErrorReason.EmailExists;
                            break;

                        //possible errors from Account Delete
                        case "USER_NOT_FOUND":
                            failureReason = AuthErrorReason.UserNotFound;
                            break;

                        //possible errors from Email/Password Signin
                        case "INVALID_PASSWORD":
                            failureReason = AuthErrorReason.WrongPassword;
                            break;
                        case "EMAIL_NOT_FOUND":
                            failureReason = AuthErrorReason.UnknownEmailAddress;
                            break;
                        case "USER_DISABLED":
                            failureReason = AuthErrorReason.UserDisabled;
                            break;

                        //possible errors from Email/Password Signin or Password Recovery or Email/Password Sign up using setAccountInfo
                        case "MISSING_EMAIL":
                            failureReason = AuthErrorReason.MissingEmail;
                            break;

                        //possible errors from Password Recovery
                        case "MISSING_REQ_TYPE":
                            failureReason = AuthErrorReason.MissingRequestType;
                            break;

                        //possible errors from Account Linking
                        case "INVALID_ID_TOKEN":
                            failureReason = AuthErrorReason.InvalidIDToken;
                            break;

                        //possible errors from Getting Linked Accounts
                        case "INVALID_IDENTIFIER":
                            failureReason = AuthErrorReason.InvalidIdentifier;
                            break;
                        case "MISSING_IDENTIFIER":
                            failureReason = AuthErrorReason.MissingIdentifier;
                            break;
                        case "FEDERATED_USER_ID_ALREADY_LINKED":
                            failureReason = AuthErrorReason.AlreadyLinked;
                            break;
                    }
                }
            }
            catch (JsonException)
            {
                //the response wasn't JSON - no data to be parsed
            }
            catch (Exception e)
            {
                Debug.WriteLine($"Unexpected error trying to parse the response: {e}");
            }

            return failureReason;
        }


        private string GetProviderId(FirebaseAuthType authType)
        {
            switch (authType)
            {
                case FirebaseAuthType.Facebook:
                case FirebaseAuthType.Google:
                case FirebaseAuthType.Github:
                case FirebaseAuthType.Twitter:
                    return authType.ToEnumString();
                case FirebaseAuthType.EmailAndPassword:
                    throw new InvalidOperationException("Email auth type cannot be used like this. Use methods specific to email & password authentication.");
                default:
                    throw new NotImplementedException("");
            }
        }
    }
}
