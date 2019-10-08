using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
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
#pragma warning disable IDE1006 // Стили именования
        private const string GoogleRefreshAuth = "https://securetoken.googleapis.com/v1/token?key={0}";
        private const string GoogleCustomAuthUrl = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={0}";
        private const string GoogleGetUser = "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={0}";
        private const string GoogleIdentityUrl = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key={0}";
        private const string GoogleSignUpUrl = "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={0}";
        private const string GooglePasswordUrl = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={0}";
        private const string GoogleDeleteUserUrl = "https://identitytoolkit.googleapis.com/v1/accounts:delete?key={0}";
        private const string GoogleGetConfirmationCodeUrl = "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={0}";
        private const string GoogleSetAccountUrl = "https://identitytoolkit.googleapis.com/v1/accounts:update?key={0}";
        private const string GoogleCreateAuthUrl = "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key={0}";
        private const string GoogleUpdateUserPassword = "https://identitytoolkit.googleapis.com/v1/accounts:update?key={0}";

        private const string ProfileDeleteDisplayName = "DISPLAY_NAME";
        private const string ProfileDeletePhotoUrl = "PHOTO_URL";

        private const string ApplicationJsonMimeType = "application/json";
        private const string ApplicationUrlEncodedMimeType = "application/x-www-form-urlencoded";
#pragma warning restore IDE1006 // Стили именования

        private readonly FirebaseConfig _authConfig;
        private HttpClient _httpClient;

        private readonly Version _defaultHttpVersion = RuntimeInformation.FrameworkDescription.Contains(".NET Framework") ? new Version(1, 1) : new Version(2, 0);

        /// <summary>
        /// Initializes a new instance of the <see cref="FirebaseAuthProvider"/> class.
        /// </summary>
        /// <param name="authConfig"> The auth config. </param>
        public FirebaseAuthProvider(FirebaseConfig authConfig)
        {
            _authConfig = authConfig;
            _httpClient = new HttpClient();
        }


        /// <summary>
        /// Disposes all allocated resources. 
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                // free managed resources
                if (_httpClient != null)
                {
                    _httpClient.Dispose();
                    _httpClient = null;
                }
            }
        }

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
        /// <returns> The <see cref="FirebaseUser"/>. </returns>
        public async Task<FirebaseUser> GetUserAsync(string firebaseToken)
        {
            var content = $"{{\"idToken\":\"{firebaseToken}\"}}";
            JsonDocument responseJson = default;
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(string.Format(CultureInfo.InvariantCulture, GoogleGetUser, _authConfig.ApiKey)))
                {
                    Content = new StringContent(content, Encoding.UTF8, ApplicationJsonMimeType),
                    Version = _defaultHttpVersion
                };
                using var response = await _httpClient.SendAsync(request).ConfigureAwait(false);
                using var responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                responseJson = await JsonDocument.ParseAsync(responseStream).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
                using var ms = new MemoryStream();
                using var utf8JsonWriter = new Utf8JsonWriter(ms);
                responseJson.RootElement.GetProperty("users").WriteTo(utf8JsonWriter);
                await utf8JsonWriter.FlushAsync().ConfigureAwait(false);
                ms.Seek(0, SeekOrigin.Begin);
                var user = (await JsonSerializer.DeserializeAsync<IEnumerable<FirebaseUser>>(ms).ConfigureAwait(false)).Single();
                return user;
            }
            catch (Exception ex)
            {
                var errorReason = GetFailureReason(responseJson);
                throw new FirebaseAuthException(GoogleGetUser, content, responseJson?.RootElement.ToString(), ex, errorReason);
            }
            finally
            {
                responseJson?.Dispose();
            }
        }

        /// <summary>
        /// Sends user an email with a link to verify his email address.
        /// </summary>
        /// <param name="auth"> The authenticated user to verify email address. </param>
        public async Task<FirebaseUser> GetUserAsync(FirebaseAuth auth) => await GetUserAsync(auth?.FirebaseToken).ConfigureAwait(false);

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
        ///     Change user's password with his token.
        /// </summary>
        /// <param name="firebaseToken"> The FirebaseToken (idToken) of an authenticated user. </param>
        /// <param name="password"> The new password. </param>
        /// <returns> The <see cref="FirebaseAuthLink"/>. </returns>
        public async Task<FirebaseAuthLink> ChangeUserPasswordAsync(string firebaseToken, string password)
        {
            var content = $"{{\"idToken\":\"{firebaseToken}\",\"password\":\"{password}\",\"returnSecureToken\":true}}";

            return await ExecuteWithPostContentAsync(GoogleUpdateUserPassword, content).ConfigureAwait(false);
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

            JsonDocument responseJson = default;
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(string.Format(CultureInfo.InvariantCulture, GoogleDeleteUserUrl, _authConfig.ApiKey)))
                {
                    Content = new StringContent(content, Encoding.UTF8, ApplicationJsonMimeType),
                    Version = _defaultHttpVersion
                };
                using var response = await _httpClient.SendAsync(request).ConfigureAwait(false);
                using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                responseJson = await JsonDocument.ParseAsync(stream).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
            }
            catch (Exception ex)
            {
                var errorReason = GetFailureReason(responseJson);
                throw new FirebaseAuthException(GoogleDeleteUserUrl, content, responseJson?.RootElement.ToString(), ex, errorReason);
            }
            finally
            {
                responseJson?.Dispose();
            }
        }

        /// <summary>
        /// Sends user an email with a link to reset his password.
        /// </summary>
        /// <param name="email"> The email. </param>
        public async Task SendPasswordResetEmailAsync(string email)
        {
            var content = $"{{\"requestType\":\"PASSWORD_RESET\",\"email\":\"{email}\"}}";

            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(string.Format(CultureInfo.InvariantCulture, GoogleGetConfirmationCodeUrl, _authConfig.ApiKey)))
            {
                Content = new StringContent(content, Encoding.UTF8, ApplicationJsonMimeType),
                Version = _defaultHttpVersion
            };
            using var response = await _httpClient.SendAsync(request).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
        }

        /// <summary>
        /// Sends user an email with a link to verify his email address.
        /// </summary>
        /// <param name="firebaseToken"> The FirebaseToken (idToken) of an authenticated user. </param>
        public async Task SendEmailVerificationAsync(string firebaseToken)
        {
            var content = $"{{\"requestType\":\"VERIFY_EMAIL\",\"idToken\":\"{firebaseToken}\"}}";

            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(string.Format(CultureInfo.InvariantCulture, GoogleGetConfirmationCodeUrl, _authConfig.ApiKey)))
            {
                Content = new StringContent(content, Encoding.UTF8, ApplicationJsonMimeType),
                Version = _defaultHttpVersion
            };
            using var response = await _httpClient.SendAsync(request).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
        }

        /// <summary>
        /// Sends user an email with a link to verify his email address.
        /// </summary>
        /// <param name="auth"> The authenticated user to verify email address. </param>
        public async Task SendEmailVerificationAsync(FirebaseAuth auth) => await SendEmailVerificationAsync(auth?.FirebaseToken).ConfigureAwait(false);

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
        public async Task<FirebaseAuthLink> LinkAccountsAsync(FirebaseAuth auth, string email, string password) => await LinkAccountsAsync(auth?.FirebaseToken, email, password).ConfigureAwait(false);

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
        public async Task<FirebaseAuthLink> LinkAccountsAsync(FirebaseAuth auth, FirebaseAuthType authType, string oauthAccessToken) => await LinkAccountsAsync(auth?.FirebaseToken, authType, oauthAccessToken).ConfigureAwait(false);

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
        public async Task<FirebaseAuthLink> UnlinkAccountsAsync(FirebaseAuth auth, FirebaseAuthType authType) => await UnlinkAccountsAsync(auth?.FirebaseToken, authType).ConfigureAwait(false);

        /// <summary>
        /// Gets a list of accounts linked to given email.
        /// </summary>
        /// <param name="email"> Email address. </param>
        /// <returns> The <see cref="ProviderQueryResult"/></returns>
        public async Task<ProviderQueryResult> GetLinkedAccountsAsync(string email)
        {
            var content = $"{{\"identifier\":\"{email}\", \"continueUri\": \"http://localhost\"}}";
            string responseString = null;
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(string.Format(CultureInfo.InvariantCulture, GoogleCreateAuthUrl, _authConfig.ApiKey)))
                {
                    Content = new StringContent(content, Encoding.UTF8, ApplicationJsonMimeType),
                    Version = _defaultHttpVersion
                };
                using var response = await _httpClient.SendAsync(request).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    responseString = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    response.EnsureSuccessStatusCode();
                }

                using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                var options = new JsonSerializerOptions();
                options.Converters.Add(new JsonStringListOfEnumConverter<FirebaseAuthType>());
                var data = await JsonSerializer.DeserializeAsync<ProviderQueryResult>(stream, options).ConfigureAwait(false);
                data.Email = email;

                return data;
            }
            catch (Exception ex)
            {
                throw new FirebaseAuthException(GoogleCreateAuthUrl, content, responseString, ex);
            }
        }

        public async Task<FirebaseAuthLink> RefreshAuthAsync(FirebaseAuth auth)
        {
            var content = $"grant_type=refresh_token&refresh_token={auth?.RefreshToken}";
            JsonDocument responseJson = default;
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(string.Format(CultureInfo.InvariantCulture, GoogleRefreshAuth, _authConfig.ApiKey)))
                {
                    Content = new StringContent(content, Encoding.UTF8, ApplicationUrlEncodedMimeType),
                    Version = _defaultHttpVersion
                };
                using var response = await _httpClient.SendAsync(request).ConfigureAwait(false);
                using var responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                responseJson = await JsonDocument.ParseAsync(responseStream).ConfigureAwait(false);
                var refreshAuth = responseJson.RootElement;
                response.EnsureSuccessStatusCode();
                return new FirebaseAuthLink
                {
                    AuthProvider = this,
                    User = auth.User,
                    ExpiresIn = Convert.ToInt32(refreshAuth.GetProperty("expires_in").GetString(), CultureInfo.InvariantCulture),
                    RefreshToken = refreshAuth.GetProperty("refresh_token").GetString(),
                    FirebaseToken = refreshAuth.GetProperty("id_token").GetString(),
                };
            }
            catch (Exception ex)
            {
                throw new FirebaseAuthException(GoogleRefreshAuth, content, responseJson?.RootElement.ToString(), ex);
            }
            finally
            {
                responseJson?.Dispose();
            }
        }

        private async Task<FirebaseAuthLink> ExecuteWithPostContentAsync(string googleUrl, string postContent)
        {
            JsonDocument responseJson = default;
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(string.Format(CultureInfo.InvariantCulture, googleUrl, _authConfig.ApiKey)))
                {
                    Content = new StringContent(postContent, Encoding.UTF8, ApplicationJsonMimeType),
                    Version = _defaultHttpVersion
                };
                using var response = await _httpClient.SendAsync(request).ConfigureAwait(false);
                using var responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    responseJson = await JsonDocument.ParseAsync(responseStream).ConfigureAwait(false);
                    response.EnsureSuccessStatusCode();
                }

                var user = await JsonSerializer.DeserializeAsync<FirebaseUser>(responseStream).ConfigureAwait(false);
                responseStream.Seek(0, SeekOrigin.Begin);
                var auth = await JsonSerializer.DeserializeAsync<FirebaseAuthLink>(responseStream).ConfigureAwait(false);

                auth.AuthProvider = this;
                auth.User = user;

                return auth;
            }
            catch (Exception ex)
            {
                var errorReason = GetFailureReason(responseJson);
                throw new FirebaseAuthException(googleUrl, postContent, responseJson?.RootElement.ToString(), ex, errorReason);
            }
            finally
            {
                responseJson?.Dispose();
            }
        }

        /// <summary>
        /// Resolves failure reason flags based on the returned error code.
        /// </summary>
        /// <remarks>Currently only provides support for failed email auth flags.</remarks>
        private static AuthErrorReason GetFailureReason(JsonDocument responseJson)
        {
            string errorCode = null;
            try
            {
                errorCode = responseJson?.RootElement
                    .GetProperty("error")
                    .GetProperty("message")
                    .GetString();
            }
            catch (JsonException) { }

            return errorCode switch
            {
                //general errors
                "invalid access_token, error code 43." => AuthErrorReason.InvalidAccessToken,
                "CREDENTIAL_TOO_OLD_LOGIN_AGAIN" => AuthErrorReason.LoginCredentialsTooOld,
                //possible errors from Third Party Authentication using GoogleIdentityUrl
                "INVALID_PROVIDER_ID : Provider Id is not supported." => AuthErrorReason.InvalidProviderID,
                "MISSING_REQUEST_URI" => AuthErrorReason.MissingRequestURI,
                "A system error has occurred - missing or invalid postBody" => AuthErrorReason.SystemError,
                //possible errors from Email/Password Account Signup (via signupNewUser or setAccountInfo) or Signin
                "INVALID_EMAIL" => AuthErrorReason.InvalidEmailAddress,
                "MISSING_PASSWORD" => AuthErrorReason.MissingPassword,
                //possible errors from Email/Password Account Signup (via signupNewUser or setAccountInfo)
                "WEAK_PASSWORD : Password should be at least 6 characters" => AuthErrorReason.WeakPassword,
                "EMAIL_EXISTS" => AuthErrorReason.EmailExists,
                //possible errors from Account Delete
                "USER_NOT_FOUND" => AuthErrorReason.UserNotFound,
                //possible errors from Email/Password Signin
                "INVALID_PASSWORD" => AuthErrorReason.WrongPassword,
                "EMAIL_NOT_FOUND" => AuthErrorReason.UnknownEmailAddress,
                "USER_DISABLED" => AuthErrorReason.UserDisabled,
                //possible errors from Email/Password Signin or Password Recovery or Email/Password Sign up using setAccountInfo
                "MISSING_EMAIL" => AuthErrorReason.MissingEmail,
                //possible errors from Password Recovery
                "MISSING_REQ_TYPE" => AuthErrorReason.MissingRequestType,
                //possible errors from Account Linking
                "INVALID_ID_TOKEN" => AuthErrorReason.InvalidIDToken,
                //possible errors from Getting Linked Accounts
                "INVALID_IDENTIFIER" => AuthErrorReason.InvalidIdentifier,
                "MISSING_IDENTIFIER" => AuthErrorReason.MissingIdentifier,
                "FEDERATED_USER_ID_ALREADY_LINKED" => AuthErrorReason.AlreadyLinked,
                _ => AuthErrorReason.Undefined,
            };
        }

        private static string GetProviderId(FirebaseAuthType authType)
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
