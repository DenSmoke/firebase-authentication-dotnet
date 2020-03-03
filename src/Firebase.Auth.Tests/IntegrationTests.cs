using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Firebase.Auth.Tests
{
    public class IntegrationTests
    {
        private static readonly IServiceProvider _serviceProvider = new ServiceCollection()
            .AddSingleton<IConfiguration>(new ConfigurationBuilder().AddJsonFile("config.json").Build())
            .AddHttpClient()
            .AddTransient<IFirebaseAuthProvider, FirebaseAuthProvider>(x =>
            {
                var config = x.GetRequiredService<IConfiguration>();
                var apiKey = config.GetValue<string>("ApiKey");
                return new FirebaseAuthProvider(apiKey, x.GetRequiredService<IHttpClientFactory>());
            })
            .BuildServiceProvider();
        private static readonly IConfiguration _config = _serviceProvider.GetRequiredService<IConfiguration>();
#pragma warning disable IDE1006
        private readonly string FacebookAccessToken = _config.GetValue<string>(nameof(FacebookAccessToken));
        private readonly string FacebookTestUserFirstName = _config.GetValue<string>(nameof(FacebookTestUserFirstName));
        private readonly string GoogleAccessToken = _config.GetValue<string>(nameof(GoogleAccessToken));
        private readonly string GoogleTestUserFirstName = _config.GetValue<string>(nameof(GoogleTestUserFirstName));
        private readonly string FirebaseEmail = _config.GetValue<string>(nameof(FirebaseEmail));
        private readonly string FirebasePassword = _config.GetValue<string>(nameof(FirebasePassword));
        private readonly string NewFirebaseEmail = _config.GetValue<string>(nameof(NewFirebaseEmail));
        private readonly string NewFirebasePassword = _config.GetValue<string>(nameof(NewFirebasePassword));
        private readonly string FirebaseDisplayName = _config.GetValue<string>(nameof(FirebaseDisplayName));
        private readonly string RecaptchaToken = _config.GetValue<string>(nameof(RecaptchaToken));
        private readonly string FirebaseDelevoperTestPhone = _config.GetValue<string>(nameof(FirebaseDelevoperTestPhone));
        private readonly string FirebasePhoneVerificationCode = _config.GetValue<string>(nameof(FirebasePhoneVerificationCode));
#pragma warning restore IDE1006

        public IFirebaseAuthProvider AuthProvider => _serviceProvider.GetRequiredService<IFirebaseAuthProvider>();

        [Fact]
        public async Task FacebookTest()
        {
            var auth = await AuthProvider.SignInWithOAuthAsync(FirebaseAuthType.Facebook, FacebookAccessToken).ConfigureAwait(false);

            Assert.Equal(FacebookTestUserFirstName, auth.User.FirstName);
            Assert.False(string.IsNullOrWhiteSpace(auth.FirebaseToken));
        }

        [Fact]
        public async Task GoogleTest()
        {
            var auth = await AuthProvider.SignInWithOAuthAsync(FirebaseAuthType.Google, GoogleAccessToken).ConfigureAwait(false);

            Assert.Equal(GoogleTestUserFirstName, auth.User.FirstName);
            Assert.False(string.IsNullOrWhiteSpace(auth.FirebaseToken));
        }

        [Fact]
        public async Task EmailTest()
        {
            var auth = await AuthProvider.SignInWithEmailAndPasswordAsync(FirebaseEmail, FirebasePassword).ConfigureAwait(false);

            Assert.Equal(FirebaseEmail, auth.User.Email);
            Assert.False(string.IsNullOrWhiteSpace(auth.FirebaseToken));
        }

        [Fact]
        public async Task UnknownEmailAddressShouldBeReflectedByFailureReason()
        {
            var exception = await Assert.ThrowsAsync<FirebaseAuthException>(() => AuthProvider.SignInWithEmailAndPasswordAsync("someinvalidaddressxxx@foo.com", FirebasePassword)).ConfigureAwait(false);
            Assert.Equal(AuthErrorReason.UnknownEmailAddress, exception.Reason);
        }

        [Fact]
        public async Task InvalidEmailAddressFormatShouldBeReflectedByFailureReason()
        {
            var exception = await Assert.ThrowsAsync<FirebaseAuthException>(() => AuthProvider.SignInWithEmailAndPasswordAsync("notanemailaddress", FirebasePassword)).ConfigureAwait(false);
            Assert.Equal(AuthErrorReason.InvalidEmailAddress, exception.Reason);
        }

        [Fact]
        public async Task InvalidPasswordShouldBeReflectedByFailureReason()
        {
            var exception = await Assert.ThrowsAsync<FirebaseAuthException>(() => AuthProvider.SignInWithEmailAndPasswordAsync(FirebaseEmail, "xx" + FirebasePassword)).ConfigureAwait(false);
            Assert.Equal(AuthErrorReason.WrongPassword, exception.Reason);
        }

        [Fact]
        public async Task CreateUserTest()
        {
            var auth = await AuthProvider.CreateUserWithEmailAndPasswordAsync(NewFirebaseEmail, NewFirebasePassword).ConfigureAwait(false);

            try
            {
                Assert.Equal(NewFirebaseEmail, auth.User.Email);
                Assert.False(string.IsNullOrWhiteSpace(auth.FirebaseToken));
            }
            finally
            {
                await AuthProvider.DeleteUserAsync(auth.FirebaseToken).ConfigureAwait(false);
            }
        }

        [Fact]
        public async Task LinkAccountsTest()
        {
            var auth = await AuthProvider.SignInAnonymouslyAsync().ConfigureAwait(false);
            try
            {
                var newAuth = await auth.LinkToAsync(NewFirebaseEmail, NewFirebasePassword).ConfigureAwait(false);

                Assert.Equal(NewFirebaseEmail, newAuth.User.Email);
                Assert.Equal(auth.User.LocalId, newAuth.User.LocalId);
                Assert.False(string.IsNullOrWhiteSpace(newAuth.FirebaseToken));
            }
            finally
            {
                await AuthProvider.DeleteUserAsync(auth.FirebaseToken).ConfigureAwait(false);
            }
        }

        [Fact]
        public async Task LinkAccountsFacebookTest()
        {
            var auth = await AuthProvider.SignInAnonymouslyAsync().ConfigureAwait(false);
            try
            {
                var newAuth = await auth.LinkToAsync(FirebaseAuthType.Facebook, FacebookAccessToken).ConfigureAwait(false);

                Assert.Equal(auth.User.LocalId, newAuth.User.LocalId);
                Assert.Equal(FacebookTestUserFirstName, newAuth.User.FirstName);
                Assert.False(string.IsNullOrWhiteSpace(newAuth.FirebaseToken));
            }
            finally
            {
                await AuthProvider.DeleteUserAsync(auth.FirebaseToken).ConfigureAwait(false);
            }
        }

        [Fact]
        public async Task GetLinkedAccountsTest()
        {
            var auth = await AuthProvider.CreateUserWithEmailAndPasswordAsync(NewFirebaseEmail, NewFirebasePassword).ConfigureAwait(false);
            try
            {
                var linkedAccounts = await AuthProvider.GetLinkedAccountsAsync(NewFirebaseEmail).ConfigureAwait(false);

                Assert.True(linkedAccounts.IsRegistered);
                Assert.Equal(FirebaseAuthType.EmailAndPassword, linkedAccounts.Providers.Single());
            }
            finally
            {
                await AuthProvider.DeleteUserAsync(auth.FirebaseToken).ConfigureAwait(false);
            }
        }

        [Fact]
        public async Task RefreshAccessToken()
        {
            var auth = await AuthProvider.SignInWithEmailAndPasswordAsync(FirebaseEmail, FirebasePassword).ConfigureAwait(false);

            var originalToken = auth.FirebaseToken;

            // simulate the token already expired
            auth.Created = DateTime.MinValue;

            var freshAuth = await auth.GetFreshAuthAsync().ConfigureAwait(false);

            //Disabled because Firebase doesn't send new ID token every time for some reason
            //Assert.NotEqual(originalToken, freshAuth.FirebaseToken);

            Assert.False(string.IsNullOrWhiteSpace(freshAuth.FirebaseToken));
        }

        [Fact]
        public async Task GetUserTest()
        {
            var auth = await AuthProvider.SignInWithEmailAndPasswordAsync(FirebaseEmail, FirebasePassword).ConfigureAwait(false);
            var user = await AuthProvider.GetUserAsync(auth).ConfigureAwait(false);

            Assert.True(user.IsEmailVerified);
            Assert.Equal(FirebaseDisplayName, user.DisplayName);

            var newUserDisplayName = "test";
            auth = await AuthProvider.CreateUserWithEmailAndPasswordAsync(NewFirebaseEmail, NewFirebasePassword, newUserDisplayName);
            try
            {
                user = await AuthProvider.GetUserAsync(auth).ConfigureAwait(false);
                Assert.False(user.IsEmailVerified);
                Assert.Equal(newUserDisplayName, user.DisplayName);
            }
            finally
            {
                await AuthProvider.DeleteUserAsync(auth.FirebaseToken).ConfigureAwait(false);
            }
        }

        [Fact]
        public async Task SigninWithPhoneAsync()
        {
            var sessionInfo = await AuthProvider.SendVerificationCodeAsync(FirebaseDelevoperTestPhone, RecaptchaToken).ConfigureAwait(false);

            Assert.False(string.IsNullOrEmpty(sessionInfo));

            var authUserInfo = await AuthProvider.SignInWithPhoneAsync(sessionInfo, FirebasePhoneVerificationCode).ConfigureAwait(false);

            Assert.NotNull(authUserInfo);
            Assert.NotNull(authUserInfo.User);
        }

        [Fact]
        public async Task SendPasswordResetEmailAsyncTest()
        {
            var newUserDisplayName = "test";
            var auth = await AuthProvider.CreateUserWithEmailAndPasswordAsync(NewFirebaseEmail, NewFirebasePassword, newUserDisplayName);
            try
            {
                await AuthProvider.SendPasswordResetEmailAsync(NewFirebaseEmail).ConfigureAwait(false);
            }
            finally
            {
                await AuthProvider.DeleteUserAsync(auth.FirebaseToken).ConfigureAwait(false);
            }
        }
    }
}
