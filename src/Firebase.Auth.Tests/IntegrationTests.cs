namespace Firebase.Auth.Tests
{
    using System;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Configuration;
    using Xunit;

    public class IntegrationTests
    {
        private static IConfigurationRoot config = new ConfigurationBuilder().AddJsonFile("config.json").Build();
#pragma warning disable IDE1006
        private readonly string ApiKey = config.GetValue<string>(nameof(ApiKey));
        private readonly string FacebookAccessToken = config.GetValue<string>(nameof(FacebookAccessToken));
        private readonly string FacebookTestUserFirstName = config.GetValue<string>(nameof(FacebookTestUserFirstName));
        private readonly string GoogleAccessToken = config.GetValue<string>(nameof(GoogleAccessToken));
        private readonly string GoogleTestUserFirstName = config.GetValue<string>(nameof(GoogleTestUserFirstName));
        private readonly string FirebaseEmail = config.GetValue<string>(nameof(FirebaseEmail));
        private readonly string FirebasePassword = config.GetValue<string>(nameof(FirebasePassword));
        private readonly string NewFirebaseEmail = config.GetValue<string>(nameof(NewFirebaseEmail));
        private readonly string NewFirebasePassword = config.GetValue<string>(nameof(NewFirebasePassword));
#pragma warning restore IDE1006

        [Fact]
        public async Task FacebookTest()
        {
            using var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));

            var auth = await authProvider.SignInWithOAuthAsync(FirebaseAuthType.Facebook, FacebookAccessToken).ConfigureAwait(false);

            Assert.Equal(FacebookTestUserFirstName, auth.User.FirstName);
            Assert.False(string.IsNullOrWhiteSpace(auth.FirebaseToken));
        }

        [Fact]
        public async Task GoogleTest()
        {
            using var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));

            var auth = await authProvider.SignInWithOAuthAsync(FirebaseAuthType.Google, GoogleAccessToken).ConfigureAwait(false);

            Assert.Equal(GoogleTestUserFirstName, auth.User.FirstName);
            Assert.False(string.IsNullOrWhiteSpace(auth.FirebaseToken));
        }

        [Fact]
        public async Task EmailTest()
        {
            using var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));

            var auth = await authProvider.SignInWithEmailAndPasswordAsync(FirebaseEmail, FirebasePassword).ConfigureAwait(false);

            Assert.Equal(FirebaseEmail, auth.User.Email);
            Assert.False(string.IsNullOrWhiteSpace(auth.FirebaseToken));
        }

        [Fact]
        public async Task UnknownEmailAddressShouldBeReflectedByFailureReason()
        {
            using var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));
            var exception = await Assert.ThrowsAsync<FirebaseAuthException>(() => authProvider.SignInWithEmailAndPasswordAsync("someinvalidaddressxxx@foo.com", FirebasePassword)).ConfigureAwait(false);
            Assert.Equal(AuthErrorReason.UnknownEmailAddress, exception.Reason);
        }

        [Fact]
        public async Task InvalidEmailAddressFormatShouldBeReflectedByFailureReason()
        {
            using var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));
            var exception = await Assert.ThrowsAsync<FirebaseAuthException>(() => authProvider.SignInWithEmailAndPasswordAsync("notanemailaddress", FirebasePassword)).ConfigureAwait(false);
            Assert.Equal(AuthErrorReason.InvalidEmailAddress, exception.Reason);
        }

        [Fact]
        public async Task InvalidPasswordShouldBeReflectedByFailureReason()
        {
            using var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));
            var exception = await Assert.ThrowsAsync<FirebaseAuthException>(() => authProvider.SignInWithEmailAndPasswordAsync(FirebaseEmail, "xx" + FirebasePassword)).ConfigureAwait(false);
            Assert.Equal(AuthErrorReason.WrongPassword, exception.Reason);
        }

        [Fact]
        public async Task CreateUserTest()
        {
            using var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));
            var auth = await authProvider.CreateUserWithEmailAndPasswordAsync(NewFirebaseEmail, NewFirebasePassword).ConfigureAwait(false);

            try
            {
                Assert.Equal(NewFirebaseEmail, auth.User.Email);
                Assert.False(string.IsNullOrWhiteSpace(auth.FirebaseToken));
            }
            finally
            {
                await authProvider.DeleteUserAsync(auth.FirebaseToken).ConfigureAwait(false);
            }
        }

        [Fact]
        public async Task LinkAccountsTest()
        {
            using var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));

            var auth = await authProvider.SignInAnonymouslyAsync().ConfigureAwait(false);
            try
            {
                var newAuth = await auth.LinkToAsync(NewFirebaseEmail, NewFirebasePassword).ConfigureAwait(false);

                Assert.Equal(NewFirebaseEmail, newAuth.User.Email);
                Assert.Equal(auth.User.LocalId, newAuth.User.LocalId);
                Assert.False(string.IsNullOrWhiteSpace(newAuth.FirebaseToken));
            }
            finally
            {
                await authProvider.DeleteUserAsync(auth.FirebaseToken).ConfigureAwait(false);
            }
        }

        [Fact]
        public async Task LinkAccountsFacebookTest()
        {
            using var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));

            var auth = await authProvider.SignInAnonymouslyAsync().ConfigureAwait(false);
            var newAuth = await auth.LinkToAsync(FirebaseAuthType.Facebook, FacebookAccessToken).ConfigureAwait(false);

            Assert.Equal(auth.User.LocalId, newAuth.User.LocalId);
            Assert.Equal(FacebookTestUserFirstName, newAuth.User.FirstName);
            Assert.False(string.IsNullOrWhiteSpace(newAuth.FirebaseToken));
        }

        [Fact]
        public async Task GetLinkedAccountsTest()
        {
            using var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));

            var auth = await authProvider.CreateUserWithEmailAndPasswordAsync(NewFirebaseEmail, NewFirebasePassword).ConfigureAwait(false);
            try
            {
                var linkedAccounts = await authProvider.GetLinkedAccountsAsync(NewFirebaseEmail).ConfigureAwait(false);

                Assert.True(linkedAccounts.IsRegistered);
                Assert.Equal(FirebaseAuthType.EmailAndPassword, linkedAccounts.Providers.Single());
            }
            finally
            {
                await authProvider.DeleteUserAsync(auth.FirebaseToken).ConfigureAwait(false);
            }
        }

        [Fact]
        public async Task RefreshAccessToken()
        {
            using var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));

            var auth = await authProvider.SignInAnonymouslyAsync().ConfigureAwait(false);
            try
            {
                var originalToken = auth.FirebaseToken;

                // simulate the token already expired
                auth.Created = DateTime.MinValue;

                var freshAuth = await auth.GetFreshAuthAsync().ConfigureAwait(false);

                //Disabled because Firebase doesn't send new ID token every time for some reason
                //Assert.NotEqual(originalToken, freshAuth.FirebaseToken);

                Assert.False(string.IsNullOrWhiteSpace(freshAuth.FirebaseToken));
            }
            finally
            {
                await authProvider.DeleteUserAsync(auth.FirebaseToken).ConfigureAwait(false);
            }
        }
    }
}
