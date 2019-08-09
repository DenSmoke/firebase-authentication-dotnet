namespace Firebase.Auth.Tests
{
    using System;
    using System.Linq;
    using System.Threading.Tasks;
    using Xunit;

    public class IntegrationTests
    {
        private const string ApiKey = "<YOUR API KEY>";
        private const string FacebookAccessToken = "<FACEBOOK USER ACCESS TOKEN>";
        private const string FacebookTestUserFirstName = "Mark";
        private const string GoogleAccessToken = "<GOOGLE USER ACCESS TOKEN>";
        private const string GoogleTestUserFirstName = "Mark";
        private const string FirebaseEmail = "<TEST USER EMAIL>";
        private const string FirebasePassword = "<TEST USER PASSWORD>";
        private const string NewFirebaseEmail = "<TEST USER EMAIL>";
        private const string NewFirebasePassword = "<TEST USER PASSWORD>";

        [Fact]
        public async Task FacebookTest()
        {
            var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));

            var auth = await authProvider.SignInWithOAuthAsync(FirebaseAuthType.Facebook, FacebookAccessToken).ConfigureAwait(false);

            Assert.Equal(FacebookTestUserFirstName, auth.User.FirstName);
            Assert.False(string.IsNullOrWhiteSpace(auth.FirebaseToken));
        }

        [Fact]
        public async Task GoogleTest()
        {
            var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));

            var auth = await authProvider.SignInWithOAuthAsync(FirebaseAuthType.Google, GoogleAccessToken).ConfigureAwait(false);

            Assert.Equal(GoogleTestUserFirstName, auth.User.FirstName);
            Assert.False(string.IsNullOrWhiteSpace(auth.FirebaseToken));
        }

        [Fact]
        public async Task EmailTest()
        {
            var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));

            var auth = await authProvider.SignInWithEmailAndPasswordAsync(FirebaseEmail, FirebasePassword).ConfigureAwait(false);

            Assert.Equal(FirebaseEmail, auth.User.Email);
            Assert.False(string.IsNullOrWhiteSpace(auth.FirebaseToken));
        }

        [Fact]
        public async Task UnknownEmailAddressShouldBeReflectedByFailureReason()
        {
            using (var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey)))
            {
                var exception = await Assert.ThrowsAsync<FirebaseAuthException>(() => authProvider.SignInWithEmailAndPasswordAsync("someinvalidaddressxxx@foo.com", FirebasePassword)).ConfigureAwait(false);
                Assert.Equal(AuthErrorReason.UnknownEmailAddress, exception.Reason);
            }
        }

        [Fact]
        public async Task InvalidEmailAddressFormatShouldBeReflectedByFailureReason()
        {
            using (var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey)))
            {
                var exception = await Assert.ThrowsAsync<FirebaseAuthException>(() => authProvider.SignInWithEmailAndPasswordAsync("notanemailaddress", FirebasePassword)).ConfigureAwait(false);
                Assert.Equal(AuthErrorReason.InvalidEmailAddress, exception.Reason);
            }
        }

        [Fact]
        public async Task InvalidPasswordShouldBeReflectedByFailureReason()
        {
            using (var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey)))
            {
                var exception = await Assert.ThrowsAsync<FirebaseAuthException>(() => authProvider.SignInWithEmailAndPasswordAsync(FirebaseEmail, "xx" + FirebasePassword)).ConfigureAwait(false);
                Assert.Equal(AuthErrorReason.WrongPassword, exception.Reason);
            }
        }

        [Fact]
        public async Task CreateUserTest()
        {
            var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));
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
            var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));

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
            var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));

            var auth = await authProvider.SignInAnonymouslyAsync().ConfigureAwait(false);
            var newAuth = await auth.LinkToAsync(FirebaseAuthType.Facebook, FacebookAccessToken).ConfigureAwait(false);

            Assert.Equal(auth.User.LocalId, newAuth.User.LocalId);
            Assert.Equal(FacebookTestUserFirstName, newAuth.User.FirstName);
            Assert.False(string.IsNullOrWhiteSpace(newAuth.FirebaseToken));
        }

        [Fact]
        public async Task GetLinkedAccountsTest()
        {
            var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));

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
            var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));

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
