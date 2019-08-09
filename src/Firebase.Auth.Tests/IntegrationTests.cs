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
        public async Task Unknown_email_address_should_be_reflected_by_failure_reason()
        {
            using (var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey)))
            {
                var exception = await Assert.ThrowsAsync<Exception>(() => authProvider.SignInWithEmailAndPasswordAsync("someinvalidaddressxxx@foo.com", FirebasePassword)).ConfigureAwait(false);
                Assert.Equal(AuthErrorReason.UnknownEmailAddress, (exception.InnerException as FirebaseAuthException)?.Reason);
            }
        }

        [Fact]
        public async Task Invalid_email_address_format_should_be_reflected_by_failure_reason()
        {
            using (var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey)))
            {
                var exception = await Assert.ThrowsAsync<Exception>(() => authProvider.SignInWithEmailAndPasswordAsync("notanemailaddress", FirebasePassword)).ConfigureAwait(false);
                Assert.Equal(AuthErrorReason.InvalidEmailAddress, (exception.InnerException as FirebaseAuthException)?.Reason);
            }
        }



        [Fact]
        public async Task Invalid_password_should_be_reflected_by_failure_reason()
        {
            using (var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey)))
            {
                var exception = await Assert.ThrowsAsync<Exception>(() => authProvider.SignInWithEmailAndPasswordAsync(FirebaseEmail, "xx" + FirebasePassword)).ConfigureAwait(false);
                Assert.Equal(AuthErrorReason.WrongPassword, (exception.InnerException as FirebaseAuthException)?.Reason);
            }
        }

        [Fact]
        public async Task CreateUserTest()
        {
            var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));
            var email = $"abcd{new Random().Next()}@test.com";

            var auth = await authProvider.SignInWithEmailAndPasswordAsync(email, "test1234").ConfigureAwait(false);

            Assert.Equal(email, auth.User.Email);
            Assert.False(string.IsNullOrWhiteSpace(auth.FirebaseToken));
        }

        [Fact]
        public async Task LinkAccountsTest()
        {
            var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));
            var email = $"abcd{new Random().Next()}@test.com";

            var auth = await authProvider.SignInAnonymouslyAsync().ConfigureAwait(false);
            var newAuth = await auth.LinkToAsync(email, "test1234").ConfigureAwait(false);

            Assert.Equal(email, newAuth.User.Email);
            Assert.Equal(auth.User.LocalId, newAuth.User.LocalId);
            Assert.False(string.IsNullOrWhiteSpace(newAuth.FirebaseToken));
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
            var email = $"abcd{new Random().Next()}@test.com";

            var auth = await authProvider.CreateUserWithEmailAndPasswordAsync(email, "test1234").ConfigureAwait(false);
            var linkedAccounts = await authProvider.GetLinkedAccountsAsync(email).ConfigureAwait(false);

            Assert.True(linkedAccounts.IsRegistered);
            Assert.Equal(FirebaseAuthType.EmailAndPassword, linkedAccounts.Providers.Single());
        }

        [Fact]
        public async Task RefreshAccessToken()
        {
            var authProvider = new FirebaseAuthProvider(new FirebaseConfig(ApiKey));

            var auth = await authProvider.SignInWithOAuthAsync(FirebaseAuthType.Facebook, FacebookAccessToken).ConfigureAwait(false);
            var originalToken = auth.FirebaseToken;

            // simulate the token already expired
            auth.Created = DateTime.MinValue;

            var freshAuth = await auth.GetFreshAuthAsync().ConfigureAwait(false);

            Assert.NotEqual(originalToken, freshAuth.FirebaseToken);
        }
    }
}
