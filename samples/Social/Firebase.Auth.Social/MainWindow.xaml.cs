namespace Firebase.Auth.Social
{
    using System;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;
    using System.Windows;
    using Database;
    using Database.Query;
    using Facebook;
    using Google.Apis.Auth.OAuth2;
    using Google.Apis.Util;

    public partial class MainWindow : Window
    {
        // TODO: fill these out
        public const string FacebookAppId = "<FACEBOOK APP ID>"; // https://developers.facebook.com/
        public const string GoogleClientId = "<GOOGLE CLIENT ID>"; // https://console.developers.google.com/apis/credentials
        public const string FirebaseAppKey = "<FIREBASE APP KEY>"; // https://console.firebase.google.com/
        public const string FirebaseAppUri = "https://<YOUR_FIREBASE_APP>.firebaseio.com/";

        public MainWindow()
        {
            InitializeComponent();
        }

        private void FacebookClick(object sender, RoutedEventArgs e)
        {
            var loginUri = GenerateFacebookLoginUrl(FacebookAppId, "email");

            Browser.Visibility = Visibility.Visible;
            Browser.Navigate(loginUri);
        }

        private async void GoogleClick(object sender, RoutedEventArgs e)
        {
            try
            {
                var cr = new PromptCodeReceiver();

                var result = await GoogleWebAuthorizationBroker.AuthorizeAsync(
                    new ClientSecrets { ClientId = GoogleClientId },
                    new[] { "email", "profile" },
                    "user",
                    CancellationToken.None);

                if (result.Token.IsExpired(SystemClock.Default))
                {
                    await result.RefreshTokenAsync(CancellationToken.None);
                }

                FetchFirebaseData(result.Token.AccessToken, FirebaseAuthType.Google);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        private Uri GenerateFacebookLoginUrl(string appId, string extendedPermissions)
        {
            // copied from http://stackoverflow.com/questions/29621427/facebook-sdk-integration-in-wpf-application

            var parameters = new
            {
                client_id = appId,
                redirect_uri = "https://www.facebook.com/connect/login_success.html",

                // The requested response: an access token (token), an authorization code (code), or both (code token).
                response_type = "token",

                // list of additional display modes can be found at http://developers.facebook.com/docs/reference/dialogs/#display
                display = "popup",
                scope = !string.IsNullOrWhiteSpace(extendedPermissions) ? extendedPermissions : null
            };
            // add the 'scope' parameter only if we have extendedPermissions.
            //if (!string.IsNullOrWhiteSpace(extendedPermissions))
            //    parameters.scope = extendedPermissions;


            // generate the login url
            var fb = new FacebookClient();
            return fb.GetLoginUrl(parameters);
        }

        private void BrowserNavigated(object sender, System.Windows.Navigation.NavigationEventArgs e)
        {
            var fb = new FacebookClient();
            if (!fb.TryParseOAuthCallbackUrl(e.Uri, out var oauthResult))
            {
                return;
            }

            if (oauthResult.IsSuccess)
            {
                Browser.Visibility = Visibility.Collapsed;
                FetchFirebaseData(oauthResult.AccessToken, FirebaseAuthType.Facebook);
            }
        }

        private async void FetchFirebaseData(string accessToken, FirebaseAuthType authType)
        {
            try
            {
                // Convert the access token to firebase token
                var auth = new FirebaseAuthProvider(new FirebaseConfig(FirebaseAppKey));
                var data = await auth.SignInWithOAuthAsync(authType, accessToken);

                // Setup FirebaseClient to use the firebase token for data requests
                var db = new FirebaseClient(
                       FirebaseAppUri,
                       new FirebaseOptions
                       {
                           AuthTokenAsyncFactory = () => Task.FromResult(data.FirebaseToken)
                       });

                // TODO: your path within your DB structure.
                var dbData = await db
                    .Child("userGroups")
                    .Child(data.User.LocalId)
                    .OnceAsync<object>(); // TODO: custom class to represent your data instead of just object

                // TODO: present your data
                MessageBox.Show(string.Join("\n", dbData.Select(d => d.ToString())));
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }
    }
}
