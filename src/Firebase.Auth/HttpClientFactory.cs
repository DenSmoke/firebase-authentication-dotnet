using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace Firebase.Auth
{
    internal class HttpClientFactory : IHttpClientFactory
    {
        private async void DisposeHttpClient(HttpClient client)
        {
            await Task.Delay(TimeSpan.FromMinutes(2)).ConfigureAwait(false);
            try
            {
                client.Dispose();
            }
            catch { }
        }

        public HttpClient CreateClient(string name)
        {
            var client = new HttpClient();
            DisposeHttpClient(client);
            return client;
        }
    }
}
