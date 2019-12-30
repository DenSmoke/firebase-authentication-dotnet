using System.Net.Http;

namespace Firebase.Auth
{
    internal class HttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new HttpClient();
    }
}
