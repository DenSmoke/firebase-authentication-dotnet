using System.Net;
using Microsoft.Extensions.DependencyInjection;

namespace Firebase.Auth
{
    /// <summary>
    /// Расширение для <see cref="IServiceCollection"/> c настройкой под <see cref="FirebaseAuthProvider"/>
    /// </summary>
    public static class ServiceCollectionExtension
    {
        /// <summary>
        /// Добавление <see cref="IHttpClientBuilder"/> к <see cref="IServiceCollection"/> c настройкой:
        /// <br> Название HttpClient = <see cref="FirebaseAuthProvider"/> </br>
        /// <br> DefaultRequestVersion = <see cref="HttpVersion.Version20"/> </br>
        /// </summary>
        public static IHttpClientBuilder AddFirebaseHttpClient(this IServiceCollection services) =>
            services.AddHttpClient(nameof(FirebaseAuthProvider), x => x.DefaultRequestVersion = HttpVersion.Version20);
    }
}
