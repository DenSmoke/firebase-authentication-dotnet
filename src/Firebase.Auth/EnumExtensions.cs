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
        /// Добавление <see cref="IHttpClientBuilder"/> к <see cref="IServiceCollection"/> c названием <see cref="FirebaseAuthProvider"/>
        /// </summary>
        public static IHttpClientBuilder AddFirebaseHttpClient(this IServiceCollection services) =>
#if NETSTANDARD2_0
            services.AddHttpClient(nameof(FirebaseAuthProvider));
#else
            services.AddHttpClient(nameof(FirebaseAuthProvider), x => x.DefaultRequestVersion = HttpVersion.Version20);
#endif
    }
}