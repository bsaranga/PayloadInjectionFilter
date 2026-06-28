using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace SpitFirePayloadExtensionFilter
{
    /// <summary>
    /// Registration helpers for the <see cref="PayloadInjectionMiddleware"/>.
    /// </summary>
    public static class PayloadInjectionMiddlewareExtensions
    {
        /// <summary>
        /// Registers and configures the options used by <see cref="PayloadInjectionMiddleware"/>.
        /// Call this in service configuration, then call <see cref="UsePayloadInjectionMiddleware"/>
        /// in the request pipeline.
        /// </summary>
        public static IServiceCollection AddPayloadInjectionMiddleware(
            this IServiceCollection services,
            Action<PayloadInjectionMiddlewareOptions> configure = null)
        {
            if (configure != null) services.Configure(configure);
            else services.Configure<PayloadInjectionMiddlewareOptions>(_ => { });

            return services;
        }

        /// <summary>
        /// Adds the payload injection scanning middleware to the request pipeline. Place this
        /// early — before <c>UseRouting</c>/<c>MapControllers</c> — so malicious requests are
        /// short-circuited before they reach any endpoint.
        /// </summary>
        public static IApplicationBuilder UsePayloadInjectionMiddleware(this IApplicationBuilder app)
            => app.UseMiddleware<PayloadInjectionMiddleware>();
    }
}
