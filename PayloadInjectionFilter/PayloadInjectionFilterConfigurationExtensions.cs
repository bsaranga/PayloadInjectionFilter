using Microsoft.Extensions.DependencyInjection;

namespace PayloadInjectionFilter_NS
{
    /// <summary>
    /// Contains payload injection filter extensible methods
    /// </summary>
    public static class PayloadInjectionFilterConfigurationExtensions
    {
        /// <summary>
        /// Adds the filter to the current controllers
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="configurations"></param>
        /// <returns></returns>
        public static IMvcBuilder AddPayloadInjectionFilter(this IMvcBuilder builder, Action<PayloadInjectionOptions> configurations = null)
        {
            builder.AddMvcOptions(options =>
            {
                options.Filters.Add<PayloadInjectionFilter>();
            });

            builder.Services.Configure<PayloadInjectionOptions>(configurations);

            return builder;
        }
    }
}
