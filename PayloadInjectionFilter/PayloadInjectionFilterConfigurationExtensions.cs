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

            if (configurations == null)
            {
                configurations = (f) =>
                {
                    f.AllowedHttpMethods = new List<HttpMethod>
                    {
                        HttpMethod.Post,
                        HttpMethod.Put,
                        HttpMethod.Patch,
                    };

                    f.ResponseContentBody = PayloadInjectionFilter.DEFAULT_CONTENT_BODY;
                    f.ResponseContentType = PayloadInjectionFilter.DEFAULT_CONTENT_TYPE;
                    f.ResponseStatusCode = PayloadInjectionFilter.DEFAULT_STATUS_CODE;

                    f.Pattern = PayloadInjectionFilter.DEFAULT_FILTER_PATTERN;
                };
            }

            builder.Services.Configure<PayloadInjectionOptions>(configurations);

            return builder;
        }
    }
}
