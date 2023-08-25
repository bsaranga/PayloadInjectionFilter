using Microsoft.Extensions.DependencyInjection;
using System.Text.RegularExpressions;

namespace PayloadInjectionFilter_NS
{
    /// <summary>
    /// Contains payload injection filter extensible methods
    /// </summary>
    public static class PayloadInjectionFilterConfigurationExtensions
    {
        private static string DEFAULT_CONTENT_BODY = "Request short-circuited due to malicious content.";
        private static int DEFAULT_STATUS_CODE = 400;
        private static string DEFAULT_CONTENT_TYPE = "text";
        private static Regex DEFAULT_FILTER_PATTERN = new Regex(@"[<>\&;]");

        /// <summary>
        /// Adds the filter to the current controllers
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="configurations"></param>
        /// <returns></returns>
        public static IMvcBuilder AddPayloadInjectionFilter(this IMvcBuilder builder, Action<PayloadInjectionOptions>? configurations = null)
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

                    f.ResponseContentBody = DEFAULT_CONTENT_BODY;
                    f.ResponseContentType = DEFAULT_CONTENT_TYPE;
                    f.ResponseStatusCode = DEFAULT_STATUS_CODE;

                    f.Pattern = DEFAULT_FILTER_PATTERN;
                };
            }

            builder.Services.Configure<PayloadInjectionOptions>(configurations);

            return builder;
        }
    }
}
