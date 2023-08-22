using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;

namespace PayloadInjectionFilter_NS
{
    /// <summary>
    /// This filter intercepts the requests before it
    /// reaches the action methods in the controllers,
    /// checks and validations are performed here so that
    /// injection attacks can be circumvented.
    /// </summary>
    public class PayloadInjectionFilter : IActionFilter
    {
        private readonly ILogger<PayloadInjectionFilter> logger;
        private readonly IOptions<PayloadInjectionOptions> options;

        /// <summary>
        /// Constructor injects the logger, primarily used to log
        /// any exceptions, diagnostic info
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="options"></param>
        public PayloadInjectionFilter(IOptions<PayloadInjectionOptions> options, ILogger<PayloadInjectionFilter> logger)
        {
            this.options = options;
            this.logger = logger;
        }

        /// <summary>
        /// Used to track if the filter executed in unit tests
        /// </summary>
        public bool FilterExecuted { get; private set; } = false;

        /// <summary>
        /// Used to track if the filter is short-circuited in unit tests
        /// </summary>
        public bool ShortCircuited { get; private set; } = false;
        
        /// <summary>
        /// Runs after the validation
        /// </summary>
        /// <param name="context"></param>
        public void OnActionExecuted(ActionExecutedContext context) { }

        /// <summary>
        /// Performs validation on model-bound data
        /// </summary>
        /// <param name="context"></param>
        public void OnActionExecuting(ActionExecutingContext context)
        {
            try
            {
                if (context.IsOneOfAllowedHttpMethods(options.Value.AllowedHttpMethods!.Select(x => x.ToString()).Distinct().ToArray()))
                {
                    FilterExecuted = true;

                    IEnumerable<PropertyInfo> properties = new List<PropertyInfo>();

                    foreach (var item in context.ActionArguments.Values)
                    {
                        var argumentType = item!.GetType();

                        if (argumentType.IsString())
                        {
                            if (DetectDisallowedChars(item as string, options.Value.Pattern!))
                            {
                                context.ShortCircuit(options.Value.ResponseContentBody!, options.Value.ResponseStatusCode, options.Value.ResponseContentType!);
                                ShortCircuited = true;
                            }
                        }

                        if (!argumentType.IsValueType() && !argumentType.IsString())
                        {
                            properties = argumentType.GetProperties(BindingFlags.Public | BindingFlags.Instance);
                        }

                        if (properties.Any())
                        {
                            foreach (var prop in properties)
                            {
                                if (prop.IsString())
                                {
                                    if (DetectDisallowedChars(prop.GetValue(item) as string, options.Value.Pattern!))
                                    {
                                        context.ShortCircuit(options.Value.ResponseContentBody!, options.Value.ResponseStatusCode, options.Value.ResponseContentType!);
                                        ShortCircuited = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, ex.Message);
                throw;
            }
        }

        private static bool DetectDisallowedChars(string? input, Regex disallowedPattern)
        {
            if (string.IsNullOrEmpty(input)) return false;
            
            return disallowedPattern.IsMatch(input);
        }
    }

    internal static class PayloadInjectionFilterExtensions
    {
        internal static bool IsString(this PropertyInfo propInfo)
        {
            return propInfo.PropertyType.Name == "String" && propInfo.PropertyType.FullName == "System.String";
        }

        internal static bool IsString(this Type objectType)
        {
            return objectType.Name == "String" && objectType.FullName == "System.String";
        }

        internal static bool IsValueType(this Type objectType)
        {
            return objectType.BaseType!.Name == "ValueType" && objectType.BaseType.FullName == "System.ValueType";
        }

        internal static void ShortCircuit(this ActionExecutingContext context, string contentBody, int statusCode, string contentType)
        {
            context.ModelState.AddModelError("__shortcircuit__", "Malicious content");
            context.Result = new ContentResult
            {
                Content = string.IsNullOrEmpty(contentBody) ? "Request short-circuited due to malicious content." : contentBody,
                StatusCode = statusCode == 0 ? 400 : statusCode,
                ContentType = string.IsNullOrEmpty(contentType) ? "text" : contentType
            };
        }

        internal static bool IsOneOfAllowedHttpMethods(this ActionExecutingContext context, params string[] HttpMethods)
        {
            return HttpMethods.Contains(context.HttpContext.Request.Method);
        }
    }
}
