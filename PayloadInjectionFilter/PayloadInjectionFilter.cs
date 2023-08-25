using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;
using System.Collections;
using Microsoft.AspNetCore.Mvc.Controllers;

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
                string controllerName = ((ControllerActionDescriptor)context.ActionDescriptor).ControllerName;
                string? pathTemplate = context.ActionDescriptor.AttributeRouteInfo?.Template;
                
                bool? controllerMatch = options.Value.WhiteListEntries?.Select(w => w.ControllerName).Contains(controllerName);
                bool? templateMatch = options.Value.WhiteListEntries?.Select(w => w.PathTemplate).Contains(pathTemplate);
                int? whiteListIndex = (controllerMatch.HasValue && controllerMatch.Value) ? options.Value.WhiteListEntries?.Select(w => w.ControllerName).ToList().IndexOf(controllerName) : null;

                if (context.IsOneOfAllowedHttpMethods(options.Value.AllowedHttpMethods!.Select(x => x.ToString()).Distinct().ToArray()))
                {
                    FilterExecuted = true;

                    IEnumerable<PropertyInfo> properties = new List<PropertyInfo>();

                    foreach (var item in context.ActionArguments)
                    {
                        bool? parameterMatch = whiteListIndex.HasValue ? options.Value.WhiteListEntries?[whiteListIndex.Value].ParameterName?.Equals(item.Key) : null;
                        var whiteListInitialCondition = ((parameterMatch.HasValue && templateMatch.HasValue && controllerMatch.HasValue) && parameterMatch.Value && templateMatch.Value && controllerMatch.Value);
                        
                        var argumentType = item.Value!.GetType();

                        if (argumentType.IsString())
                        {
                            if (DetectDisallowedChars(item.Value as string, options.Value.Pattern!))
                            {
                                ShortCircuit(context);
                            }
                        }

                        if (argumentType.IsEnumerable())
                        {
                            foreach (var listItem in (item.Value as IEnumerable)!)
                            {
                                Evaluate(listItem.GetType(), listItem, context, whiteListIndex, whiteListInitialCondition);
                            }
                        }
                        else Evaluate(argumentType, item.Value, context, whiteListIndex, whiteListInitialCondition);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, ex.Message);
                throw;
            }
        }

        private void Evaluate(Type incomingType, object incomingItem, ActionExecutingContext context, int? whiteListIndex, bool? initialWhiteListCondition)
        {
            IEnumerable<PropertyInfo> properties = new List<PropertyInfo>();

            if (!incomingType.IsValueType() && !incomingType.IsString())
            {
                properties = incomingType.GetProperties(BindingFlags.Public | BindingFlags.Instance);
            }

            if (properties.Any())
            {
                foreach (var prop in properties)
                {
                    var whiteListedProperty = whiteListIndex.HasValue ? options.Value.WhiteListEntries?[whiteListIndex.Value].PropertyNames?.Contains(prop.Name) : null;

                    if (prop.IsString() && !(initialWhiteListCondition.HasValue && whiteListedProperty.HasValue && initialWhiteListCondition.Value && whiteListedProperty.Value))
                    {
                        if (DetectDisallowedChars(prop.GetValue(incomingItem) as string, options.Value.Pattern!))
                        {
                            ShortCircuit(context);
                        }
                    }
                }
            }
        }

        private bool DetectDisallowedChars(string? input, Regex disallowedPattern)
        {
            if (string.IsNullOrEmpty(input)) return false;
            
            return disallowedPattern.IsMatch(input);
        }

        private void ShortCircuit(ActionExecutingContext context)
        {
            ShortCircuited = true;
            context.ModelState.AddModelError("__shortcircuit__", "Malicious content");
            context.Result = new ContentResult
            {
                Content = options.Value.ResponseContentBody,
                StatusCode = options.Value.ResponseStatusCode,
                ContentType = options.Value.ResponseContentType
            };
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

        internal static bool IsEnumerable(this Type objectType)
        {
            return typeof(IEnumerable).IsAssignableFrom(objectType);
        }

        internal static bool IsOneOfAllowedHttpMethods(this ActionExecutingContext context, params string[] HttpMethods)
        {
            return HttpMethods.Contains(context.HttpContext.Request.Method);
        }
    }
}
