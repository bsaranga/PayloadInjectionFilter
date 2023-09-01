using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;
using System.Collections;
using Zone24x7PayloadExtensionFilter.HelperExtensions;

namespace Zone24x7PayloadExtensionFilter
{
    /// <summary>
    /// This filter intercepts the requests before it
    /// reaches the action methods in the controllers,
    /// checks and validations are performed here so that
    /// injection attacks can be circumvented.
    /// </summary>
    public class PayloadInjectionFilter : IActionFilter
    {
        public static readonly string DEFAULT_CONTENT_BODY = "Request short-circuited due to malicious content.";
        public static readonly int DEFAULT_STATUS_CODE = 400;
        public static readonly string DEFAULT_CONTENT_TYPE = "text";
        public static readonly Regex DEFAULT_FILTER_PATTERN = new Regex(@"[<>\&;]");

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
                string pathTemplate;
                int whiteListIndex = -1;
                bool templateMatch = false;
                bool parameterMatch = false;
                bool whiteListInitialCondition = false;
                bool hasWhiteListedEntries = options.Value.WhiteListEntries != null;

                if (hasWhiteListedEntries)
                {
                    pathTemplate = context.ActionDescriptor.AttributeRouteInfo.Template;
                    templateMatch = options.Value.WhiteListEntries.Select(w => w.PathTemplate).Contains(pathTemplate);
                    whiteListIndex = (templateMatch) ? options.Value.WhiteListEntries.Select(w => w.PathTemplate).ToList().IndexOf(pathTemplate) : -1;
                }

                if (context.IsOneOfAllowedHttpMethods(options.Value.AllowedHttpMethods!.Select(x => x.ToString()).Distinct().ToArray()))
                {
                    FilterExecuted = true;

                    foreach (var argument in context.ActionArguments)
                    {
                        if (hasWhiteListedEntries && whiteListIndex != -1)
                        {
                            parameterMatch = options.Value.WhiteListEntries[whiteListIndex].ParameterName.Equals(argument.Key);
                            whiteListInitialCondition = parameterMatch && templateMatch;
                        }
                        
                        var argumentType = argument.Value.GetType();

                        if (argumentType.IsString())
                        {
                            if (DetectDisallowedChars(argument.Value as string, options.Value.Pattern ?? DEFAULT_FILTER_PATTERN))
                            {
                                ShortCircuit(context);
                            }
                        } else if (argumentType.IsEnumerable())
                        {
                            foreach (var listItem in (argument.Value as IEnumerable)!)
                            {
                                Evaluate(listItem.GetType(), listItem, context, whiteListIndex, whiteListInitialCondition);
                            }
                        }
                        else Evaluate(argumentType, argument.Value, context, whiteListIndex, whiteListInitialCondition);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, ex.Message);
                throw;
            }
        }

        private void Evaluate(Type argType, object arg, ActionExecutingContext context, int whiteListIndex, bool initialWhiteListCondition)
        {
            IEnumerable<PropertyInfo> properties = new List<PropertyInfo>();
            bool isWhiteListedProperty = false;

            if (arg != null && !argType.IsValueType())
            {
                properties = argType.GetProperties(BindingFlags.Public | BindingFlags.Instance);

                if (properties.Any())
                {
                    foreach (var prop in properties)
                    {
                        isWhiteListedProperty = whiteListIndex != -1 ? options.Value.WhiteListEntries[whiteListIndex].PropertyNames.Contains(prop.Name) : false;

                        if (prop.IsString() && !(initialWhiteListCondition && isWhiteListedProperty))
                        {
                            if (DetectDisallowedChars(prop.GetValue(arg) as string, options.Value.Pattern ?? DEFAULT_FILTER_PATTERN))
                            {
                                ShortCircuit(context);
                            }
                        } else if (!prop.PropertyType.IsValueType)
                        {
                            Evaluate(prop.PropertyType, prop.GetValue(arg), context, whiteListIndex, initialWhiteListCondition);
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
                Content = options.Value.ResponseContentBody ?? DEFAULT_CONTENT_BODY,
                StatusCode = options.Value.ResponseStatusCode == 0 ? DEFAULT_STATUS_CODE : options.Value.ResponseStatusCode,
                ContentType = options.Value.ResponseContentType ?? DEFAULT_CONTENT_TYPE
            };
        }
    }
}
