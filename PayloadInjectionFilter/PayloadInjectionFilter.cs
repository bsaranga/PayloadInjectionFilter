using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;
using System.Collections;
using SpitFirePayloadExtensionFilter.HelperExtensions;
using System.Net;

namespace SpitFirePayloadExtensionFilter
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
        private int PLACE_HOLDER_RECURSION_DEPTH = int.MinValue;

        private int MaxRecursionDepth;
        private int CurrentRecursionDepth;
        private List<string> CaughtMaliciousContent;
        private ActionExecutingContext CurrentContext;

        /// <summary>
        /// Tracks the reference-type instances on the current traversal path so that
        /// cyclic object graphs (e.g. A -> B -> A) do not cause infinite recursion.
        /// Reference equality is used so that distinct sibling instances are not skipped.
        /// </summary>
        private readonly HashSet<object> VisitedOnPath = new HashSet<object>(ReferenceEqualityComparer.Instance);

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

            this.MaxRecursionDepth = -1;
            this.CurrentRecursionDepth = 0;
            this.CaughtMaliciousContent = new List<string>();
        }

        /// <summary>
        /// Used to track if the filter executed in unit tests
        /// </summary>
        public bool FilterHasExecuted { get; private set; } = false;

        /// <summary>
        /// Used to track if the filter is short-circuited in unit tests
        /// </summary>
        public bool HasShortCircuited { get; private set; } = false;

        /// <summary>
        /// Used to track if recursion depth has exceeded
        /// </summary>
        public bool RecursionDepthHasExceeded { get; private set; } = false;

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
                CurrentContext = context;
                MaxRecursionDepth = options.Value.MaxRecursionDepth;

                string pathTemplate;
                int whiteListIndex = -1;
                bool templateMatch = false;
                bool parameterMatch = false;
                bool whiteListInitialCondition = false;
                bool hasWhiteListedEntries = options.Value.WhiteListEntries != null;

                if (hasWhiteListedEntries)
                {
                    // AttributeRouteInfo is null for convention-routed controllers; guard against it.
                    pathTemplate = context.ActionDescriptor.AttributeRouteInfo?.Template;

                    if (pathTemplate != null)
                    {
                        templateMatch = options.Value.WhiteListEntries.Select(w => w.PathTemplate).Contains(pathTemplate);
                        whiteListIndex = (templateMatch) ? options.Value.WhiteListEntries.Select(w => w.PathTemplate).ToList().IndexOf(pathTemplate) : -1;
                    }
                }

                if (context.IsOneOfAllowedHttpMethods(options.Value.AllowedHttpMethods!.Select(x => x.ToString()).Distinct().ToArray()))
                {
                    FilterHasExecuted = true;

                    foreach (var argument in context.ActionArguments)
                    {
                        // A nullable/optional bound parameter can be null; skip it instead of throwing.
                        if (argument.Value == null) continue;

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
                                ShortCircuit(context, argument.Value as string);
                            }
                        } else if (argumentType.IsEnumerable())
                        {
                            foreach (var listItem in (argument.Value as IEnumerable)!)
                            {
                                if (listItem == null) continue;
                                Evaluate(listItem.GetType(), listItem, context, whiteListIndex, whiteListInitialCondition, ref PLACE_HOLDER_RECURSION_DEPTH);
                            }
                        }
                        else Evaluate(argumentType, argument.Value, context, whiteListIndex, whiteListInitialCondition, ref PLACE_HOLDER_RECURSION_DEPTH);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, ex.Message);
                throw;
            }
        }

        private void Evaluate(Type argType, object arg, ActionExecutingContext context, int whiteListIndex, bool initialWhiteListCondition, ref int recursionDepth)
        {
            bool isWhiteListedProperty = false;

            if (recursionDepth != PLACE_HOLDER_RECURSION_DEPTH) recursionDepth++;

            if (MaxRecursionDepth == -1 || recursionDepth <= MaxRecursionDepth)
            {
                if (arg != null && (!argType.IsValueType || argType.IsKeyValuePair()))
                {
                    // Cycle guard: if this exact instance is already on the current traversal
                    // path, recursing again would loop forever. Track it for the duration of
                    // this subtree and remove it on the way out so siblings are still scanned.
                    bool tracked = !argType.IsValueType && VisitedOnPath.Add(arg);
                    if (!tracked && !argType.IsValueType) return;

                    try
                    {
                        PropertyInfo[] properties = GetCachedProperties(argType);

                        foreach (var prop in properties)
                        {
                            isWhiteListedProperty = whiteListIndex != -1 && options.Value.WhiteListEntries[whiteListIndex].PropertyNames.Contains(prop.Name);

                            if (prop.IsString() && !(initialWhiteListCondition && isWhiteListedProperty))
                            {
                                var value = prop.GetValue(arg) as string;
                                if (DetectDisallowedChars(value, options.Value.Pattern ?? DEFAULT_FILTER_PATTERN))
                                {
                                    ShortCircuit(context, value);
                                }
                            }
                            else if (prop.IsString() && initialWhiteListCondition && isWhiteListedProperty
                                     && whiteListIndex != -1 && options.Value.WhiteListEntries[whiteListIndex].ExclusionPattern != null)
                            {
                                // The property is white-listed, but an ExclusionPattern is configured:
                                // still short-circuit if the (otherwise allowed) value matches it.
                                var value = prop.GetValue(arg) as string;
                                if (DetectDisallowedChars(value, options.Value.WhiteListEntries[whiteListIndex].ExclusionPattern))
                                {
                                    ShortCircuit(context, value);
                                }
                            }
                            else if (!prop.PropertyType.IsValueType)
                            {
                                var value = prop.GetValue(arg);
                                if (value == null) continue;

                                if (prop.PropertyType.IsEnumerable())
                                {
                                    foreach (var item in (value as IEnumerable))
                                    {
                                        if (item == null) continue;
                                        Evaluate(item.GetType(), item, context, whiteListIndex, initialWhiteListCondition, ref CurrentRecursionDepth);
                                    }
                                }
                                else Evaluate(prop.PropertyType, value, context, whiteListIndex, initialWhiteListCondition, ref CurrentRecursionDepth);
                            }
                        }
                    }
                    finally
                    {
                        if (tracked) VisitedOnPath.Remove(arg);
                    }
                }
            }
            else RecursionDepthExceeded(context);
        }

        /// <summary>
        /// Caches the public instance properties per <see cref="Type"/> so the reflection
        /// metadata lookup is performed only once per type rather than on every request.
        /// </summary>
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<Type, PropertyInfo[]> PropertyCache
            = new System.Collections.Concurrent.ConcurrentDictionary<Type, PropertyInfo[]>();

        private static PropertyInfo[] GetCachedProperties(Type type)
            => PropertyCache.GetOrAdd(type, t => t.GetProperties(BindingFlags.Public | BindingFlags.Instance));

        private bool DetectDisallowedChars(string input, Regex disallowedPattern)
        {
            if (string.IsNullOrEmpty(input)) return false;
            
            return disallowedPattern.IsMatch(input);
        }

        private void ShortCircuit(ActionExecutingContext context, string maliciousContent)
        {
            HasShortCircuited = true;
            CaughtMaliciousContent.Add(maliciousContent);

            context.ModelState.AddModelError("__shortcircuit__", "Malicious content");
            context.Result = new ContentResult
            {
                Content = options.Value.ResponseContentBody ?? DEFAULT_CONTENT_BODY,
                StatusCode = options.Value.ResponseStatusCode == 0 ? DEFAULT_STATUS_CODE : options.Value.ResponseStatusCode,
                ContentType = options.Value.ResponseContentType ?? DEFAULT_CONTENT_TYPE
            };
        }

        private void RecursionDepthExceeded(ActionExecutingContext context)
        {
            RecursionDepthHasExceeded = true;
            context.ModelState.AddModelError("__recursiondepthexceeded__", "Recursion depth has exceeded");
            context.Result = new ContentResult
            {
                Content = "Recursion depth has exceeded",
                StatusCode = ((int)HttpStatusCode.RequestEntityTooLarge),
                ContentType = DEFAULT_CONTENT_TYPE
            };

            logger.LogWarning("[PayloadInjectionFilter]:[Warning] Recursion depth has exceeded.");
        }

        public List<string> GetCaughtMaliciousContent() => CaughtMaliciousContent;
        public int GetCurrentRecursionDepth() => CurrentRecursionDepth;
        public ActionExecutingContext GetCurrentContext() => CurrentContext;
        public int GetMaxRecursionDepth() => MaxRecursionDepth;
    }
}
