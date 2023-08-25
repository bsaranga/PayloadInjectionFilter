using System.Text.RegularExpressions;

namespace PayloadInjectionFilter_NS
{
    /// <summary>
    /// Set fine-tuning options for the payload filter
    /// </summary>
    public class PayloadInjectionOptions
    {
        /// <summary>
        /// Add the HTTP method types for which the payload injection filter should work on.
        /// </summary>
        public List<HttpMethod>? AllowedHttpMethods { get; set; }

        /// <summary>
        /// Set a regex pattern to specify malicious or disallowed content.
        /// </summary>
        public Regex? Pattern { get; set; }

        /// <summary>
        /// Set an HTTP response status code that's sent in the response if the action filter triggers. By default this is 400.
        /// </summary>
        public int ResponseStatusCode { get; set; }

        /// <summary>
        /// Set an HTTP response body, by default this is a text string.
        /// </summary>
        public string? ResponseContentBody { get; set; }

        /// <summary>
        /// Set the response content type, by default this is text.
        /// </summary>
        public string? ResponseContentType { get; set; }

        /// <summary>
        /// Specify endpoints, and white-listed parameters. If an `ExclusionPattern` is specified
        /// then that will be used to short-circuit the request.
        /// </summary>
        public List<WhiteListEntry>? WhiteListEntries { get; set; }
    }

    /// <summary>
    /// Describes the controller and controller method to be white-listed
    /// </summary>
    public class WhiteListEntry
    {
        /// <summary>
        /// The controller to be white-listed
        /// </summary>
        public string? ControllerName { get; set; }
        /// <summary>
        /// The endpoint of a specific action method
        /// </summary>
        public string? PathTemplate { get; set; }
        /// <summary>
        /// The data-bound parameter name of the action method.
        /// </summary>
        public string? ParameterName { get; set; }
        /// <summary>
        /// Property names must only be set if the parameter is a custom data type, 
        /// if it is a value type or string type, then this can be kept optional
        /// </summary>
        public List<string>? PropertyNames { get; set; }
        /// <summary>
        /// This regex pattern will be used to short-circuit the white-listed
        /// entries, this is optional
        /// </summary>
        public Regex? ExclusionPattern { get; set; }
    }
}
