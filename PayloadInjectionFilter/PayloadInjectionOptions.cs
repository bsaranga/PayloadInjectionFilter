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
    }
}
