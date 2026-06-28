using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;

namespace SpitFirePayloadExtensionFilter
{
    /// <summary>
    /// Options for the <see cref="PayloadInjectionMiddleware"/>.
    /// <para>
    /// Unlike the MVC action filter, the middleware runs before model binding and inspects
    /// the raw request (query string and body) as text. It therefore works for any endpoint
    /// type ASP.NET Core supports — MVC controllers, minimal APIs, Razor Pages and gRPC — at
    /// the cost of not being able to target individual bound model properties. Use the
    /// <see cref="ExcludedPaths"/> list to allow specific routes through unscanned.
    /// </para>
    /// </summary>
    public class PayloadInjectionMiddlewareOptions
    {
        /// <summary>
        /// Regex describing disallowed / malicious content. Defaults to <c>[&lt;&gt;\&amp;;]</c>.
        /// </summary>
        public Regex Pattern { get; set; } = new Regex(@"[<>\&;]");

        /// <summary>
        /// HTTP methods to scan. Defaults to POST, PUT and PATCH.
        /// </summary>
        public List<HttpMethod> AllowedHttpMethods { get; set; } = new List<HttpMethod>
        {
            HttpMethod.Post,
            HttpMethod.Put,
            HttpMethod.Patch,
        };

        /// <summary>
        /// Status code returned when a request is short-circuited. Defaults to 400.
        /// </summary>
        public int ResponseStatusCode { get; set; } = 400;

        /// <summary>
        /// Content type of the short-circuit response. Defaults to <c>text/plain</c>.
        /// </summary>
        public string ResponseContentType { get; set; } = "text/plain";

        /// <summary>
        /// Body of the short-circuit response.
        /// </summary>
        public string ResponseContentBody { get; set; } = "Request short-circuited due to malicious content.";

        /// <summary>
        /// Whether to scan the request query string. Defaults to <c>true</c>.
        /// </summary>
        public bool ScanQueryString { get; set; } = true;

        /// <summary>
        /// Whether to scan the request body. Defaults to <c>true</c>.
        /// </summary>
        public bool ScanBody { get; set; } = true;

        /// <summary>
        /// Maximum body size (in bytes) that will be buffered and scanned. Requests with a
        /// larger declared <c>Content-Length</c> are rejected with HTTP 413 rather than buffered,
        /// which bounds the memory cost of scanning. Defaults to 30 MB.
        /// </summary>
        public long MaxScannedBodyBytes { get; set; } = 30L * 1024 * 1024;

        /// <summary>
        /// Request paths (prefix match) that should bypass scanning entirely. Useful for
        /// endpoints that legitimately accept rich text / markup.
        /// </summary>
        public List<PathString> ExcludedPaths { get; set; } = new List<PathString>();
    }
}
