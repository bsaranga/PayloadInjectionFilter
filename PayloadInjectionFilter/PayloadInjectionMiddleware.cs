using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SpitFirePayloadExtensionFilter
{
    /// <summary>
    /// Middleware that scans the raw request (query string and body) for disallowed content
    /// before it reaches the endpoint pipeline. Because it runs before model binding it covers
    /// MVC controllers, minimal APIs, Razor Pages and gRPC alike.
    /// <para>
    /// This is a defense-in-depth boundary check, not a substitute for output encoding,
    /// parameterized queries or a dedicated WAF. Deny-listing characters such as
    /// <c>&lt; &gt; &amp; ;</c> will reject some legitimate input — exclude such routes via
    /// <see cref="PayloadInjectionMiddlewareOptions.ExcludedPaths"/>.
    /// </para>
    /// </summary>
    public class PayloadInjectionMiddleware
    {
        private readonly RequestDelegate next;
        private readonly ILogger<PayloadInjectionMiddleware> logger;
        private readonly PayloadInjectionMiddlewareOptions options;
        private readonly HashSet<string> methods;
        private readonly Regex pattern;

        public PayloadInjectionMiddleware(
            RequestDelegate next,
            IOptions<PayloadInjectionMiddlewareOptions> options,
            ILogger<PayloadInjectionMiddleware> logger)
        {
            this.next = next;
            this.logger = logger;
            this.options = options.Value;
            this.pattern = this.options.Pattern ?? new Regex(@"[<>\&;]");
            this.methods = new HashSet<string>(
                (this.options.AllowedHttpMethods ?? new List<HttpMethod>()).Select(m => m.Method),
                StringComparer.OrdinalIgnoreCase);
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var request = context.Request;

            if (!methods.Contains(request.Method) || IsExcluded(request.Path))
            {
                await next(context);
                return;
            }

            if (options.ScanQueryString && request.QueryString.HasValue)
            {
                // Decode so percent-encoded payloads (e.g. %3Cscript%3E) are caught too.
                var query = Uri.UnescapeDataString(request.QueryString.Value!);
                if (pattern.IsMatch(query))
                {
                    await ShortCircuitAsync(context, "query string");
                    return;
                }
            }

            if (options.ScanBody && HasBody(request))
            {
                if (request.ContentLength.HasValue && request.ContentLength.Value > options.MaxScannedBodyBytes)
                {
                    await RejectOversizedAsync(context);
                    return;
                }

                var body = await ReadBodyAsync(request);
                if (body != null && pattern.IsMatch(body))
                {
                    await ShortCircuitAsync(context, "request body");
                    return;
                }
            }

            await next(context);
        }

        private bool IsExcluded(PathString path)
        {
            if (options.ExcludedPaths == null || options.ExcludedPaths.Count == 0) return false;
            return options.ExcludedPaths.Any(p => path.StartsWithSegments(p, StringComparison.OrdinalIgnoreCase));
        }

        private static bool HasBody(HttpRequest request)
            => (request.ContentLength ?? 0) > 0 || request.Headers.ContainsKey("Transfer-Encoding");

        private async Task<string> ReadBodyAsync(HttpRequest request)
        {
            // Buffer the body so it can be re-read by the endpoint after scanning.
            request.EnableBuffering();

            using var reader = new StreamReader(
                request.Body,
                Encoding.UTF8,
                detectEncodingFromByteOrderMarks: false,
                bufferSize: 1024,
                leaveOpen: true);

            var body = await reader.ReadToEndAsync();
            request.Body.Position = 0;
            return body;
        }

        private async Task ShortCircuitAsync(HttpContext context, string location)
        {
            logger.LogWarning(
                "[PayloadInjectionMiddleware]:[Warning] Request short-circuited due to malicious content in the {Location}.",
                location);

            context.Response.Clear();
            context.Response.StatusCode = options.ResponseStatusCode == 0 ? 400 : options.ResponseStatusCode;
            context.Response.ContentType = options.ResponseContentType ?? "text/plain";
            await context.Response.WriteAsync(
                options.ResponseContentBody ?? "Request short-circuited due to malicious content.");
        }

        private async Task RejectOversizedAsync(HttpContext context)
        {
            logger.LogWarning("[PayloadInjectionMiddleware]:[Warning] Request body exceeds the scannable limit of {Limit} bytes.", options.MaxScannedBodyBytes);

            context.Response.Clear();
            context.Response.StatusCode = (int)HttpStatusCode.RequestEntityTooLarge;
            context.Response.ContentType = "text/plain";
            await context.Response.WriteAsync("Request body is too large to scan.");
        }
    }
}
