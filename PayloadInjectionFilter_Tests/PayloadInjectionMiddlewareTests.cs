using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using SpitFirePayloadExtensionFilter;

namespace PayloadInjectionFilter_Tests
{
    [TestFixture]
    public class PayloadInjectionMiddlewareTests
    {
        private static PayloadInjectionMiddleware Build(PayloadInjectionMiddlewareOptions opts, RequestDelegate next)
        {
            var logger = new Mock<ILogger<PayloadInjectionMiddleware>>();
            var options = new Mock<IOptions<PayloadInjectionMiddlewareOptions>>();
            options.Setup(x => x.Value).Returns(opts);
            return new PayloadInjectionMiddleware(next, options.Object, logger.Object);
        }

        private static DefaultHttpContext ContextWith(string method, string body = null, string queryString = null)
        {
            var ctx = new DefaultHttpContext();
            ctx.Request.Method = method;
            ctx.Response.Body = new MemoryStream();

            if (queryString != null) ctx.Request.QueryString = new QueryString(queryString);

            if (body != null)
            {
                var bytes = Encoding.UTF8.GetBytes(body);
                ctx.Request.Body = new MemoryStream(bytes);
                ctx.Request.ContentLength = bytes.Length;
            }

            return ctx;
        }

        [Test]
        public async Task ShortCircuits_Malicious_Body()
        {
            var nextCalled = false;
            var middleware = Build(new PayloadInjectionMiddlewareOptions(), _ => { nextCalled = true; return Task.CompletedTask; });

            var ctx = ContextWith("POST", body: "{\"name\":\"<script>alert(1)</script>\"}");
            await middleware.InvokeAsync(ctx);

            Assert.That(nextCalled, Is.False);
            Assert.That(ctx.Response.StatusCode, Is.EqualTo(400));
        }

        [Test]
        public async Task Allows_Clean_Body_And_Body_Is_Rewound_For_Downstream()
        {
            string seenByEndpoint = null;
            var middleware = Build(new PayloadInjectionMiddlewareOptions(), async ctx =>
            {
                using var reader = new StreamReader(ctx.Request.Body);
                seenByEndpoint = await reader.ReadToEndAsync();
            });

            var ctx = ContextWith("POST", body: "{\"name\":\"perfectly fine\"}");
            await middleware.InvokeAsync(ctx);

            Assert.That(ctx.Response.StatusCode, Is.EqualTo(200));
            Assert.That(seenByEndpoint, Is.EqualTo("{\"name\":\"perfectly fine\"}"));
        }

        [Test]
        public async Task ShortCircuits_Malicious_QueryString()
        {
            var nextCalled = false;
            var middleware = Build(new PayloadInjectionMiddlewareOptions(), _ => { nextCalled = true; return Task.CompletedTask; });

            var ctx = ContextWith("POST", queryString: "?q=%3Cscript%3E");
            await middleware.InvokeAsync(ctx);

            Assert.That(nextCalled, Is.False);
            Assert.That(ctx.Response.StatusCode, Is.EqualTo(400));
        }

        [Test]
        public async Task Does_Not_Scan_Disallowed_Methods()
        {
            var nextCalled = false;
            var middleware = Build(new PayloadInjectionMiddlewareOptions(), _ => { nextCalled = true; return Task.CompletedTask; });

            var ctx = ContextWith("GET", body: "<script>");
            await middleware.InvokeAsync(ctx);

            Assert.That(nextCalled, Is.True);
        }

        [Test]
        public async Task Skips_Excluded_Paths()
        {
            var nextCalled = false;
            var opts = new PayloadInjectionMiddlewareOptions { ExcludedPaths = { "/api/richtext" } };
            var middleware = Build(opts, _ => { nextCalled = true; return Task.CompletedTask; });

            var ctx = ContextWith("POST", body: "<b>bold</b>");
            ctx.Request.Path = "/api/richtext/save";
            await middleware.InvokeAsync(ctx);

            Assert.That(nextCalled, Is.True);
        }

        [Test]
        public async Task Honors_Custom_Response()
        {
            var opts = new PayloadInjectionMiddlewareOptions
            {
                ResponseStatusCode = 422,
                ResponseContentType = "application/json",
                ResponseContentBody = "{\"error\":\"nope\"}"
            };
            var middleware = Build(opts, _ => Task.CompletedTask);

            var ctx = ContextWith("PUT", body: "a;b");
            await middleware.InvokeAsync(ctx);

            ctx.Response.Body.Position = 0;
            var written = await new StreamReader(ctx.Response.Body).ReadToEndAsync();

            Assert.That(ctx.Response.StatusCode, Is.EqualTo(422));
            Assert.That(ctx.Response.ContentType, Is.EqualTo("application/json"));
            Assert.That(written, Is.EqualTo("{\"error\":\"nope\"}"));
        }

        [Test]
        public async Task Rejects_Oversized_Body_With_413()
        {
            var opts = new PayloadInjectionMiddlewareOptions { MaxScannedBodyBytes = 4 };
            var middleware = Build(opts, _ => Task.CompletedTask);

            var ctx = ContextWith("POST", body: "this body is definitely longer than four bytes");
            await middleware.InvokeAsync(ctx);

            Assert.That(ctx.Response.StatusCode, Is.EqualTo(413));
        }
    }
}
