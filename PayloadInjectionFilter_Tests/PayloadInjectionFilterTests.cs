using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using System.Text.RegularExpressions;
using PayloadInjectionFilter_NS;
using PayloadInjectionFilter_Tests.CustomTypes;

namespace PayloadInjectionFilter_Tests
{
    [TestFixture]
    public class PayloadInjectionFilterTests
    {
        [Test]
        public void Does_Not_Execute_For_GET_Requests()
        {
            var mockLogger = new Mock<ILogger<PayloadInjectionFilter>>();
            var mockOptions = new Mock<IOptions<PayloadInjectionOptions>>();

            mockOptions.Setup(x => x.Value).Returns(new PayloadInjectionOptions
            {
                AllowedHttpMethods = new List<HttpMethod> { HttpMethod.Put, HttpMethod.Post, HttpMethod.Patch },
                Pattern = new Regex(@"[<>\&;]")
            });

            var sanitizationFilter = new PayloadInjectionFilter(mockOptions.Object, mockLogger.Object);
            var defaultHttpContext = new DefaultHttpContext();
            defaultHttpContext.Request.Method = HttpMethod.Get.Method;

            var actionContext = new ActionContext(defaultHttpContext, new RouteData(), new ActionDescriptor(), new ModelStateDictionary());
            var actionExecutingContext = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), new Dictionary<string, object>(), null);

            sanitizationFilter.OnActionExecuting(actionExecutingContext);

            Assert.That(sanitizationFilter.FilterExecuted, Is.EqualTo(false));
        }

        [TestCase("POST")]
        [TestCase("PUT")]
        [TestCase("PATCH")]
        public void ShortCircuits_For_QueryParameters_With_Malicious_Content(string httpMethod)
        {
            var mockLogger = new Mock<ILogger<PayloadInjectionFilter>>();
            var mockOptions = new Mock<IOptions<PayloadInjectionOptions>>();

            mockOptions.Setup(x => x.Value).Returns(new PayloadInjectionOptions
            {
                AllowedHttpMethods = new List<HttpMethod> { HttpMethod.Put, HttpMethod.Post, HttpMethod.Patch },
                Pattern = new Regex(@"[<>\&;]")
            });

            var sanitizationFilter = new PayloadInjectionFilter(mockOptions.Object, mockLogger.Object);
            var defaultHttpContext = new DefaultHttpContext();
            defaultHttpContext.Request.Method = httpMethod;

            var maliciousQueryParameters = new Dictionary<string, object>
            {
                {
                    "queryParam1",
                    "foo@g<>.com"
                }
            };

            var actionContext = new ActionContext(defaultHttpContext, new RouteData(), new ActionDescriptor(), new ModelStateDictionary());
            var actionExecutingContext = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), maliciousQueryParameters, null);

            sanitizationFilter.OnActionExecuting(actionExecutingContext);

            Assert.That(sanitizationFilter.FilterExecuted, Is.EqualTo(true));
            Assert.That(sanitizationFilter.ShortCircuited, Is.EqualTo(true));
        }

        [TestCase("POST")]
        [TestCase("PUT")]
        [TestCase("PATCH")]
        public void ShortCircuits_For_Malicious_Model_Bound_Content(string httpMethod)
        {
            var mockLogger = new Mock<ILogger<PayloadInjectionFilter>>();
            var mockOptions = new Mock<IOptions<PayloadInjectionOptions>>();

            mockOptions.Setup(x => x.Value).Returns(new PayloadInjectionOptions
            {
                AllowedHttpMethods = new List<HttpMethod> { HttpMethod.Put, HttpMethod.Post, HttpMethod.Patch },
                Pattern = new Regex(@"[<>\&;]")
            });

            var sanitizationFilter = new PayloadInjectionFilter(mockOptions.Object, mockLogger.Object);
            var defaultHttpContext = new DefaultHttpContext();
            defaultHttpContext.Request.Method = httpMethod;

            var maliciousBody = new Dictionary<string, object>
            {
                {
                    "userId",
                    1
                },
                {
                    "userBasicSettings",
                    new UserBasicSetting
                    {
                        UserId = 1,
                        UserCode = "Xlm001",
                        UserName = "<script>alert(\"Hello world...\")</script>"
                    }
                }
            };

            var actionContext = new ActionContext(defaultHttpContext, new RouteData(), new ActionDescriptor(), new ModelStateDictionary());
            var actionExecutingContext = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), maliciousBody, null);

            sanitizationFilter.OnActionExecuting(actionExecutingContext);

            Assert.That(sanitizationFilter.FilterExecuted, Is.EqualTo(true));
            Assert.That(sanitizationFilter.ShortCircuited, Is.EqualTo(true));
        }

        [TestCase("PATCH")]
        public void ShortCircuits_For_Lists_In_Payload(string httpMethod)
        {
            var mockLogger = new Mock<ILogger<PayloadInjectionFilter>>();
            var mockOptions = new Mock<IOptions<PayloadInjectionOptions>>();

            mockOptions.Setup(x => x.Value).Returns(new PayloadInjectionOptions
            {
                AllowedHttpMethods = new List<HttpMethod> { HttpMethod.Put, HttpMethod.Post, HttpMethod.Patch },
                Pattern = new Regex(@"[<>\&;]")
            });

            var sanitizationFilter = new PayloadInjectionFilter(mockOptions.Object, mockLogger.Object);
            var defaultHttpContext = new DefaultHttpContext();
            defaultHttpContext.Request.Method = httpMethod;

            var maliciousBody = new Dictionary<string, object>
            {
                {
                    "checkListReorder",
                    new List<Checklist>
                    {
                        new Checklist
                        {
                            SortValue = 1,
                            ChecklistItem = "NIC",
                            LinkName = "NIC DISP",
                            Link = "<script></script>",
                            ChecklistId = 2,
                            ServiceId = 24,
                        },
                        new Checklist
                        {
                            SortValue = 2,
                            ChecklistItem = "Passport",
                            LinkName = "Passport DISP",
                            Link = "",
                            ChecklistId = 1,
                            ServiceId = 24,
                        }
                    }
                }
            };

            var actionContext = new ActionContext(defaultHttpContext, new RouteData(), new ActionDescriptor(), new ModelStateDictionary());
            var actionExecutingContext = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), maliciousBody, null);

            sanitizationFilter.OnActionExecuting(actionExecutingContext);

            Assert.That(sanitizationFilter.FilterExecuted, Is.EqualTo(true));
            Assert.That(sanitizationFilter.ShortCircuited, Is.EqualTo(true));
        }
    }
}
