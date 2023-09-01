using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using System.Text.RegularExpressions;
using PayloadInjectionFilter_Tests.CustomTypes;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Routing;
using Zone24x7PayloadExtensionFilter;

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

            var ctrlActionDescriptor = new ControllerActionDescriptor
            {
                ControllerName = "Service"
            };

            var actionContext = new ActionContext(defaultHttpContext, new RouteData(), ctrlActionDescriptor, new ModelStateDictionary());
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

            var ctrlActionDescriptor = new ControllerActionDescriptor
            {
                ControllerName = "Service"
            };

            var actionContext = new ActionContext(defaultHttpContext, new RouteData(), ctrlActionDescriptor, new ModelStateDictionary());
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
                    new UserSettings
                    {
                        UserId = 1,
                        UserCode = "Xlm001",
                        UserName = "<script>alert(\"Hello world...\")</script>"
                    }
                }
            };

            var ctrlActionDescriptor = new ControllerActionDescriptor
            {
                ControllerName = "Service"
            };

            var actionContext = new ActionContext(defaultHttpContext, new RouteData(), ctrlActionDescriptor, new ModelStateDictionary());
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
                    new List<ListItem>
                    {
                        new ListItem
                        {
                            ChecklistItem = "NIC",
                            LinkName = "NIC DISP",
                            Link = "<script></script>",
                            ServiceId = 24,
                        },
                        new ListItem
                        {
                            ChecklistItem = "Passport",
                            LinkName = "Passport DISP",
                            Link = "",
                            ServiceId = 24,
                        }
                    }
                }
            };

            var ctrlActionDescriptor = new ControllerActionDescriptor
            {
                ControllerName = "Service"
            };

            var actionContext = new ActionContext(defaultHttpContext, new RouteData(), ctrlActionDescriptor, new ModelStateDictionary());
            var actionExecutingContext = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), maliciousBody, null);

            sanitizationFilter.OnActionExecuting(actionExecutingContext);

            Assert.That(sanitizationFilter.FilterExecuted, Is.EqualTo(true));
            Assert.That(sanitizationFilter.ShortCircuited, Is.EqualTo(true));
        }

        [Test]
        public void Should_Pass_Through_Whitelisted_Fields()
        {
            var mockLogger = new Mock<ILogger<PayloadInjectionFilter>>();
            var mockOptions = new Mock<IOptions<PayloadInjectionOptions>>();

            mockOptions.Setup(x => x.Value).Returns(new PayloadInjectionOptions
            {
                AllowedHttpMethods = new List<HttpMethod> { HttpMethod.Put, HttpMethod.Post, HttpMethod.Patch },
                Pattern = new Regex(@"[<>\&;]"),
                WhiteListEntries = new List<WhiteListEntry> { 
                    new WhiteListEntry 
                    {
                        PathTemplate = "appointmentSettings/{id}",
                        ParameterName = "legitimateRichText",
                        PropertyNames = new List<string>
                        {
                            nameof(LegitimateRichText.AllowedRichText)
                        }
                    }
                }
            });

            var sanitizationFilter = new PayloadInjectionFilter(mockOptions.Object, mockLogger.Object);
            var defaultHttpContext = new DefaultHttpContext();
            defaultHttpContext.Request.Method = "PUT";

            var legitimateBody = new Dictionary<string, object>
            {
                {
                    "legitimateRichText",
                    new LegitimateRichText
                    {
                        ModelId = 1,
                        AllowedRichText = "<p><strong>Hello World</strong></p>\n\n<ol>\n\t<li><strong>this is a listed item</strong></li>\n\t<li><em>this is a listed item in italics</em></li>\n\t<li><s>this is a strike through item</s></li>\n</ol>\n\n<blockquote>\n<p>THIS IS Quoted text</p>\n</blockquote>\n"
                    }
                }
            };

            var ctrlActionDescriptor = new ControllerActionDescriptor
            {
                ControllerName = "Service",
                AttributeRouteInfo = new AttributeRouteInfo
                {
                    Template = "appointmentSettings/{id}"
                }
            };

            var actionContext = new ActionContext(defaultHttpContext, new RouteData(), ctrlActionDescriptor, new ModelStateDictionary());
            var actionExecutingContext = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), legitimateBody, null);

            sanitizationFilter.OnActionExecuting(actionExecutingContext);

            Assert.That(sanitizationFilter.FilterExecuted, Is.EqualTo(true));
            Assert.That(sanitizationFilter.ShortCircuited, Is.EqualTo(false));
        }

        [Test]
        public void Should_Pass_Through_Whitelisted_Fields_In_A_List_Type()
        {
            var mockLogger = new Mock<ILogger<PayloadInjectionFilter>>();
            var mockOptions = new Mock<IOptions<PayloadInjectionOptions>>();

            mockOptions.Setup(x => x.Value).Returns(new PayloadInjectionOptions
            {
                AllowedHttpMethods = new List<HttpMethod> { HttpMethod.Put, HttpMethod.Post, HttpMethod.Patch },
                Pattern = new Regex(@"[<>\&;]"),
                WhiteListEntries = new List<WhiteListEntry> {
                    new WhiteListEntry
                    {
                        PathTemplate = "appointmentSettings/{id}",
                        ParameterName = "legitimateRichText",
                        PropertyNames = new List<string>
                        {
                            nameof(LegitimateRichText.AllowedRichText)
                        }
                    }
                }
            });

            var sanitizationFilter = new PayloadInjectionFilter(mockOptions.Object, mockLogger.Object);
            var defaultHttpContext = new DefaultHttpContext();
            defaultHttpContext.Request.Method = "PUT";

            var legitimateBody = new Dictionary<string, object>
            {
                {
                    "legitimateRichText",
                    new List<LegitimateRichText>
                    {
                        new LegitimateRichText
                        {
                            ModelId = 1,
                            MoreText = "this is legitimate",
                            AllowedRichText = "Hello world..."
                        },
                        new LegitimateRichText
                        {
                            ModelId = 2,
                            MoreText = "this is legitimate",
                            AllowedRichText = "<p><strong>Hello World</strong></p>\n\n<ol>\n\t<li><strong>this is a listed item</strong></li>\n\t<li><em>this is a listed item in italics</em></li>\n\t<li><s>this is a strike through item</s></li>\n</ol>\n\n<blockquote>\n<p>THIS IS Quoted text</p>\n</blockquote>\n"
                        }
                    }
                }
            };

            var ctrlActionDescriptor = new ControllerActionDescriptor
            {
                ControllerName = "Service",
                AttributeRouteInfo = new AttributeRouteInfo
                {
                    Template = "appointmentSettings/{id}"
                }
            };

            var actionContext = new ActionContext(defaultHttpContext, new RouteData(), ctrlActionDescriptor, new ModelStateDictionary());
            var actionExecutingContext = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), legitimateBody, null);

            sanitizationFilter.OnActionExecuting(actionExecutingContext);

            Assert.That(sanitizationFilter.FilterExecuted, Is.EqualTo(true));
            Assert.That(sanitizationFilter.ShortCircuited, Is.EqualTo(false));
        }

        [TestCase("PUT")]
        public void ShortCircuits_For_Nested_Lists_In_Payload(string httpMethod)
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
                    "nestedLists",
                    new RecursiveType
                    {
                        Text1 = "Hello1",
                        Text2 = "Hello2",
                        Nested = new RecursiveType
                        {
                            Text1 = "<Hello/>",
                            Text2 = "Hello World"
                        }
                    }
                }
            };

            var ctrlActionDescriptor = new ControllerActionDescriptor
            {
                ControllerName = "Service"
            };

            var actionContext = new ActionContext(defaultHttpContext, new RouteData(), ctrlActionDescriptor, new ModelStateDictionary());
            var actionExecutingContext = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), maliciousBody, null);

            sanitizationFilter.OnActionExecuting(actionExecutingContext);

            Assert.That(sanitizationFilter.FilterExecuted, Is.EqualTo(true));
            Assert.That(sanitizationFilter.ShortCircuited, Is.EqualTo(true));
        }
    }
}
