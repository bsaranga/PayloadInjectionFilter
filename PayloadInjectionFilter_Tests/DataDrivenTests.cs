using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using PayloadInjectionFilter_Tests.CustomTypes;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Zone24x7PayloadExtensionFilter;
using Microsoft.AspNetCore.Routing;
using Newtonsoft.Json;

namespace PayloadInjectionFilter_Tests
{
    [TestFixture]
    public class DataDrivenTests
    {
        [Test]
        public void FailsAppointmentSettingsModelThatContainsBadData()
        {
            string path = Path.Combine(Directory.GetCurrentDirectory(), "TestData", "appointmentSettings.json");
            var datum = File.ReadAllText(path, Encoding.UTF8);

            var deserializedDatum = System.Text.Json.JsonSerializer.Deserialize<ServiceAppointmentSetting>(datum, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            });

            var mockLogger = new Mock<ILogger<PayloadInjectionFilter>>();
            var mockOptions = new Mock<IOptions<PayloadInjectionOptions>>();

            mockOptions.Setup(x => x.Value).Returns(new PayloadInjectionOptions
            {
                AllowedHttpMethods = new List<HttpMethod> { HttpMethod.Put, HttpMethod.Post, HttpMethod.Patch },
                Pattern = new Regex(@"[<>\&;]")
            });

            var sanitizationFilter = new PayloadInjectionFilter(mockOptions.Object, mockLogger.Object);
            var defaultHttpContext = new DefaultHttpContext();
            defaultHttpContext.Request.Method = "PUT";

            var maliciousBody = new Dictionary<string, object>
            {
                {
                    "deserializedDatum",
                    deserializedDatum
                }
            };

            var ctrlActionDescriptor = new ControllerActionDescriptor
            {
                ControllerName = "Service"
            };

            var actionContext = new ActionContext(defaultHttpContext, new RouteData(), ctrlActionDescriptor, new ModelStateDictionary());
            var actionExecutingContext = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), maliciousBody, null);

            sanitizationFilter.OnActionExecuting(actionExecutingContext);

            Assert.That(sanitizationFilter.FilterHasExecuted, Is.EqualTo(true));
            Assert.That(sanitizationFilter.HasShortCircuited, Is.EqualTo(true));
            Assert.That((sanitizationFilter.GetCurrentContext().Result as ContentResult).StatusCode, Is.EqualTo(400));
        }

        [Test]
        public void FailsLobbyEntryModelThatContainsBadData()
        {
            string path = Path.Combine(Directory.GetCurrentDirectory(), "TestData", "lobbyEntry.json");

            var datum = File.ReadAllText(path, Encoding.UTF8);

            var deserializedDatum = System.Text.Json.JsonSerializer.Deserialize<LobbyCheckInDto>(datum);

            var mockLogger = new Mock<ILogger<PayloadInjectionFilter>>();
            var mockOptions = new Mock<IOptions<PayloadInjectionOptions>>();

            mockOptions.Setup(x => x.Value).Returns(new PayloadInjectionOptions
            {
                AllowedHttpMethods = new List<HttpMethod> { HttpMethod.Put, HttpMethod.Post, HttpMethod.Patch },
                Pattern = new Regex(@"[<>\&;]")
            });

            var sanitizationFilter = new PayloadInjectionFilter(mockOptions.Object, mockLogger.Object);
            var defaultHttpContext = new DefaultHttpContext();
            defaultHttpContext.Request.Method = "PUT";

            var maliciousBody = new Dictionary<string, object>
            {
                {
                    "deserializedDatum",
                    deserializedDatum
                }
            };

            var ctrlActionDescriptor = new ControllerActionDescriptor
            {
                ControllerName = "Service"
            };

            var actionContext = new ActionContext(defaultHttpContext, new RouteData(), ctrlActionDescriptor, new ModelStateDictionary());
            var actionExecutingContext = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), maliciousBody, null);

            sanitizationFilter.OnActionExecuting(actionExecutingContext);

            Assert.That(sanitizationFilter.FilterHasExecuted, Is.EqualTo(true));
            Assert.That(sanitizationFilter.HasShortCircuited, Is.EqualTo(true));
            Assert.That((sanitizationFilter.GetCurrentContext().Result as ContentResult).StatusCode, Is.EqualTo(400));
        }

        [Test]
        public void FailsLocationHolidayDetailsModelThatContainsBadData()
        {
            string path = Path.Combine(Directory.GetCurrentDirectory(), "TestData", "locationHolidayDetail.json");

            var datum = File.ReadAllText(path, Encoding.UTF8);

            var deserializedDatum = JsonConvert.DeserializeObject<LocationHolidayDetail>(datum);

            var mockLogger = new Mock<ILogger<PayloadInjectionFilter>>();
            var mockOptions = new Mock<IOptions<PayloadInjectionOptions>>();

            mockOptions.Setup(x => x.Value).Returns(new PayloadInjectionOptions
            {
                AllowedHttpMethods = new List<HttpMethod> { HttpMethod.Put, HttpMethod.Post, HttpMethod.Patch },
                Pattern = new Regex(@"[<>\&;]")
            });

            var sanitizationFilter = new PayloadInjectionFilter(mockOptions.Object, mockLogger.Object);
            var defaultHttpContext = new DefaultHttpContext();
            defaultHttpContext.Request.Method = "PUT";

            var maliciousBody = new Dictionary<string, object>
            {
                {
                    "deserializedDatum",
                    deserializedDatum
                }
            };

            var ctrlActionDescriptor = new ControllerActionDescriptor
            {
                ControllerName = "Service"
            };

            var actionContext = new ActionContext(defaultHttpContext, new RouteData(), ctrlActionDescriptor, new ModelStateDictionary());
            var actionExecutingContext = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), maliciousBody, null);

            sanitizationFilter.OnActionExecuting(actionExecutingContext);

            Assert.That(sanitizationFilter.FilterHasExecuted, Is.EqualTo(true));
            Assert.That(sanitizationFilter.HasShortCircuited, Is.EqualTo(true));
            Assert.That(sanitizationFilter.GetCaughtMaliciousContent().Contains("Christmas <>hello</>"), Is.True);
            Assert.That((sanitizationFilter.GetCurrentContext().Result as ContentResult).StatusCode, Is.EqualTo(400));
        }

        [Test]
        public void FailsSortOrderViewModelThatContainsBadData()
        {
            string path = Path.Combine(Directory.GetCurrentDirectory(), "TestData", "sortOrder.json");
            var datum = File.ReadAllText(path, Encoding.UTF8);

            var deserializedDatum = JsonConvert.DeserializeObject<SortOrderViewModel>(datum);

            var mockLogger = new Mock<ILogger<PayloadInjectionFilter>>();
            var mockOptions = new Mock<IOptions<PayloadInjectionOptions>>();

            mockOptions.Setup(x => x.Value).Returns(new PayloadInjectionOptions
            {
                AllowedHttpMethods = new List<HttpMethod> { HttpMethod.Put, HttpMethod.Post, HttpMethod.Patch },
                Pattern = new Regex(@"[<>\&;]")
            });

            var sanitizationFilter = new PayloadInjectionFilter(mockOptions.Object, mockLogger.Object);
            var defaultHttpContext = new DefaultHttpContext();
            defaultHttpContext.Request.Method = "PUT";

            var maliciousBody = new Dictionary<string, object>
            {
                {
                    "deserializedDatum",
                    deserializedDatum
                }
            };

            var ctrlActionDescriptor = new ControllerActionDescriptor
            {
                ControllerName = "Service"
            };

            var actionContext = new ActionContext(defaultHttpContext, new RouteData(), ctrlActionDescriptor, new ModelStateDictionary());
            var actionExecutingContext = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), maliciousBody, null);

            sanitizationFilter.OnActionExecuting(actionExecutingContext);

            Assert.That(sanitizationFilter.FilterHasExecuted, Is.EqualTo(true));
            Assert.That(sanitizationFilter.HasShortCircuited, Is.EqualTo(true));
            Assert.That(sanitizationFilter.GetCaughtMaliciousContent().Contains("Catty Service4 <hello/>"), Is.True);
            Assert.That((sanitizationFilter.GetCurrentContext().Result as ContentResult).StatusCode, Is.EqualTo(400));
        }

        [Test]
        public void FailsListOfUserSkillsThatContainsBadData()
        {
            string path = Path.Combine(Directory.GetCurrentDirectory(), "TestData", "userSkills.json");
            var datum = File.ReadAllText(path, Encoding.UTF8);

            var deserializedDatum = JsonConvert.DeserializeObject<List<UserService>>(datum);

            var mockLogger = new Mock<ILogger<PayloadInjectionFilter>>();
            var mockOptions = new Mock<IOptions<PayloadInjectionOptions>>();

            mockOptions.Setup(x => x.Value).Returns(new PayloadInjectionOptions
            {
                AllowedHttpMethods = new List<HttpMethod> { HttpMethod.Put, HttpMethod.Post, HttpMethod.Patch },
                Pattern = new Regex(@"[<>\&;]")
            });

            var sanitizationFilter = new PayloadInjectionFilter(mockOptions.Object, mockLogger.Object);
            var defaultHttpContext = new DefaultHttpContext();
            defaultHttpContext.Request.Method = "PUT";

            var maliciousBody = new Dictionary<string, object>
            {
                {
                    "deserializedDatum",
                    deserializedDatum
                }
            };

            var ctrlActionDescriptor = new ControllerActionDescriptor
            {
                ControllerName = "Service"
            };

            var actionContext = new ActionContext(defaultHttpContext, new RouteData(), ctrlActionDescriptor, new ModelStateDictionary());
            var actionExecutingContext = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), maliciousBody, null);

            sanitizationFilter.OnActionExecuting(actionExecutingContext);

            Assert.That(sanitizationFilter.FilterHasExecuted, Is.EqualTo(true));
            Assert.That(sanitizationFilter.HasShortCircuited, Is.EqualTo(true));
            Assert.That(sanitizationFilter.GetCaughtMaliciousContent().Contains("Catty Service3 <hello/>&foobar"), Is.True);
            Assert.That((sanitizationFilter.GetCurrentContext().Result as ContentResult).StatusCode, Is.EqualTo(400));
        }

        [Test]
        public void ComplexCustomTypeShouldNotFailDuringRecursion()
        {
            string path = Path.Combine(Directory.GetCurrentDirectory(), "TestData", "detailsViewCharDataRequests.json");
            var datum = File.ReadAllText(path, Encoding.UTF8);

            var deserializedDatum = JsonConvert.DeserializeObject<DetailsViewChartDataRequest>(datum);

            var mockLogger = new Mock<ILogger<PayloadInjectionFilter>>();
            var mockOptions = new Mock<IOptions<PayloadInjectionOptions>>();

            mockOptions.Setup(x => x.Value).Returns(new PayloadInjectionOptions
            {
                AllowedHttpMethods = new List<HttpMethod> { HttpMethod.Put, HttpMethod.Post, HttpMethod.Patch },
                Pattern = new Regex(@"[<>\&;]")
            });

            var sanitizationFilter = new PayloadInjectionFilter(mockOptions.Object, mockLogger.Object);
            var defaultHttpContext = new DefaultHttpContext();
            defaultHttpContext.Request.Method = "PUT";

            var maliciousBody = new Dictionary<string, object>
            {
                {
                    "deserializedDatum",
                    deserializedDatum
                }
            };

            var ctrlActionDescriptor = new ControllerActionDescriptor
            {
                ControllerName = "Report"
            };

            var actionContext = new ActionContext(defaultHttpContext, new RouteData(), ctrlActionDescriptor, new ModelStateDictionary());
            var actionExecutingContext = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), maliciousBody, null);

            sanitizationFilter.OnActionExecuting(actionExecutingContext);

            Assert.That(sanitizationFilter.FilterHasExecuted, Is.EqualTo(true));
            Assert.That(sanitizationFilter.HasShortCircuited, Is.EqualTo(false));
        }
    }
}
