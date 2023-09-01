using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using PayloadInjectionFilter_Tests.CustomTypes;
using Zone24x7PayloadExtensionFilter.HelperExtensions;

namespace PayloadInjectionFilter_Tests
{
    [TestFixture]
    internal class HelperTests
    {

        [Test (Description = "Determines that the type of an object is string")]
        public void DeterminesStringTypeFromObjectType()
        {
            object someObject = "thisisastring...";
            Type someObjectType = someObject.GetType();

            Assert.That(someObjectType.IsString(), Is.True);
        }

        [Test (Description = "Determines that the type of an object is not string, if it is a value type.")]
        public void DistinguishesStringTypeFromValueType()
        {
            object secretOfTheUniverse = 42;
            Type secretOfTheUniverseType = secretOfTheUniverse.GetType();

            Assert.That(secretOfTheUniverseType.IsString(), Is.False);
        }

        [Test (Description = "Determines that the type of an object's property is string")]
        public void DeterminesStringTypeFromPropertyType()
        {
            var userSetting = new UserSettings
            {
                UserId = 1,
                UserCode = "Foobar",
                UserName = "Username"
            };

            Type userSettingType = userSetting.GetType();
            
            var userId = userSettingType.GetProperties().Single(p => p.Name.Equals("UserId")).GetValue(userSetting).GetType();
            var userCode = userSettingType.GetProperties().Single(p => p.Name.Equals("UserCode")).GetValue(userSetting).GetType();

            Assert.That(userId.IsString(), Is.False);
            Assert.That(userCode.IsString(), Is.True);
        }

        [Test(Description = "Determines stringy-ness from PropertyInfo")]
        public void DeterminesStringTypeFromPropertyInfo()
        {
            var userSetting = new UserSettings
            {
                UserId = 1,
                UserCode = "Foobar",
                UserName = "Username"
            };

            Type userSettingType = userSetting.GetType();

            var userId = userSettingType.GetProperties().Single(p => p.Name.Equals("UserId"));
            var userCode = userSettingType.GetProperties().Single(p => p.Name.Equals("UserCode"));

            Assert.That(userId.IsString(), Is.False);
            Assert.That(userCode.IsString(), Is.True);
        }

        [Test(Description = "Determines an enumerable type")]
        public void DeterminesAnObjectTypeIsAnEnumerable()
        {
            var list = new List<int>
            {
                1, 2, 3,
            };

            int[] list2 = new int[] { 1, 2, 3 };

            HashSet<int> list3 = new HashSet<int> 
            {
                1, 2, 3,
            };

            Assert.True(list.GetType().IsEnumerable());
            Assert.True(list2.GetType().IsEnumerable());
            Assert.True(list3.GetType().IsEnumerable());
        }

        [Test(Description = "A string should not pass out as enumerable")]
        public void AStringShouldNotPassAsAnEnumerable()
        {
            string someString = "this is a nice string and not really an enumerable in this context";
            Assert.IsFalse(someString.GetType().IsEnumerable());
        }

        [Test(Description = "Returns true if the action executing context is of the expected HTTP Verb")]
        public void ReturnsTrueIfTheActionExecutingContextIsOfExpectedHttpVerb()
        {
            var httpContext = new DefaultHttpContext();
            httpContext.Request.Method = "POST";

            var actionExecContext = new ActionExecutingContext(
                new ActionContext(
                    httpContext, 
                    new RouteData(), 
                    new ActionDescriptor()
                ), 
                new List<IFilterMetadata>{ }, 
                new Dictionary<string, object> { }, 
                null
            );

            Assert.IsTrue(actionExecContext.IsOneOfAllowedHttpMethods(new string[] { "POST", "PUT", "PATCH" }));
            Assert.IsFalse(actionExecContext.IsOneOfAllowedHttpMethods(new string[] { "OPTIONS", "HEAD", "DELETE" }));
        }
    }
}
