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
    }
}
