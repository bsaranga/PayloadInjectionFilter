using System.Reflection;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Zone24x7PayloadExtensionFilter.HelperExtensions
{
    public static class HelperExtensions
    {
        public static bool IsString(this PropertyInfo propInfo)
        {
            if (propInfo == null)
            {
                throw new ArgumentNullException(nameof(propInfo));
            }

            return propInfo.PropertyType == typeof(string);
        }

        public static bool IsString(this Type objectType)
        {
            if (objectType == null)
            {
                throw new ArgumentNullException(nameof(objectType));
            }

            return objectType == typeof(string);
        }

        public static bool IsEnumerable(this Type objectType)
        {
            return !objectType.IsString() && objectType.GetInterfaces().Any(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IEnumerable<>));
        }

        public static bool IsOneOfAllowedHttpMethods(this ActionExecutingContext context, params string[] HttpMethods)
        {
            return HttpMethods.Contains(context.HttpContext.Request.Method);
        }
    }
}
