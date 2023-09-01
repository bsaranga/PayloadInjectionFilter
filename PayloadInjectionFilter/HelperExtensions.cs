using System.Reflection;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Zone24x7PayloadExtensionFilter.HelperExtensions
{
    public static class HelperExtensions
    {
        public static bool IsString(this PropertyInfo propInfo)
        {
            return propInfo.PropertyType.Name == "String" && propInfo.PropertyType.FullName == "System.String";
        }

        public static bool IsString(this Type objectType)
        {
            return objectType.Name == "String" && objectType.FullName == "System.String";
        }

        public static bool IsValueType(this Type objectType)
        {
            return objectType.BaseType!.Name == "ValueType" && objectType.BaseType.FullName == "System.ValueType";
        }

        public static bool IsEnumerable(this Type objectType)
        {
            return objectType.Name.Equals("List`1");
        }

        public static bool IsOneOfAllowedHttpMethods(this ActionExecutingContext context, params string[] HttpMethods)
        {
            return HttpMethods.Contains(context.HttpContext.Request.Method);
        }
    }
}
