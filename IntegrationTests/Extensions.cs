using System.Text;
using System.Text.Json;

namespace IntegrationTests
{
    public static class Extensions
    {
        public static StringContent GetStringContent(this object model)
        {
            return new StringContent(JsonSerializer.Serialize(
                model, model.GetType(), 
                new JsonSerializerOptions { 
                    PropertyNameCaseInsensitive = true 
                }), 
                Encoding.UTF8, 
                "application/json");
        }
    }
}
