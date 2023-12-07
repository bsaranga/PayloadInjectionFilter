using System.Net;
using TestModels;

namespace IntegrationTests
{
    public class LibraryIntegrationTests
    {
        private HttpClient client;

        [SetUp]
        public void Setup()
        {
            client = new HttpClient();
            client.BaseAddress = new Uri("http://localhost:5000");
        }

        [Test]
        public async Task ExecutesForSingleValuedModel()
        {
            var content = new SingleValuedModel("<a href=\"https:\\www.evil.com\"/>").GetStringContent();
            var response = await client.PostAsync("api/test/single", content);

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }

        [Test]
        public async Task ExecutesForMultiValuedModel()
        {
            var content = new MultiValuedModel("Good", "Good", "<a href=\"https:\\www.evil.com\"/>").GetStringContent();
            var response = await client.PostAsync("api/test/multivalued", content);

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }
    }
}
