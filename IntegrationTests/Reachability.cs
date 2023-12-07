using System.Net;

namespace IntegrationTests
{
    /// <summary>
    /// The TestAPI should be running before running the integration tests
    /// </summary>
    public class Reachability
    {
        HttpClient client;

        [SetUp]
        public void Setup()
        {
            client = new HttpClient();
            client.BaseAddress = new Uri("http://localhost:5000");
        }

        [Test]
        public async Task ApiIsReachable()
        {
            var response = await client.GetAsync("api/test");
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        }
    }
}