using Microsoft.AspNetCore.Mvc;
using TestModels;

namespace TestAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class Test : ControllerBase
    {
        [HttpGet]
        public IActionResult Check()
        {
            return Ok();
        }

        [HttpPost("single")]
        public IActionResult PostSingleValuedPayload([FromBody] SingleValuedModel singleValuedModel)
        {
            return Ok();
        }

        [HttpPost("multivalued")]
        public IActionResult PostMultiValuedPayload([FromBody] MultiValuedModel multiValuedModel)
        {
            return Ok();
        }
    }
}
