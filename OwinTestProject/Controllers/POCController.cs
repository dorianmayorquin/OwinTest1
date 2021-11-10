using System.Web.Http;

namespace OwinTestProject.Controllers
{
    [Authorize]
    public class POCController : ApiController
    {
        [HttpGet]
        [Route("api/TestMethod")]
        public string TestMethod()
        {
            return "Hello, C# Corner Member. ";
        }
    }
}