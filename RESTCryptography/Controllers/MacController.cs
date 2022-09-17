using Microsoft.AspNetCore.Mvc;
using RESTCryptography.DTO;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace RESTCryptography.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class MacController : ControllerBase
    {
        // GET: api/<MacController>
        //[HttpGet]
        //public IEnumerable<string> Get()
        //{
        //    return new string[] { "value1", "value2" };
        //}

        //// GET api/<MacController>/5
        //[HttpGet("{id}")]
        //public string Get(int id)
        //{
        //    return "value";
        //}

        // POST api/<MacController>
        [HttpPost]
        public MacCheckDto Post([FromBody] MacCheckDto value)
        {
            return value;
        }

        //// PUT api/<MacController>/5
        //[HttpPut("{id}")]
        //public void Put(int id, [FromBody] string value)
        //{
        //}

        //// DELETE api/<MacController>/5
        //[HttpDelete("{id}")]
        //public void Delete(int id)
        //{
        //}
    }
}
