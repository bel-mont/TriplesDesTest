using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Crypto.Macs;
using RESTCryptography.DTO;
using TriplesDesTest.Cryptography;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace RESTCryptography.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class MacController : ControllerBase
    {
        // first 16 bytes of the hashed card id
        static byte[] kmac = { 0x65, 0x22, 0xB4, 0xE1, 0x71, 0x19, 0x5B, 0xB2, 0x18, 0x22, 0x3A, 0x97, 0x6C, 0x04, 0x01, 0x11 };
        // Exact same as kmac
        static byte[] kenc = { 0x65, 0x22, 0xB4, 0xE1, 0x71, 0x19, 0x5B, 0xB2, 0x18, 0x22, 0x3A, 0x97, 0x6C, 0x04, 0x01, 0x11 };
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
            var retailMac = new RetailMac();
            var eifd = new byte[] { 0x93, 0x77, 0x45, 0xC2, 0x08, 0x83, 0xA1, 0xBA, 0xD1, 0xE0, 0x41, 0x93, 0x72, 0x2A, 0x15, 0x92, 0x37, 0x8F, 0x81, 0xA8, 0xF1, 0xDC, 0x58, 0x91, 0x57, 0xAE, 0xB0, 0xF7, 0x54, 0x4F, 0xA1, 0xBA, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            var mac = retailMac.getMac(eifd, kmac);
            var eicc = new byte[] { 0x58, 0x60, 0x77, 0x5B, 0x4D, 0x03, 0x2C, 0xC5, 0x64, 0xBA, 0x20, 0x4B, 0x8E, 0xA8, 0x68, 0xF6, 0x94, 0xA7, 0x4E, 0x74, 0x75, 0xA8, 0xFE, 0xF2, 0x40, 0x58, 0x8B, 0xDA, 0x1A, 0xF4, 0x96, 0xCE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            var mac2 = retailMac.getMac(eicc, kmac);

            //var string1 = string.Join(" ", mac.Select(e => $"0x{e} "));
            //var string2 = string.Join(" ", mac2.Select(e => $"0x{e} "));
            //Debug.WriteLine(mac);
            //Debug.WriteLine(mac2);
            //var result = mac + mac2;
            Debug.WriteLine(retailMac.BytesToHex(mac));
            value.data = Convert.ToBase64String(mac);
            Debug.WriteLine(value.data);
            var decoded = Convert.FromBase64String(value.data);
            Debug.WriteLine(retailMac.BytesToHex(decoded));
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
