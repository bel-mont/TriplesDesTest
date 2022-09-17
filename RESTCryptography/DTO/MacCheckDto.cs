using System.ComponentModel.DataAnnotations;

namespace RESTCryptography.DTO
{
    public class MacCheckDto
    {
        [Required]
        public string data { get; set; }
    }
}
