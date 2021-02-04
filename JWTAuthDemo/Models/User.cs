using System.Security.Claims;

namespace JWTAuthDemo.Models
{
    public class User
    {
        public string Username { get; set; }
        public Claim[] Claims { get; set; }
    }
}
