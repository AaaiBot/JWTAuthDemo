using JWTAuthDemo.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JWTAuthDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IConfiguration config;

        public LoginController(IConfiguration config)
        {
            this.config = config;
        }

        [HttpGet]
        public IActionResult Login(string username, string password)
        {
            var login = new UserModel
            {
                UserName = username,
                Password = password
            };

            IActionResult response = Unauthorized();

            var user = AuthenticateUser(login);

            if (user != null)
            {
                var tokenStr = GenerateJsonWebToken(user);
                response = Ok(new { token = tokenStr });
            }

            return response;
        }

        [Authorize]
        [HttpPost("Claims")]
        public string Claims()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            var claims = identity.Claims.ToList();
            var username = claims[0].Value;
            return $"{username} has these claims: {Environment.NewLine} {string.Join($"{Environment.NewLine} ", claims)}";
        }

        [Authorize(Policy = "ValuablesPolicy")]
        [HttpGet("Valuables")]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new string[] { "Valuable1", "Valuable2", "Valuable3" };
        }

        private string GenerateJsonWebToken(UserModel userModel)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim("Permissions", "ValuablesReader"),
                new Claim(JwtRegisteredClaimNames.Sub, userModel.UserName),
                new Claim(JwtRegisteredClaimNames.Email, userModel.EmailAddress),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: this.config["Jwt:Issuer"],
                audience: this.config["Jwt:Issuer"],
                claims,
                expires: DateTime.Now.AddMinutes(120),
                signingCredentials: credentials);

            var encodedToken = new JwtSecurityTokenHandler().WriteToken(token);
            return encodedToken;
        }

        private UserModel AuthenticateUser(UserModel login)
        {
            // Simplified for demo. This could be a select statement on a secured database instead.
            UserModel user = null;
            if (login.UserName == "richard" && login.Password == "123")
            {
                user = new UserModel { UserName = "Richard", EmailAddress = "richard@abc.com" };
            }

            return user;
        }
    }
}

