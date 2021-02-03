using JWTAuthDemo.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly string _secretKey;
        private readonly string _issuer;

        public LoginController(IConfiguration configuration)
        {
            _secretKey = configuration["Jwt:SecretKey"];
            _issuer = configuration["Jwt:Issuer"];
        }

        [HttpGet]
        public IActionResult Login(string username, string password)
        {
            var user = GetUser(username, password);
            if (user == null)
            {
                return Unauthorized();
            }

            var claims = GetClaims(user);
            return Ok(new { token = GenerateJwt(claims) });
        }

        private static Claim[] GetClaims(User user)
        {
            switch (user.Username)
            {
                case "Richard":
                    // Claims can be either "custom" like "Permissions", or "reserved" lie the "JwtRegisteredClaimNames" defined in https://tools.ietf.org/html/rfc7519#section-4
                    return new[]
                    {
                        new Claim("Permissions", "ValuablesReader"),
                        new Claim(JwtRegisteredClaimNames.Sub, user.Username),
                        new Claim(JwtRegisteredClaimNames.Email, user.Email),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                    };
                case "Student":
                    return new[]
                    {
                        new Claim("Role", "Student"),
                        new Claim(JwtRegisteredClaimNames.Sub, user.Username),
                        new Claim(JwtRegisteredClaimNames.Email, user.Email),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                    };
                case "Teacher":
                    return new[]
                    {
                        new Claim("Role", "Teacher"),
                        new Claim(JwtRegisteredClaimNames.Sub, user.Username),
                        new Claim(JwtRegisteredClaimNames.Email, user.Email),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                    };
                default:
                    throw new NotImplementedException();
            }
        }

        private string GenerateJwt(Claim[] claims)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _issuer,
                audience: _issuer,
                claims: claims,
                expires: DateTime.Now.AddMinutes(120),
                signingCredentials: credentials);

            var encodedJwtSecurityToken = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            return encodedJwtSecurityToken;
        }

        private static User GetUser(string username, string password)
        {
            // Dramatically simplified for demo!
            if (username == "richard" && password == "123")
            {
                return new User { Username = "Richard", Email = "richard.sheridan@schoolofcode.co.uk" };
            }
            if (username == "student" && password == "123")
            {
                return new User { Username = "Student", Email = "student@schoolofcode.co.uk" };
            }
            if (username == "teacher" && password == "123")
            {
                return new User { Username = "Teacher", Email = "teacher@schoolofcode.co.uk" };
            }
            else
            {
                return null;
            }
        }
    }
}

