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
                return Unauthorized("The username or password is incorrect");
            }

            var expiresOn = DateTime.Now.AddMinutes(120);
            return Ok(new { token = GenerateJwt(user, expiresOn), expiresOn = $"{expiresOn:F}" });
        }

        private string GenerateJwt(User user, DateTime expiresOn)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _issuer,
                audience: _issuer,
                claims: user.Claims,
                expires: expiresOn,
                signingCredentials: credentials);

            var encodedJwtSecurityToken = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            return encodedJwtSecurityToken;
        }

        private static User GetUser(string username, string password)
        {
            // Dramatically simplified for demo!
            if (username == "richard" && password == "123")
            {
                return new User { 
                    Username = username,
                    Claims = new[]
                    {
                        // Claims can be either "custom" like "Permissions", or "reserved" lie the "JwtRegisteredClaimNames" defined in https://tools.ietf.org/html/rfc7519#section-4
                        new Claim("Permissions", "ValuablesReader"),
                        new Claim(JwtRegisteredClaimNames.Sub, username),
                        new Claim(JwtRegisteredClaimNames.Email, "richard.sheridan@schoolofcode.co.uk"),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                    }
                };
            }

            if (username == "student" && password == "123")
            {
                return new User
                {
                    Username = username,
                    Claims = new[]
                    {
                        new Claim("SchoolRole", "Student"),
                        new Claim(JwtRegisteredClaimNames.Sub, username),
                        new Claim(JwtRegisteredClaimNames.Email, "student@schoolofcode.co.uk"),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                    }
                };
            }

            if (username == "teacher" && password == "123")
            {
                return new User { 
                    Username = "Teacher", 
                    Claims = new[]
                    {
                        new Claim("SchoolRole", "Teacher"),
                        new Claim(JwtRegisteredClaimNames.Sub, username),
                        new Claim(JwtRegisteredClaimNames.Email, "teacher@schoolofcode.co.uk"),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                    }
                };
            }

            return null;
        }
    }
}

