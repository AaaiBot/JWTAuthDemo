using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace JWTAuthDemo.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class MyController : ControllerBase
    {
        [AllowAnonymous]
        [HttpGet("Freebies")]
        public ActionResult<IEnumerable<string>> Freebies()
        {
            return new string[] { "Freeby1", "Freeby2", "Freeby3" };
        }

        [Authorize(Policy = "TrustedPerson")]
        [HttpGet("Valuables")]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new string[] { "Valuable1", "Valuable2", "Valuable3" };
        }

        [Authorize]
        [HttpGet("Claims")]
        public string Claims()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            var claims = identity.Claims.ToList();
            var name = claims.FirstOrDefault(a => a.Type.Contains("name")).Value;
            return $"{name} has these claims: {Environment.NewLine} {string.Join($"{Environment.NewLine} ", claims)}";
        }
    }
}

