using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Security.Claims;

namespace JWTAuthDemo.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class SchoolWikiController : ControllerBase
    {
        [AllowAnonymous]
        [HttpGet("Blogs")]
        public ActionResult<int[]> Blogs(int id)
        {
            return new[] { 1, 2, 3 };
        }

        [AllowAnonymous]
        [HttpGet("Blogs/{id}")]
        public ActionResult<string> ReadBlog(int id)
        {
            return $"The blog with {id} for {GetName() ?? "[Unauthorised]"}";
        }

        [Authorize(Policy = "BlogWriter")]
        [HttpPost("Blogs/{content}")]
        public ActionResult<long> InsertBlog(string content)
        {
            return DateTime.Now.Ticks;
        }

        [Authorize(Policy = "BlogAdministrator")]
        [HttpDelete("Blogs/{id}")]
        public ActionResult DeleteBlog(int id)
        {
            return Ok();
        }

        private string GetName()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            var claims = identity.Claims.ToList();
            var name = claims.FirstOrDefault(a => a.Type.Contains("name"))?.Value;
            return name;
        }
    }
}

