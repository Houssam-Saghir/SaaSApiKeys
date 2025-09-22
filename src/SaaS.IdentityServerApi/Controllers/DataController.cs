using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SaaS.IdentityServerApi.Authentication;
using System.Security.Claims;

namespace SaaS.IdentityServerApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class DataController : ControllerBase
{
    [HttpGet]
    [Authorize] // Uses the policy that accepts both schemes
    public IActionResult Get()
    {
        return Ok(new
        {
            message = "Protected SaaS data",
            subject = User.FindFirstValue("sub"),
            tenant = User.FindFirstValue("tenant_id"),
            owner = User.FindFirstValue("owner_sub"),
            scopes = User.Claims.Where(c => c.Type == "scope").Select(c => c.Value).ToArray(),
            issuedVia = User.FindFirstValue("auth_origin") ?? "unknown",
            authenticationType = User.Identity?.AuthenticationType,
            authenticationScheme = HttpContext.User.Identity?.AuthenticationType
        });
    }
}