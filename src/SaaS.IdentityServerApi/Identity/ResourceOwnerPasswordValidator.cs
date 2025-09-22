using IdentityServer4.Models;
using IdentityServer4.Validation;
using SaaS.IdentityServerApi.Services;
using System.Security.Claims;

namespace SaaS.IdentityServerApi.Identity;

public class ResourceOwnerPasswordValidator : IResourceOwnerPasswordValidator
{
    private readonly UserService _userService;
    private readonly ILogger<ResourceOwnerPasswordValidator> _logger;

    public ResourceOwnerPasswordValidator(UserService userService, ILogger<ResourceOwnerPasswordValidator> logger)
    {
        _userService = userService;
        _logger = logger;
    }

    public async Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
    {
        var user = await _userService.ValidateCredentialsAsync(context.UserName, context.Password);
        
        if (user == null)
        {
            context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant, "Invalid credentials");
            _logger.LogWarning("Invalid login attempt for username: {Username}", context.UserName);
            return;
        }

        var claims = new List<Claim>
        {
            new("sub", user.UserId),
            new("email", user.Email),
            new("tenant_id", user.TenantId),
            new("auth_origin", "password")
        };

        // Add scope claims
        foreach (var scope in user.Scopes)
        {
            claims.Add(new Claim("scope", scope));
        }

        context.Result = new GrantValidationResult(
            subject: user.UserId,
            authenticationMethod: "password",
            claims: claims);

        _logger.LogInformation("User {Username} (tenant {Tenant}) authenticated successfully", 
            user.Username, user.TenantId);
    }
}