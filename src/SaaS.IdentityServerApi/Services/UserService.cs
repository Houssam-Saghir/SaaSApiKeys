using Microsoft.AspNetCore.Identity;
using SaaS.IdentityServerApi.Models;

namespace SaaS.IdentityServerApi.Services;

public class UserService
{
    private readonly IPasswordHasher<User> _passwordHasher;
    private readonly ILogger<UserService> _logger;

    public UserService(IPasswordHasher<User> passwordHasher, ILogger<UserService> logger)
    {
        _passwordHasher = passwordHasher;
        _logger = logger;
    }

    // Demo users - replace with real database in production
    private readonly List<User> _users = new()
    {
        new User
        {
            UserId = "user-123",
            Username = "demo@tenant-abc.com",
            TenantId = "tenant-abc",
            Email = "demo@tenant-abc.com",
            IsActive = true,
            Scopes = new List<string> { "api1" }
        },
        new User
        {
            UserId = "user-456",
            Username = "user@example.com",
            TenantId = "tenant-example",
            Email = "user@example.com",
            IsActive = true,
            Scopes = new List<string> { "api1" }
        }
    };

    public async Task<User?> ValidateCredentialsAsync(string username, string password)
    {
        var user = _users.FirstOrDefault(u => 
            u.Username.Equals(username, StringComparison.OrdinalIgnoreCase) && 
            u.IsActive);

        if (user == null)
            return null;

        // For demo purposes, accept any password. In production, verify against PasswordHash
        if (string.IsNullOrEmpty(user.PasswordHash))
        {
            // Demo: any password works
            _logger.LogWarning("Demo mode: accepting any password for user {Username}", username);
            return user;
        }

        var result = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password);
        return result == PasswordVerificationResult.Success ? user : null;
    }

    public async Task<User?> FindByUsernameAsync(string username)
    {
        return _users.FirstOrDefault(u => 
            u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
    }
}