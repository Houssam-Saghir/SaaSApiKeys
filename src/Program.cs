using ApiKeys;
using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

// --- Configuration ---
builder.Configuration["ApiKey:HashSecret"] = builder.Configuration["API_KEY_HASH_SECRET"] 
    ?? "DEV_ONLY_CHANGE_ME_TO_LONG_RANDOM_SECRET_+_MIN_64_CHARS";

// --- EF Core (InMemory for demo) ---
builder.Services.AddDbContext<ApiKeyDbContext>(o => o.UseInMemoryDatabase("ApiKeys"));

builder.Services.AddScoped<ApiKeyService>();

// --- IdentityServer (Duende) basic in-memory config ---
builder.Services.AddIdentityServer(options =>
{
    options.EmitStaticAudienceClaim = true;
})
.AddInMemoryApiScopes(new[]
{
    new ApiScope("api1","Sample API")
})
.AddInMemoryClients(new[]
{
    // A sample standard client (client_credentials) - optional
    new Client
    {
        ClientId = "machine.client",
        AllowedGrantTypes = GrantTypes.ClientCredentials,
        ClientSecrets = { new Secret("machine_secret".Sha256()) },
        AllowedScopes = { "api1" }
    }
})
.AddInMemoryApiResources(new[]
{
    new ApiResource("api1-resource"){ Scopes = { "api1" } }
})
.AddInMemoryIdentityResources(new IdentityResource[]
{
    new IdentityResources.OpenId()
})
.AddDeveloperSigningCredential()
.AddExtensionGrantValidator<ApiKeyGrantValidator>(); // custom grant

// --- JWT Auth for Duende-issued tokens ---
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, opts =>
{
    opts.Authority = "https://localhost:5001";
    opts.RequireHttpsMetadata = false; // dev only
    opts.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateAudience = false
    };
})
// Add custom API Key scheme
.AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>("ApiKey", o =>
{
    o.HeaderName = "X-Api-Key";
});

builder.Services.AddAuthorization(options =>
{
    // Accept either JWT Bearer or ApiKey for "ApiAccess"
    options.AddPolicy("ApiAccess", policy =>
    {
        policy.RequireAssertion(ctx =>
            ctx.User.HasClaim(c => c.Type == "scope" && c.Value == "api1"));
    });
});

var app = builder.Build();

app.UseHttpsRedirection();
app.UseIdentityServer();

// IMPORTANT: We want both JWT and ApiKey available.
// Order: Authentication -> Authorization
app.UseAuthentication();
app.UseAuthorization();

// -------------- API Key Management Endpoints --------------
// NOTE: In real app secure these with user auth (e.g., cookie or OIDC login). For demo we fake a user id header.

string GetDemoUserId(HttpContext ctx) =>
    ctx.Request.Headers.TryGetValue("X-Demo-User", out var v) ? v.ToString() : "user-123";

app.MapPost("/api-keys", async (ApiKeyService service, HttpContext ctx, string? scopes, int? ttlMinutes) =>
{
    var userId = GetDemoUserId(ctx);
    var scopeList = string.IsNullOrWhiteSpace(scopes) ? new[] { "api1" } : scopes.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
    TimeSpan? lifetime = ttlMinutes.HasValue ? TimeSpan.FromMinutes(ttlMinutes.Value) : null;
    var (plain, entity) = await service.CreateKeyAsync(userId, scopeList, lifetime);
    return Results.Json(new
    {
        apiKey = plain, // show once
        id = entity.PublicId,
        scopes = entity.GetScopes(),
        expiresUtc = entity.ExpiresUtc
    });
});

app.MapGet("/api-keys", async (ApiKeyService service, HttpContext ctx) =>
{
    var userId = GetDemoUserId(ctx);
    var list = await service.ListAsync(userId);
    return list.Select(k => new
    {
        id = k.PublicId,
        scopes = k.GetScopes(),
        createdUtc = k.CreatedUtc,
        expiresUtc = k.ExpiresUtc,
        lastUsedUtc = k.LastUsedUtc
    });
});

app.MapDelete("/api-keys/{id}", async (ApiKeyService service, HttpContext ctx, string id) =>
{
    var userId = GetDemoUserId(ctx);
    var ok = await service.RevokeAsync(id, userId);
    return ok ? Results.Ok() : Results.NotFound();
});

// -------------- Exchange API Key for Access Token --------------
// Client uses: POST /connect/token (normal Duende endpoint) with:
// grant_type=api_key&api_key=<value>&scope=api1
// Handled by ApiKeyGrantValidator automatically.

// -------------- Direct Protected Resource --------------
app.MapGet("/data", (HttpContext http) =>
{
    return Results.Json(new
    {
        message = "Protected data",
        authSchemes = http.User.Identities.Select(i => i.AuthenticationType).ToArray(),
        claims = http.User.Claims.Select(c => new { c.Type, c.Value })
    });
})
.RequireAuthorization("ApiAccess")
.WithMetadata(new Microsoft.AspNetCore.Authorization.AuthorizeAttribute
{
    AuthenticationSchemes = $"{JwtBearerDefaults.AuthenticationScheme},ApiKey"
});

app.MapGet("/", () => "API Key + Duende demo running.");
app.Run();