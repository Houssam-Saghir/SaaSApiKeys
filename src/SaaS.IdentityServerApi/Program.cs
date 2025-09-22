using IdentityServer4;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SaaS.IdentityServerApi.Data;
using SaaS.IdentityServerApi.Identity;
using SaaS.IdentityServerApi.Models; 
using SaaS.IdentityServerApi.Services;
using Serilog;
using Microsoft.AspNetCore.Identity;

var builder = WebApplication.CreateBuilder(args);

// Serilog basic
builder.Host.UseSerilog((ctx, cfg) =>
{
    cfg.ReadFrom.Configuration(ctx.Configuration)
       .WriteTo.Console();
});

// EF InMemory (replace with real DB provider in prod)
builder.Services.AddDbContext<ApiKeyDbContext>(o => o.UseInMemoryDatabase("ApiKeys"));
builder.Services.AddScoped<ApiKeyService>();
builder.Services.AddScoped<UserService>();
builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();

// IdentityServer4 configuration
builder.Services.AddIdentityServer(options =>
{
    options.EmitStaticAudienceClaim = true;
})
.AddDeveloperSigningCredential() // dev only
.AddInMemoryApiScopes(Config.ApiScopes)
.AddInMemoryApiResources(Config.ApiResources)
.AddInMemoryClients(Config.Clients)
.AddInMemoryIdentityResources(Config.IdentityResources)
.AddResourceOwnerValidator<ResourceOwnerPasswordValidator>()
.AddExtensionGrantValidator<ApiKeyGrantValidator>();

// Single authentication configuration
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, opts =>
{
    opts.Authority = "https://localhost:64130";
    opts.RequireHttpsMetadata = false; // dev
    opts.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateAudience = false
    };
})
.AddScheme<SaaS.IdentityServerApi.Authentication.ApiKeyAuthenticationSchemeOptions, 
            SaaS.IdentityServerApi.Authentication.ApiKeyAuthenticationHandler>(
    SaaS.IdentityServerApi.Authentication.ApiKeyAuthenticationSchemeOptions.DefaultScheme, 
    options => { });

builder.Services.AddAuthorization(opts =>
{
    opts.AddPolicy("ApiScope", policy =>
    {
        policy.RequireClaim("scope", "api1");
    });
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.UseSerilogRequestLogging();
app.UseHttpsRedirection();

// Swagger (dev convenience)
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseIdentityServer();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.MapGet("/", () => new
{
    message = "SaaS IdentityServer4 + API Key Extension Grant demo",
    tokenEndpoint = "/connect/token",
    apiKeysEndpoint = "/api/apikeys",
    protectedEndpoint = "/api/data"
});

app.Run();