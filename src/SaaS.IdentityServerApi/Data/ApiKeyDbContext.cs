using Microsoft.EntityFrameworkCore;
using SaaS.IdentityServerApi.Models;

namespace SaaS.IdentityServerApi.Data;

public class ApiKeyDbContext : DbContext
{
    public ApiKeyDbContext(DbContextOptions<ApiKeyDbContext> options) : base(options) { }
    public DbSet<ApiKey> ApiKeys => Set<ApiKey>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ApiKey>()
            .HasIndex(k => k.PublicId)
            .IsUnique();
        modelBuilder.Entity<ApiKey>()
            .Property(k => k.PublicId)
            .HasMaxLength(60);
        modelBuilder.Entity<ApiKey>()
            .Property(k => k.Hash)
            .HasMaxLength(200);
        modelBuilder.Entity<ApiKey>()
            .Property(k => k.TenantId)
            .HasMaxLength(100);
    }
}