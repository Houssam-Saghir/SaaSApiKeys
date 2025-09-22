using Microsoft.EntityFrameworkCore;

namespace ApiKeys;

public class ApiKeyDbContext : DbContext
{
    public ApiKeyDbContext(DbContextOptions<ApiKeyDbContext> options) : base(options) { }

    public DbSet<ApiKey> ApiKeys => Set<ApiKey>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ApiKey>()
            .HasIndex(k => k.PublicId)
            .IsUnique();
    }
}