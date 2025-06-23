using Microsoft.EntityFrameworkCore;
using VulDuende.Models;

namespace VulDuende.Data;

public class PasskeyDbContext : DbContext
{
    public PasskeyDbContext(DbContextOptions<PasskeyDbContext> options) : base(options)
    {
    }

    public DbSet<PasskeyUser> Users { get; set; }
    public DbSet<StoredCredential> Credentials { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<PasskeyUser>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Username).IsUnique();
            entity.HasIndex(e => e.Email).IsUnique();
            entity.Property(e => e.Username).IsRequired().HasMaxLength(100);
            entity.Property(e => e.Email).IsRequired().HasMaxLength(255);
            entity.Property(e => e.DisplayName).HasMaxLength(100);
        });

        modelBuilder.Entity<StoredCredential>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.UserId).IsRequired();
            entity.Property(e => e.Username).IsRequired().HasMaxLength(100);
            entity.Property(e => e.DisplayName).HasMaxLength(100);
            entity.Property(e => e.CredType).HasMaxLength(50);
            entity.Property(e => e.DeviceName).HasMaxLength(100);

            // Configure relationship
            entity.HasOne<PasskeyUser>()
                  .WithMany(u => u.Credentials)
                  .HasForeignKey(c => c.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
