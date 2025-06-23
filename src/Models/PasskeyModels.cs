using System.ComponentModel.DataAnnotations;

namespace VulDuende.Models;

public class StoredCredential
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    public string UserId { get; set; } = string.Empty;

    public string Username { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public byte[] PublicKey { get; set; } = Array.Empty<byte>();

    public byte[] UserHandle { get; set; } = Array.Empty<byte>();

    public uint SignatureCounter { get; set; }

    public string CredType { get; set; } = string.Empty;

    public DateTime RegDate { get; set; } = DateTime.UtcNow;

    public Guid AaGuid { get; set; }

    public string? DeviceName { get; set; }

    public bool IsBackupEligible { get; set; }

    public bool IsBackedUp { get; set; }

    public string? AttestationObject { get; set; }

    public string? AttestationClientDataJson { get; set; }
}

public class PasskeyUser
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    public string Username { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public byte[] UserHandle { get; set; } = Array.Empty<byte>();

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public List<StoredCredential> Credentials { get; set; } = new();
}
