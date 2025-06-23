using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using System.Text;
using System.Text.Json;
using VulDuende.Data;
using VulDuende.Models;

namespace VulDuende.Services;

public interface IWebAuthnService
{
    Task<(CredentialCreateOptions options, string sessionId)> GetRegistrationOptionsAsync(string username, string displayName, string email);
    Task<bool> CompleteRegistrationAsync(string username, string attestationResponse, string sessionId);
    Task<(AssertionOptions options, string sessionId)> GetAuthenticationOptionsAsync(string? username = null);
    Task<PasskeyUser?> CompleteAuthenticationAsync(string assertionResponse, string sessionId);
    Task<List<StoredCredential>> GetUserCredentialsAsync(string userId);
    Task<bool> DeleteCredentialAsync(string credentialId, string userId);
}

public class WebAuthnService : IWebAuthnService
{
    private readonly IFido2 _fido2;
    private readonly PasskeyDbContext _context;
    private readonly ILogger<WebAuthnService> _logger;
    private readonly IMemoryCache _cache;

    public WebAuthnService(IFido2 fido2, PasskeyDbContext context, ILogger<WebAuthnService> logger, IMemoryCache cache)
    {
        _fido2 = fido2;
        _context = context;
        _logger = logger;
        _cache = cache;
    }

    public async Task<(CredentialCreateOptions options, string sessionId)> GetRegistrationOptionsAsync(string username, string displayName, string email)
    {
        try
        {
            // Check if user already exists
            var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.Username == username || u.Email == email);

            PasskeyUser user;
            if (existingUser == null)
            {
                // Create new user
                user = new PasskeyUser
                {
                    Username = username,
                    DisplayName = displayName,
                    Email = email,
                    UserHandle = Encoding.UTF8.GetBytes(Guid.NewGuid().ToString())
                };
                _context.Users.Add(user);
                await _context.SaveChangesAsync();
            }
            else
            {
                user = existingUser;
            }

            // Get existing credentials for this user
            var existingCredentials = await _context.Credentials
                .Where(c => c.UserId == user.Id)
                .Select(c => new PublicKeyCredentialDescriptor(Convert.FromBase64String(c.Id)))
                .ToListAsync();

            var fidoUser = new Fido2User
            {
                DisplayName = user.DisplayName,
                Name = user.Username,
                Id = user.UserHandle
            };

            var options = _fido2.RequestNewCredential(
                fidoUser,
                existingCredentials,
                AuthenticatorSelection.Default,
                AttestationConveyancePreference.None);

            // Store session data
            var sessionId = Guid.NewGuid().ToString();
            _cache.Set($"fido2_registration_{sessionId}", options.ToJson(), TimeSpan.FromMinutes(5));

            return (options, sessionId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating registration options for user {Username}", username);
            throw;
        }
    }

    public async Task<bool> CompleteRegistrationAsync(string username, string attestationResponse, string sessionId)
    {
        try
        {
            var storedOptionsJson = _cache.Get($"fido2_registration_{sessionId}") as string;
            if (string.IsNullOrEmpty(storedOptionsJson))
            {
                _logger.LogWarning("Registration session {SessionId} not found or expired", sessionId);
                return false;
            }

            var storedOptions = CredentialCreateOptions.FromJson(storedOptionsJson);
            var response = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(attestationResponse);

            if (response == null)
            {
                _logger.LogWarning("Invalid attestation response format");
                return false;
            }

            // Check if credential ID already exists
            IsCredentialIdUniqueToUserAsyncDelegate callback = async (args, cancellationToken) =>
            {
                var existingCred = await _context.Credentials
                    .AnyAsync(c => c.Id == Convert.ToBase64String(args.CredentialId), cancellationToken);
                return !existingCred;
            };

            // Verify the attestation
            var result = await _fido2.MakeNewCredentialAsync(response, storedOptions, callback);

            if (result.Status != "ok")
            {
                _logger.LogWarning("Credential registration failed: {Status}, {ErrorMessage}", result.Status, result.ErrorMessage);
                return false;
            }

            // Get user
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user == null)
            {
                _logger.LogWarning("User {Username} not found during registration completion", username);
                return false;
            }

            // Store the credential
            var credential = new StoredCredential
            {
                Id = Convert.ToBase64String(result.Result?.CredentialId ?? Array.Empty<byte>()),
                UserId = user.Id,
                Username = user.Username,
                DisplayName = user.DisplayName,
                PublicKey = result.Result?.PublicKey ?? Array.Empty<byte>(),
                UserHandle = user.UserHandle,
                SignatureCounter = result.Result?.Counter ?? 0,
                CredType = result.Result?.CredType ?? string.Empty,
                AaGuid = result.Result?.Aaguid ?? Guid.Empty,
                RegDate = DateTime.UtcNow,
                AttestationObject = Convert.ToBase64String(response.Response.AttestationObject),
                AttestationClientDataJson = Convert.ToBase64String(response.Response.ClientDataJson)
            };

            _context.Credentials.Add(credential);
            await _context.SaveChangesAsync();

            // Remove session data
            _cache.Remove($"fido2_registration_{sessionId}");

            _logger.LogInformation("Successfully registered passkey for user {Username}", username);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error completing registration for user {Username}", username);
            return false;
        }
    }

    public async Task<(AssertionOptions options, string sessionId)> GetAuthenticationOptionsAsync(string? username = null)
    {
        try
        {
            var allowedCredentials = new List<PublicKeyCredentialDescriptor>();

            if (!string.IsNullOrEmpty(username))
            {
                // Get credentials for specific user
                var user = await _context.Users
                    .Include(u => u.Credentials)
                    .FirstOrDefaultAsync(u => u.Username == username);

                if (user != null)
                {
                    allowedCredentials = user.Credentials
                        .Select(c => new PublicKeyCredentialDescriptor(Convert.FromBase64String(c.Id)))
                        .ToList();
                }
            }
            else
            {
                // Allow any registered credential (usernameless/discoverable)
                allowedCredentials = await _context.Credentials
                    .Select(c => new PublicKeyCredentialDescriptor(Convert.FromBase64String(c.Id)))
                    .ToListAsync();
            }

            var options = _fido2.GetAssertionOptions(
                allowedCredentials,
                UserVerificationRequirement.Preferred);

            // Store session data
            var sessionId = Guid.NewGuid().ToString();
            _cache.Set($"fido2_authentication_{sessionId}", options.ToJson(), TimeSpan.FromMinutes(5));

            return (options, sessionId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating authentication options");
            throw;
        }
    }

    public async Task<PasskeyUser?> CompleteAuthenticationAsync(string assertionResponse, string sessionId)
    {
        try
        {
            var storedOptionsJson = _cache.Get($"fido2_authentication_{sessionId}") as string;
            if (string.IsNullOrEmpty(storedOptionsJson))
            {
                _logger.LogWarning("Authentication session {SessionId} not found or expired", sessionId);
                return null;
            }

            var storedOptions = AssertionOptions.FromJson(storedOptionsJson);
            var response = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(assertionResponse);

            if (response == null)
            {
                _logger.LogWarning("Invalid assertion response format");
                return null;
            }

            // Get stored credential
            var storedCredential = await _context.Credentials
                .FirstOrDefaultAsync(c => c.Id == Convert.ToBase64String(response.Id));

            if (storedCredential == null)
            {
                _logger.LogWarning("Credential {CredentialId} not found", Convert.ToBase64String(response.Id));
                return null;
            }

            // Update signature counter callback
            IsUserHandleOwnerOfCredentialIdAsync callback = async (args, cancellationToken) =>
            {
                // The callback is called to verify the user handle, we'll update counter separately
                return true;
            };

            // Verify the assertion
            var result = await _fido2.MakeAssertionAsync(
                response,
                storedOptions,
                storedCredential.PublicKey,
                storedCredential.SignatureCounter,
                callback);

            if (result.Status != "ok")
            {
                _logger.LogWarning("Authentication failed: {Status}, {ErrorMessage}", result.Status, result.ErrorMessage);
                return null;
            }

            // Get user
            var user = await _context.Users
                .Include(u => u.Credentials)
                .FirstOrDefaultAsync(u => u.Id == storedCredential.UserId);

            if (user == null)
            {
                _logger.LogWarning("User not found for credential {CredentialId}", Convert.ToBase64String(response.Id));
                return null;
            }

            // Remove session data
            _cache.Remove($"fido2_authentication_{sessionId}");

            _logger.LogInformation("Successfully authenticated user {Username} with passkey", user.Username);
            return user;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error completing authentication");
            return null;
        }
    }

    public async Task<List<StoredCredential>> GetUserCredentialsAsync(string userId)
    {
        return await _context.Credentials
            .Where(c => c.UserId == userId)
            .OrderByDescending(c => c.RegDate)
            .ToListAsync();
    }

    public async Task<bool> DeleteCredentialAsync(string credentialId, string userId)
    {
        try
        {
            var credential = await _context.Credentials
                .FirstOrDefaultAsync(c => c.Id == credentialId && c.UserId == userId);

            if (credential == null)
            {
                return false;
            }

            _context.Credentials.Remove(credential);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Deleted credential {CredentialId} for user {UserId}", credentialId, userId);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting credential {CredentialId}", credentialId);
            return false;
        }
    }
}
