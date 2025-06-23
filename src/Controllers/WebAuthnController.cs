using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using VulDuende.Services;

namespace VulDuende.Controllers;

[ApiController]
[Route("api/[controller]")]
public class WebAuthnController : ControllerBase
{
    private readonly IWebAuthnService _webAuthnService;
    private readonly ILogger<WebAuthnController> _logger;

    public WebAuthnController(IWebAuthnService webAuthnService, ILogger<WebAuthnController> logger)
    {
        _webAuthnService = webAuthnService;
        _logger = logger;
    }

    [HttpPost("register/begin")]
    public async Task<IActionResult> BeginRegistration([FromBody] BeginRegistrationRequest request)
    {
        try
        {
            if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Email))
            {
                return BadRequest("Username and email are required");
            }

            var (options, sessionId) = await _webAuthnService.GetRegistrationOptionsAsync(
                request.Username,
                request.DisplayName ?? request.Username,
                request.Email);

            // Store session ID in HTTP session for the client
            HttpContext.Session.SetString("passkey_session", sessionId);

            // Create a properly formatted response for the client
            var clientOptions = new
            {
                challenge = Convert.ToBase64String(options.Challenge),
                rp = new
                {
                    id = options.Rp.Id,
                    name = options.Rp.Name
                },
                user = new
                {
                    id = Convert.ToBase64String(options.User.Id),
                    name = options.User.Name,
                    displayName = options.User.DisplayName
                },
                pubKeyCredParams = options.PubKeyCredParams.Select(p => new
                {
                    type = p.Type,
                    alg = p.Alg
                }).ToArray(),
                authenticatorSelection = options.AuthenticatorSelection,
                timeout = options.Timeout,
                attestation = options.Attestation.ToString().ToLower(),
                excludeCredentials = options.ExcludeCredentials?.Select(c => new
                {
                    id = Convert.ToBase64String(c.Id),
                    type = c.Type,
                    transports = c.Transports
                }).ToArray()
            };

            return Ok(new
            {
                options = clientOptions,
                sessionId
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error beginning registration for user {Username}", request.Username);
            return StatusCode(500, "Registration initiation failed");
        }
    }

    [HttpPost("register/complete")]
    public async Task<IActionResult> CompleteRegistration([FromBody] CompleteRegistrationRequest request)
    {
        try
        {
            if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.AttestationResponse))
            {
                return BadRequest("Username and attestation response are required");
            }

            var sessionId = request.SessionId ?? HttpContext.Session.GetString("passkey_session");
            if (string.IsNullOrEmpty(sessionId))
            {
                return BadRequest("No active registration session found");
            }

            var success = await _webAuthnService.CompleteRegistrationAsync(
                request.Username,
                request.AttestationResponse,
                sessionId);

            if (success)
            {
                HttpContext.Session.Remove("passkey_session");
                HttpContext.Session.Remove($"registration_options_{sessionId}");
                return Ok(new { success = true, message = "Passkey registered successfully" });
            }

            return BadRequest("Registration failed");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error completing registration for user {Username}", request.Username);
            return StatusCode(500, "Registration completion failed");
        }
    }

    [HttpPost("authenticate/begin")]
    public async Task<IActionResult> BeginAuthentication([FromBody] BeginAuthenticationRequest? request = null)
    {
        try
        {
            var (options, sessionId) = await _webAuthnService.GetAuthenticationOptionsAsync(request?.Username);

            HttpContext.Session.SetString("auth_session", sessionId);

            // Create a properly formatted response for the client
            var clientOptions = new
            {
                challenge = Convert.ToBase64String(options.Challenge),
                timeout = options.Timeout,
                rpId = options.RpId,
                allowCredentials = options.AllowCredentials?.Select(c => new
                {
                    id = Convert.ToBase64String(c.Id),
                    type = c.Type,
                    transports = c.Transports?.Select(t => t.ToString().ToLower()).ToArray() ?? Array.Empty<string>()
                }).ToArray() ?? Array.Empty<object>(),
                userVerification = options.UserVerification.ToString().ToLower()
            };

            return Ok(new
            {
                options = clientOptions,
                sessionId
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error beginning authentication");
            return StatusCode(500, "Authentication initiation failed");
        }
    }

    [HttpPost("authenticate/complete")]
    public async Task<IActionResult> CompleteAuthentication([FromBody] CompleteAuthenticationRequest request)
    {
        try
        {
            if (string.IsNullOrEmpty(request.AssertionResponse))
            {
                return BadRequest("Assertion response is required");
            }

            var sessionId = request.SessionId ?? HttpContext.Session.GetString("auth_session");
            if (string.IsNullOrEmpty(sessionId))
            {
                return BadRequest("No active authentication session found");
            }

            var user = await _webAuthnService.CompleteAuthenticationAsync(
                request.AssertionResponse,
                sessionId);

            if (user != null)
            {
                HttpContext.Session.Remove("auth_session");
                HttpContext.Session.Remove($"authentication_options_{sessionId}");

                return Ok(new
                {
                    success = true,
                    user = new
                    {
                        id = user.Id,
                        username = user.Username,
                        displayName = user.DisplayName,
                        email = user.Email
                    }
                });
            }

            return BadRequest("Authentication failed");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error completing authentication");
            return StatusCode(500, "Authentication completion failed");
        }
    }

    [HttpGet("credentials/{userId}")]
    public async Task<IActionResult> GetUserCredentials(string userId)
    {
        try
        {
            var credentials = await _webAuthnService.GetUserCredentialsAsync(userId);

            var credentialInfo = credentials.Select(c => new
            {
                id = c.Id,
                deviceName = c.DeviceName ?? "Unknown Device",
                registrationDate = c.RegDate,
                lastUsed = c.RegDate, // You might want to track this separately
                credentialType = c.CredType
            });

            return Ok(credentialInfo);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting credentials for user {UserId}", userId);
            return StatusCode(500, "Failed to retrieve credentials");
        }
    }

    [HttpDelete("credentials/{credentialId}")]
    public async Task<IActionResult> DeleteCredential(string credentialId, [FromQuery] string userId)
    {
        try
        {
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("User ID is required");
            }

            var success = await _webAuthnService.DeleteCredentialAsync(credentialId, userId);

            if (success)
            {
                return Ok(new { success = true, message = "Credential deleted successfully" });
            }

            return NotFound("Credential not found");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting credential {CredentialId}", credentialId);
            return StatusCode(500, "Failed to delete credential");
        }
    }
}

// Request/Response models
public class BeginRegistrationRequest
{
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
}

public class CompleteRegistrationRequest
{
    public string Username { get; set; } = string.Empty;
    public string AttestationResponse { get; set; } = string.Empty;
    public string? SessionId { get; set; }
}

public class BeginAuthenticationRequest
{
    public string? Username { get; set; }
}

public class CompleteAuthenticationRequest
{
    public string AssertionResponse { get; set; } = string.Empty;
    public string? SessionId { get; set; }
}
