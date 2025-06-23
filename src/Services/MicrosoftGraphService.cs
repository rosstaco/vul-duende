using Microsoft.Graph;
using Microsoft.Graph.Models;
using System.Net.Http.Headers;
using Microsoft.Kiota.Abstractions;
using Microsoft.Kiota.Abstractions.Authentication;

namespace VulDuende.Services;

public interface IMicrosoftGraphService
{
    Task<string?> GetUserProfilePictureAsync(string accessToken);
    Task<ProfileImageData?> GetUserProfilePictureStreamAsync(string accessToken);
    Task<User?> GetUserProfileAsync(string accessToken);
}

public class ProfileImageData
{
    public Stream Stream { get; set; } = null!;
    public string ContentType { get; set; } = "image/jpeg";
}

public class MicrosoftGraphService : IMicrosoftGraphService
{
    private readonly ILogger<MicrosoftGraphService> _logger;
    private readonly HttpClient _httpClient;

    public MicrosoftGraphService(ILogger<MicrosoftGraphService> logger, HttpClient httpClient)
    {
        _logger = logger;
        _httpClient = httpClient;
    }

    public async Task<ProfileImageData?> GetUserProfilePictureStreamAsync(string accessToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://graph.microsoft.com/v1.0/me/photo/$value");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var response = await _httpClient.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                var contentType = response.Content.Headers.ContentType?.MediaType ?? "image/jpeg";
                var stream = await response.Content.ReadAsStreamAsync();

                return new ProfileImageData
                {
                    Stream = stream,
                    ContentType = contentType
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to retrieve user profile picture stream from Microsoft Graph");
        }

        return null;
    }

    public async Task<string?> GetUserProfilePictureAsync(string accessToken)
    {
        try
        {
            var imageData = await GetUserProfilePictureStreamAsync(accessToken);

            if (imageData != null)
            {
                using var memoryStream = new MemoryStream();
                await imageData.Stream.CopyToAsync(memoryStream);
                var photoBytes = memoryStream.ToArray();

                // Convert to base64 data URL
                var base64String = Convert.ToBase64String(photoBytes);
                return $"data:{imageData.ContentType};base64,{base64String}";
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to retrieve user profile picture from Microsoft Graph");
        }

        return null;
    }

    public async Task<User?> GetUserProfileAsync(string accessToken)
    {
        try
        {
            var graphClient = CreateGraphClient(accessToken);
            return await graphClient.Me.GetAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to retrieve user profile from Microsoft Graph");
            return null;
        }
    }

    private GraphServiceClient CreateGraphClient(string accessToken)
    {
        // Create a simple authentication provider
        var authProvider = new SimpleAuthProvider(accessToken);
        return new GraphServiceClient(authProvider);
    }
}

public class SimpleAuthProvider : IAuthenticationProvider
{
    private readonly string _accessToken;

    public SimpleAuthProvider(string accessToken)
    {
        _accessToken = accessToken;
    }

    public Task AuthenticateRequestAsync(RequestInformation request, Dictionary<string, object>? additionalAuthenticationContext = null, CancellationToken cancellationToken = default)
    {
        request.Headers.Add("Authorization", $"Bearer {_accessToken}");
        return Task.CompletedTask;
    }
}
