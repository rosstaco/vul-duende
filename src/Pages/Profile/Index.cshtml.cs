using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;
using VulDuende.Services;

namespace VulDuende.Pages.Profile;

[Authorize]
public class IndexModel : PageModel
{
    private readonly IMicrosoftGraphService _graphService;

    public IndexModel(IMicrosoftGraphService graphService)
    {
        _graphService = graphService;
    }

    public string? ProfilePicture { get; set; }
    public string? DisplayName { get; set; }
    public string? Email { get; set; }
    public string? JobTitle { get; set; }
    public bool HasMicrosoftToken => !string.IsNullOrEmpty(User.FindFirst("ms_access_token")?.Value);

    public void OnGet()
    {
        // Get profile information from claims
        DisplayName = User.FindFirst("name")?.Value ?? User.Identity?.Name;
        Email = User.FindFirst("email")?.Value;
        JobTitle = User.FindFirst("job_title")?.Value;

        // For non-Microsoft logins, still try to get base64 profile picture from claims
        if (!HasMicrosoftToken)
        {
            ProfilePicture = User.FindFirst("picture")?.Value;
        }
        // For Microsoft logins, the profile picture will be loaded via the API endpoint
    }
}
