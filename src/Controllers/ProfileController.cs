using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulDuende.Services;

namespace VulDuende.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class ProfileController : ControllerBase
{
    private readonly IMicrosoftGraphService _graphService;

    public ProfileController(IMicrosoftGraphService graphService)
    {
        _graphService = graphService;
    }

    [HttpGet("picture")]
    public async Task<IActionResult> GetProfilePicture()
    {
        var accessToken = User.FindFirst("ms_access_token")?.Value;

        if (string.IsNullOrEmpty(accessToken))
        {
            return NotFound("No Microsoft access token available");
        }

        var imageData = await _graphService.GetUserProfilePictureStreamAsync(accessToken);

        if (imageData == null)
        {
            return NotFound("Profile picture not found");
        }

        return File(imageData.Stream, imageData.ContentType);
    }
}
