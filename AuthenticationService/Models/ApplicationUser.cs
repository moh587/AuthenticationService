using Microsoft.AspNetCore.Identity;

namespace AuthenticationService.Models
{
    public class ApplicationUser : IdentityUser
    {
        public List<RefreshToken>? RefreshTokens { get; set; }
    }
}
