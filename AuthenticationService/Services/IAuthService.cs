using AuthenticationService.DTO;
using static AuthenticationService.Services.AuthService;

namespace AuthenticationService.Services
{
    public interface IAuthService
    {
        Task<bool> RegisterAsync(RegisterDto registerDto);
        Task<Response?> LoginAsync(LoginDto loginDto);
        Task<Response?> RefreshTokenAsync(string token);
        Task<bool> RevokeRefreshTokenAsync(string token);
    }
}
