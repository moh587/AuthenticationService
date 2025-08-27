using AuthenticationService.DTO;
using AuthenticationService.Models;
using AuthenticationService.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthenticationService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        public IConfiguration _configuration { get; }
        private readonly IAuthService _authService;

        public AccountController(UserManager<ApplicationUser> userManager, IConfiguration configuration, IAuthService authService)
        {
            _userManager = userManager;
            _configuration = configuration;
            _authService = authService;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterDto registerDto)
        {
            var isSuccess = await _authService.RegisterAsync(registerDto);

            if (!isSuccess)
                return BadRequest("Registration failed.");

            return Ok("User registered successfully.");
        }
        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginDto loginDto)
        {
            var token = await _authService.LoginAsync(loginDto);

            if (token == null)
                return Unauthorized("Invalid username or password.");

            return Ok(token);
        }
        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshToken(string token)
        {
            var response = await _authService.RefreshTokenAsync(token);
            if (response == null)
                return Unauthorized("Invalid or expired refresh token.");
            return Ok(response);
        }
        [HttpPost("RevokeRefreshToken")]
        public async Task<IActionResult> RevokeRefreshToken(string token)
        {
            var isRevoked = await _authService.RevokeRefreshTokenAsync(token);
            if (!isRevoked)
                return BadRequest("Failed to revoke refresh token.");
            return Ok("Refresh token revoked successfully.");
        }
    }
}
