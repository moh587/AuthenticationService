using AuthenticationService.DTO;
using AuthenticationService.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthenticationService.Services
{
    public class AuthService : IAuthService
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _context;

        public AuthService(UserManager<ApplicationUser> userManager, IConfiguration configuration, ApplicationDbContext context)
        {
            _userManager = userManager;
            _configuration = configuration;
            _context = context;
        }
        public sealed record Response(string AccessToken,string RefreshToken);
        public async Task<bool> RegisterAsync(RegisterDto registerDto)
        {
            if (registerDto == null || string.IsNullOrEmpty(registerDto.UserName) || string.IsNullOrEmpty(registerDto.Email) || string.IsNullOrEmpty(registerDto.Password))
            {
                return false;
            }
            var user = new ApplicationUser
            {
                UserName = registerDto.UserName,
                Email = registerDto.Email
            };

            var result = await _userManager.CreateAsync(user, registerDto.Password);
            return result.Succeeded;
        }
        public async Task<Response?> LoginAsync(LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.UserName);
            if (user == null)
                return null;

            var passwordValid = await _userManager.CheckPasswordAsync(user, loginDto.Password);
            if (!passwordValid)
                return null;

            // Create JWT token
            var token = CreateAccessToken(user);
            var x = user.RefreshTokens.Any(t => t.IsActive);

            if (user.RefreshTokens.Any(t => t.IsActive))
            {
                var activeRefreshToken = user.RefreshTokens.FirstOrDefault(t => t.IsActive);
                return new Response(token, activeRefreshToken.Token);
            }
            else
            {
                var refresh = GenerateRefreshToket();

                user.RefreshTokens.Add(refresh);

                await _userManager.UpdateAsync(user);
                return new Response(token, refresh.Token);
            }            
        }

        public async Task<Response?> RefreshTokenAsync(string token)
        {
            var user = _context.Users.FirstOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
            if (user == null)
                return await Task.FromResult<Response?>(null);

            var refreshToken = user.RefreshTokens.FirstOrDefault(t => t.Token == token);
            if (refreshToken == null || !refreshToken.IsActive)
                return await Task.FromResult<Response?>(null);

            // Generate new access token
            var newAccessToken = CreateAccessToken(user);
            var newRefreshToken = GenerateRefreshToket();

            // Update the user's refresh tokens
            refreshToken.RevokedOn = DateTime.UtcNow;
            user.RefreshTokens.Add(newRefreshToken);
            await _userManager.UpdateAsync(user);

            return new Response(newAccessToken, newRefreshToken.Token);
        }
        public async Task<bool> RevokeRefreshTokenAsync(string token)
        {
            var user = _context.Users.FirstOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
            if (user == null)
                return false;
            var refreshToken = user.RefreshTokens.FirstOrDefault(t => t.Token == token);
            if (refreshToken == null || !refreshToken.IsActive)
                return false;
            refreshToken.RevokedOn = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);
            return true;
        }

        public RefreshToken GenerateRefreshToket()
        {
            var refresh = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                ExpiresOn = DateTime.UtcNow.AddDays(7),
                CreatedOn = DateTime.UtcNow
            };

            return refresh;
        }
        public string CreateAccessToken(ApplicationUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken
            (
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(double.Parse(_configuration["Jwt:ExpiresInMinutes"])),
                signingCredentials: creds
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
            //return token;
        }
    }

}
