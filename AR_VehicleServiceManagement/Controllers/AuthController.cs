using AR_VehicleServiceManagement.Data;
using AR_VehicleServiceManagement.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AR_VehicleServiceManagement.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly VehicleServiceContext _context;
        private readonly IConfiguration _configuration;

        public AuthController(VehicleServiceContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        // Register User
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Register model)
        {
            if (ModelState.IsValid)
            {
                // Check if the user already exists
                if (await _context.Users.AnyAsync(u => u.Username == model.UserName || u.Email == model.Email))
                {
                    return BadRequest(new { Message = "User with this username or email already exists" });
                }

                var user = new User
                {
                    Username = model.UserName,
                    FullName = model.FullName,
                    Email = model.Email,
                    Password = model.Password, // Store password securely
                    PhoneNumber = model.PhoneNumber,
                    Address = model.Address,
                    City = model.City
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                return Ok(new { Message = "User registered successfully" });
            }

            return BadRequest(ModelState);
        }

        // User Login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLogin model)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == model.Username);

            if (user != null && user.Password == model.Password) // Verify password securely
            {
                var token = GenerateJwtToken(user);
                return Ok(new { Token = token });
            }

            return Unauthorized(new { Message = "Invalid username or password" });
        }

        // Generate JWT Token
        private string GenerateJwtToken(User user)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Email, user.Email),
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(50),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
