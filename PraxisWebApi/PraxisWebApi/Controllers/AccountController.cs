using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PraxisWebApi.Models;
using System.Net.Mail;
using System.Net;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace PraxisWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AccountController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var user = new IdentityUser
            {
                UserName = model.Username,
                Email = model.Email
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                return Ok(new { message = "Benutzer wurde erfolgreich angelegt" });
            }

            return BadRequest(result.Errors);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);

            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRole = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName!),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                authClaims.AddRange(userRole.Select(role => new Claim(ClaimTypes.Role, role)));

                var token = new JwtSecurityToken(
                    issuer: _configuration["Jwt:Issuer"],
                    expires: DateTime.Now.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)),
                    SecurityAlgorithms.HmacSha256
                    )
                    );
                return Ok(new LoginResponse { Token = new JwtSecurityTokenHandler().WriteToken(token), Message = "Login erfolgreich." });
            }
            return Unauthorized(new LoginResponse { Token = null, Message = "Ungültige Benutzername oder Passwort." });
        }

        [HttpPost("add-role")]
        public async Task<IActionResult> AddRole([FromBody] string role)
        {
            if (!await _roleManager.RoleExistsAsync(role))
            {
                var result = await _roleManager.CreateAsync(new IdentityRole(role));
                if (result.Succeeded)
                {
                    return Ok(new { message = "Rolle wurde erfolgreich angelegt" });
                }
                return BadRequest(result.Errors);
            }
            return BadRequest(new { message = "Rolle existiert bereits" });
        }

        [HttpPost("assign-role")]
        public async Task<IActionResult> AssignRole([FromBody] UserRole model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null)
            {
                return BadRequest("Benutzer existiert nicht");
            }

            var result = await _userManager.AddToRoleAsync(user, model.Role);
            if (result.Succeeded)
            {
                return Ok(new { message = "Rolle wurde erfolgreich zugewiesen" });
            }
            return BadRequest(result.Errors);
        }

        [HttpPost("send-reset-code")]
        public async Task<IActionResult> SendResetCode([FromBody] ForgetPasswordRequest model)
        {
            // E-Mail-Adresse trimmen und in Kleinbuchstaben umwandeln
            var email = model.Email.Trim().ToLower();

            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                return BadRequest(new ForgetPasswordResponse { Success = false, Message = "Benutzer mit dieser E-Mail-Adresse existiert nicht" });
            }

            // 6-stelligen numerischen Code generieren
            var resetCode = new Random().Next(100000, 999999).ToString();

            // Code und Zeitstempel in den Benutzeransprüchen speichern
            var claims = await _userManager.GetClaimsAsync(user);
            var resetCodeClaim = claims.FirstOrDefault(c => c.Type == "ResetCode");
            if (resetCodeClaim != null)
            {
                await _userManager.RemoveClaimAsync(user, resetCodeClaim);
            }
            await _userManager.AddClaimsAsync(user, new List<Claim>
            {
                new Claim("ResetCode", resetCode),
                new Claim("ResetCodeTimestamp", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")) // Einfacheres Format
            });

            var mailMessage = new MailMessage
            {
                From = new MailAddress("praxisapp.user@gmail.com"),
                Subject = "Passwort zurücksetzen",
                Body = $"Ihr Zurücksetzungscode: {resetCode}",
                IsBodyHtml = false,
            };
            mailMessage.To.Add(model.Email);

            using (var smtpClient = new SmtpClient("smtp.gmail.com")
            {
                Port = 587,
                Credentials = new NetworkCredential("praxisapp.user@gmail.com", "ofwqidbjcdnnnbbw "),
                EnableSsl = true,
            })
            {
                await smtpClient.SendMailAsync(mailMessage);
            }

            return Ok(new ForgetPasswordResponse { Success = true, Message = "Zurücksetzungscode wurde an Ihre E-Mail-Adresse gesendet" });
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return BadRequest(new ResetPasswordResponse { Success = false, Message = "Benutzer mit dieser E-Mail-Adresse existiert nicht" });
            }

            var claims = await _userManager.GetClaimsAsync(user);
            var resetCodeClaim = claims.FirstOrDefault(c => c.Type == "ResetCode");
            var timestampClaims = claims.Where(c => c.Type == "ResetCodeTimestamp")
                                        .OrderByDescending(c => DateTime.Parse(c.Value))
                                        .ToList();
            var timestampClaim = timestampClaims.FirstOrDefault();

            if (resetCodeClaim != null && timestampClaim != null)
            {
                if (DateTime.TryParseExact(timestampClaim.Value, "yyyy-MM-ddTHH:mm:ssZ", null, System.Globalization.DateTimeStyles.AssumeUniversal, out var timestamp))
                {
                    if (resetCodeClaim.Value == model.ResetCode && DateTime.UtcNow - timestamp < TimeSpan.FromMinutes(60))
                    {
                        // Passwort-Zurücksetzungstoken generieren
                        var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);

                        // Passwort mit dem generierten Token zurücksetzen
                        var result = await _userManager.ResetPasswordAsync(user, resetToken, model.NewPassword);
                        if (result.Succeeded)
                        {
                            // Entfernen des Zurücksetzungscodes nach erfolgreicher Passwortzurücksetzung
                            await _userManager.RemoveClaimsAsync(user, new List<Claim> { resetCodeClaim, timestampClaim });
                            return Ok(new ResetPasswordResponse { Success = true, Message = "Passwort wurde erfolgreich zurückgesetzt" });
                        }
                        return BadRequest(result.Errors);
                    }
                    else
                    {
                        return BadRequest(new ResetPasswordResponse { Success = false, Message = "Zurücksetzungscode ist abgelaufen oder ungültig." });
                    }
                }
                else
                {
                    return BadRequest(new ResetPasswordResponse { Success = false, Message = "Zeitstempel konnte nicht geparst werden." });
                }
            }
            return BadRequest(new ResetPasswordResponse { Success = false, Message = "Zurücksetzungscode oder Zeitstempel fehlen." });
        }

        [HttpPost("check-email-exist")]
        public async Task<IActionResult> CheckEmailExist([FromBody] CheckEmailExistRequest model)
        {
            // E-Mail-Adresse trimmen und in Kleinbuchstaben umwandeln
            var email = model.Email.Trim().ToLower();

            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                return Ok(new CheckEmailExistResponse { Success = true, Message = "E-Mail-Adresse existiert." });
            }
            return BadRequest(new CheckEmailExistResponse { Success = false, Message = "Benutzer mit dieser E-Mail-Adresse existiert nicht." });
        }
    }
}