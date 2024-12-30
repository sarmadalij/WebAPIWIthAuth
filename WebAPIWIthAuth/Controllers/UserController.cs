using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MimeKit;
using MimeKit.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace WebAPIWIthAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController(UserManager<IdentityUser> userManager) : ControllerBase
    {
        [HttpPost("register/{email}/{password}")]
        public async Task<IActionResult> Register(string email, string password)
        {
            var user = await GetUser(email);
            if (user != null)
            {
                return BadRequest("User already exists");
            }
            else
            {
                var result = await userManager.CreateAsync(new IdentityUser()
                {
                    UserName = email,
                    Email = email,
                    PasswordHash = password
                }, password);

                if (result.Succeeded)
                {
                    var newUser = await GetUser(email);
                    var emailToken = await userManager.GenerateEmailConfirmationTokenAsync(newUser!);
                    string sendEmail = SendEmail(email, emailToken);


                    return Ok(sendEmail);
                }
                else
                {
                    return BadRequest("Something went wrong");
                }
            }
        }

        private string SendEmail(string email, string emailToken)
        {
            StringBuilder emailMessage = new StringBuilder();

            emailMessage.AppendLine("<html>");
            emailMessage.AppendLine("<body>");
            emailMessage.AppendLine($"<h3>Dear {email},</h3>");
            emailMessage.AppendLine("<p>Thank you for registering with us. Please use the following verification code.</p>");
            emailMessage.AppendLine($"<b>Verification Code: {emailToken}</b>");
            emailMessage.AppendLine("<p>Please enter this code on our website to complete your registration</p>");
            emailMessage.AppendLine("<p>If you did not requested this code, please ignore this email.</p>");
            emailMessage.AppendLine("<br>");
            emailMessage.AppendLine("<p>Best Regards,</p>");
            emailMessage.AppendLine("<p><strong>Our Website Brand</strong></p>");
            emailMessage.AppendLine("</body>");
            emailMessage.AppendLine("</html>");

            string emailMessageString = emailMessage.ToString();

            var emailMsg = new MimeMessage();
            emailMsg.To.Add(MailboxAddress.Parse("brennan8@ethereal.email"));
            emailMsg.From.Add(MailboxAddress.Parse("brennan8@ethereal.email"));
            emailMsg.Subject = "Email Confirmation";

            emailMsg.Body = new TextPart(TextFormat.Html)
            {
                Text = emailMessageString
            };

            using var smtp = new SmtpClient();
            smtp.Connect("smtp.ethereal.email", 587, MailKit.Security.SecureSocketOptions.StartTls);
            smtp.Authenticate("brennan8@ethereal.email", "8ePB2X9MCQEAxQcjfN");

            smtp.Send(emailMsg);

            smtp.Disconnect(true);

            return "Thank you for registration! Check your email for confirmation";
        }


        [HttpPost("confirmation/{email}/{code:int}")]
        public async Task<IActionResult> ConfirmEmail(string email, int code)
        {
            if (string.IsNullOrEmpty(email) || code <= 0)
            {
                return BadRequest("Invalid email or code");
            } else
            {
                var user = await GetUser(email);
                if (user == null)
                {
                    return BadRequest("User not found");
                }
                else
                {
                    var result = await userManager.ConfirmEmailAsync(user, code.ToString());
                    if (result.Succeeded)
                    {
                        return Ok("Email confirmed successfully");
                    }
                    else
                    {
                        return BadRequest("Email confirmation failed");
                    }
                }
            }
        }

        [HttpPost("login/{email}/{password}")]
        public async Task<IActionResult> Login(string email, string password)
        {
            var user = await GetUser(email);
            if (user == null)
            {
                return BadRequest("User not found");
            }
            else
            {
                //email verification
                var isEmailConfirmed = await userManager.IsEmailConfirmedAsync(user);
                if (!isEmailConfirmed)
                {
                    return BadRequest("Email not confirmed/verified");
                }


                var result = await userManager.CheckPasswordAsync(user, password);
                if (result)
                {
                    return Ok(new[] { "Login successful", GenerateToken(user) });
                }
                else
                {
                    return BadRequest("Invalid password");
                }
            }
        }


        private async Task<IdentityUser?> GetUser(string email)
        {
            return await userManager.FindByEmailAsync(email);
        }

        private string GenerateToken(IdentityUser? user)
        {
            byte[] key = Encoding.UTF8.GetBytes("2608CBA0-9983-4074-A9AB-4A73E083E325-longkeyforjwtauthenticationwebapi");
            var securityKey = new SymmetricSecurityKey(key);

            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512Signature);

            var claimsS = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user!.Id),
                new Claim(JwtRegisteredClaimNames.Email, user!.Email!)
            };

            var token = new JwtSecurityToken(
                issuer: null,
                audience: null,
                claims: claimsS,
                expires: null,
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


        [HttpGet("protected")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public string GetMessage() => "This is a protected end-point message\nOnly Authorized user can read this.";


    }
}
