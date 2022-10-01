using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using API.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _token;
        public AccountController(DataContext context, ITokenService token)
        {  
            _token = token;
            _context = context;  
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto register)
        {   
            if(await UserExists(register.username)) return BadRequest("Username is taken");
            using var hmac = new HMACSHA512();
            var user = new AppUser
            {
                UserName = register.username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(register.password)),
                PasswordSalt = hmac.Key
            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return new UserDto
            {
                Username = user.UserName,
                Token = _token.CreateToken(user)
            };

        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto login)
        {
         var user = await _context.Users.SingleOrDefaultAsync(x => x.UserName == login.Username);
         if(user == null) return Unauthorized("Invalid username");
         using var hmac = new HMACSHA512(user.PasswordSalt);
         var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(login.Password));
         for(int i = 0; i < computedHash.Length; ++i)
            if(computedHash[i] != user.PasswordHash[i])
            return Unauthorized("Invalid password");
             return new UserDto
            {
                Username = user.UserName,
                Token = _token.CreateToken(user)
            };
    
         
        }

        private async Task<bool> UserExists(string username)
        {
            return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());
        }

        
    }
}