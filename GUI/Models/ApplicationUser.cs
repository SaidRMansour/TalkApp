using System;
using Microsoft.AspNetCore.Identity;

namespace GUI.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
    }
}
