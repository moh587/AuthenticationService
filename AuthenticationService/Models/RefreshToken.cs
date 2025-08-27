using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthenticationService.Models
{
    //[Index(nameof(Token), IsUnique = true)] // Moved the Index attribute to the class level
    //public class RefreshToken
    //{
    //    [Key]
    //    public Guid Id { get; set; }
    //    [MaxLength(200)]
    //    public string Token { get; set; }
    //    public DateTime ExpiresOnUtc { get; set; }
    //    public bool IsExpired => DateTime.UtcNow >= ExpiresOnUtc;
    //    public DateTime? RevokedOn { get; set; }
    //    public bool IsActive => RevokedOn == null && !IsExpired;
    //    public DateTime CreatedOn { get; set; }
    //    [Required]
    //    public string ApplicationUserId { get; set; }  // FK

    //    public ApplicationUser ApplicationUser { get; set; }
    //}

    [Owned]
    public class RefreshToken
    {
        public string Token { get; set; }
        public DateTime ExpiresOn { get; set; }
        public bool IsExpired => DateTime.UtcNow >= ExpiresOn;
        public DateTime CreatedOn { get; set; }
        public DateTime? RevokedOn { get; set; }
        public bool IsActive => RevokedOn == null && !IsExpired;
    }
}
