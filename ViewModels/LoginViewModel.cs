using System.ComponentModel.DataAnnotations;

namespace IdentityApp.ViewModels
{
    public class LoginViewModel
    {
        [EmailAddress]
        [Required]

        public string Email { get; set; } = null!;

        [DataType(DataType.Password)]
        [Required]
        public string Password { get; set; } = null!;

        public bool RememberMe { get; set; } = true;
    }
}