using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace RolesByEmail.Data {
    public class ApplicationContext : IdentityDbContext<IdentityUser> {
        public ApplicationContext(DbContextOptions<ApplicationContext> options)
            : base(options) {
            Database.EnsureCreated();
        }

    }
}
