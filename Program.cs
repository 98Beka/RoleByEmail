using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using RolesByEmail.Data;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<ApplicationContext>(options =>
     options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<IdentityUser, IdentityRole>(opt => {
    opt.Password.RequireNonAlphanumeric = false;
    opt.Password.RequireUppercase = false;
    opt.Password.RequiredLength = 1;
    opt.Password.RequireLowercase = false;
    opt.Password.RequireDigit = false;
})
    .AddEntityFrameworkStores<ApplicationContext>();

builder.Services.ConfigureApplicationCookie(options => {
    // Cookie settings
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(5);

    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.SlidingExpiration = true;
});

// Add services to the container.
builder.Services.AddControllersWithViews();

var app = builder.Build();

using (var serviceScope = app.Services.CreateScope()) {
    var services = serviceScope.ServiceProvider;
    var userManager = services.GetRequiredService<UserManager<IdentityUser>>();
    var rolesManager = services.GetRequiredService<RoleManager<IdentityRole>>();
    var email = builder.Configuration.GetSection("SuperAdmin:Email");
    var password = builder.Configuration.GetSection("SuperAdmin:Password");
    await RoleInitializer.InitializeAsync(userManager,
        rolesManager, new IdentityUser { Email = email.Value, UserName = email.Value}, password.Value);
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment()) {
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

