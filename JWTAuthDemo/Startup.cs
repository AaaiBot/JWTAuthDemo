using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace JWTAuthDemo
{
    public class Startup
    {
        private readonly string _secretKey;
        private readonly string _issuer;

        public Startup(IConfiguration configuration)
        {
            _secretKey = configuration["Jwt:SecretKey"];
            _issuer = configuration["Jwt:Issuer"];
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = _issuer,
                        ValidAudience = _issuer,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey))
                    };
                });

            services.AddAuthorization(options =>
            {
                options.AddPolicy("ValuablesPolicy", policy => 
                    policy.RequireClaim("Permissions", new[] 
                    { 
                        "ValuablesReader", 
                        "ValuablesWriter", 
                        "Administrator" 
                    }));

                options.AddPolicy("BlogWriter", policy =>
                    policy.RequireClaim("Role", new[]
                    {
                        "Student",
                        "Teacher"
                    }));

                options.AddPolicy("BlogAdministrator", policy =>
                    policy.RequireClaim("Role", new[]
                    {
                        "Teacher"
                    }));

            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
