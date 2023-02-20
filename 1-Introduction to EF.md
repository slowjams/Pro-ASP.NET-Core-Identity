Chapter 1-Introduction to EF
==============================

`DbContext` is a class you create that inherits from EF Core's DbContext class. This class holds the information EF Core nedds to configure that database mapping and is also the class you use in your code to access the database, for example:
```C#
public class AppDbContext : DbContext {
   /* 
   The database connection string holds information about the database:
       How to find the database server
       The name of the database
       Authorization to access the database
   */
   private const string ConnectionString = @"Server=(localdb)\mssqllocaldb;Database=MyFirstEfCoreDb;Trusted_Connection=True";
    
   protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder) {
      optionsBuilder.UseSqlServer(connectionString);   // tell EF that you're using an SQL Server database by using the UseSqlServer extension method
   }

   public DbSet<Book> { get; set; } Books   // you tell EF Core that there's a database table named Books, and it has the columns and keys as in the Book class
   
   protected override void OnModelCreating(ModelBuilder modelBuilder) {
      modelBuilder.Entity<BookAuthor>()
                  .HasKey(x => new { x.BookId, x.AuthorId });
   }
}
```
Note that above program is a console application without DI configuration, in an asp.net project with DI, it will be like:
```C#
// Startup.cs
public void ConfigureServices(IServiceCollection services) {
   services.AddDbContext<EFCoreContext>(   // register EFCoreContext so it can be injected
      options => options.UseSqlServer(connection)   // tell EF that you're using an SQL Server database by using the UseSqlServer method
   ); 
}

public class EFCoreContext : DbContext {
   public EFCoreContext(DbContextOptions<EFCoreContext> options) : base(options) { }

   public DbSet<Book> Books { get; set; }
   ...
}
```

## Modeling the Database

Before you can do anything with the database, EF Core must go through a process that I refer to as *modeling the database*. This modeling is EF Core's way of working out what the database looks like by looking at the classes and other EF Core configuration data. Then EF Core uses the resulting model in all database accesses.

The modeling process is kicked off the first tume you create the application's DbContext. It has one property, `DbSet<Book>`, which is the way that the code accesses the database.

Below is an overview of the modeling process, which will help you understand the process EF Core uses to model the database (default configurations):

![alt text](./zImages/1-1.png "Title")

Figure 1.6 shows the modeling steps, which happens the first time an instance of DbContext is created



<!-- <div class="alert alert-info p-1" role="alert">
    
</div> -->

<!-- ![alt text](./zImages/17-6.png "Title") -->

<!-- <code>&lt;T&gt;</code> -->

<!-- <div class="alert alert-info pt-2 pb-0" role="alert">
    <ul class="pl-1">
      <li></li>
      <li></li>
    </ul>  
</div> -->

<!-- <ul>
  <li><b></b></li>
  <li><b></b></li>
  <li><b></b></li>
  <li><b></b></li>
</ul>  -->

<!-- <span style="color:red">hurt</span> -->

<style type="text/css">
.markdown-body {
  max-width: 1800px;
  margin-left: auto;
  margin-right: auto;
}
</style>

<link rel="stylesheet" href="./zCSS/bootstrap.min.css">
<script src="./zCSS/jquery-3.3.1.slim.min.js"></script>
<script src="./zCSS/popper.min.js"></script>
<script src="./zCSS/bootstrap.min.js"></script>