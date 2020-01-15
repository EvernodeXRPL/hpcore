using Microsoft.EntityFrameworkCore;

namespace ToDoContract
{
    public class DataContext : DbContext
    {
        public DbSet<ToDoEntry> ToDoEntries { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder options)
            => options.UseSqlite("Data Source=state/todo.db");
    }

    public class ToDoEntry
    {
        public int Id { get; set; }
        public string Content { get; set; }
        public string CreatedBy { get; set; }
    }
}