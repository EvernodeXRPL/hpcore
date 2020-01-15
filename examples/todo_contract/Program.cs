using System;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using HotPocket;
using System.Linq;

namespace ToDoContract
{
    /* 
     * This is a simple multi-user ToDo list contract which uses sqlite database as storage.
     * In order to run this .Net Core should be installed on the system. If using docker,
     * mcr.microsoft.com/dotnet/core/sdk:3.1 docker image must be used.
     * 
     * Produce deployable output with: dotnet publish -c Release
     *
     * User inputs can be submitted in the following format.
     * Insert a new ToDo record:            add <title>
     * Retrieve all records owned by user:  get all
     * Retrieve record by ID:               get <id>
     * Delete all records owned by user:    delete all
     * Delete record by ID:                 delete <id>
     */
    public class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("Starting .Net ToDo contract");

            using (var dataContext = new DataContext())
            {
                dataContext.Database.Migrate();
            }

            ContractArgs contractArgs = await HotPocketHelper.GetContractArgsAsync();

            foreach (var user in contractArgs.UserPipes)
            {
                var pubkey = user.Key;
                var pipe = user.Value;

                var input = HotPocketHelper.ReadStringFromFD(pipe.ReadFD);
                if (string.IsNullOrEmpty(input))
                    continue;

                var output = await HandleUserInputAsync(pubkey, input);
                HotPocketHelper.WriteStringToFD(pipe.WriteFD, output);
            }
        }

        static async Task<string> HandleUserInputAsync(string userId, string input)
        {
            var parts = input.Trim().Split(' ', 2);
            if (parts.Length < 2)
                return "Invalid input format";

            var command = parts[0].ToLower();
            var param = parts[1];

            using (var dataContext = new DataContext())
            {
                if (command == "add") // add new record.
                {
                    var entry = new ToDoEntry
                    {
                        Content = param,
                        CreatedBy = userId
                    };
                    dataContext.ToDoEntries.Add(entry);

                    await dataContext.SaveChangesAsync();

                    return "Added entry with id " + entry.Id;
                }
                else if (command == "get" || command == "delete")
                {
                    if (param == "all") // get/delete all records.
                    {
                        // Get all entries belonging to this user.
                        var entries = await dataContext.ToDoEntries.Where(e => e.CreatedBy == userId).OrderBy(e => e.Id).ToListAsync();

                        if (command == "get")
                        {
                            return JsonConvert.SerializeObject(entries.Select(e => $"ID-{e.Id}: {e.Content}"));
                        }
                        else
                        {
                            // Delete all records for this user.
                            dataContext.RemoveRange(entries);
                            await dataContext.SaveChangesAsync();
                            return $"{entries.Count} record(s) deleted";

                        }
                    }
                    else // get/delete by ID.
                    {
                        int id = 0;
                        if (int.TryParse(param, out id))
                        {
                            var entry = await dataContext.ToDoEntries.FirstOrDefaultAsync(e => e.Id == id);
                            if (entry == null)
                            {
                                return $"Record id {id} does not exist";
                            }
                            else if (entry.CreatedBy != userId)
                            {
                                return $"You do not have permission for record id {id}";
                            }
                            else
                            {
                                if (command == "get")
                                {
                                    return entry.Content;
                                }
                                else
                                {
                                    dataContext.Remove(entry);
                                    await dataContext.SaveChangesAsync();
                                    return $"Record id {id} deleted";
                                }
                            }
                        }
                        else
                        {
                            return "Invalid record id";
                        }
                    }
                }
                else
                {
                    return "Invalid command";
                }
            }
        }
    }
}
