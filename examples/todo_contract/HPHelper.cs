using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Mono.Unix.Native;
using Newtonsoft.Json;

namespace HotPocket
{
    public static class HotPocketHelper
    {
        const int FD_READ_BUFFER_LEN = 1024;

        public static async Task<ContractArgs> GetContractArgsAsync()
        {
            using (var s = new StreamReader(Console.OpenStandardInput()))
            {
                var input = await s.ReadToEndAsync();
                var contractArgs = JsonConvert.DeserializeObject<ContractArgs>(input);
                return contractArgs;
            }
        }

        public static string ReadStringFromFD(int fd)
        {
            return Encoding.UTF8.GetString(ReadBytesFromFD(fd));
        }

        public static void WriteStringToFD(int fd, string str)
        {
            WriteBytesToFD(fd, Encoding.UTF8.GetBytes(str));
        }

        public static unsafe byte[] ReadBytesFromFD(int fd)
        {
            // Keep reading the fd bytes and fill the memory stream until no more bytes.
            using (var ms = new MemoryStream())
            {
                int readbytes = 0;

                do
                {
                    var buffer = new byte[FD_READ_BUFFER_LEN];

                    fixed (byte* p = buffer)
                    {
                        IntPtr ptr = (IntPtr)p;
                        readbytes = (int)Syscall.read(fd, ptr, FD_READ_BUFFER_LEN);
                    }

                    ms.Write(buffer, 0, readbytes);

                } while (readbytes == FD_READ_BUFFER_LEN);

                return ms.ToArray();
            }
        }

        public static unsafe void WriteBytesToFD(int fd, byte[] buffer)
        {
            fixed (byte* p = buffer)
            {
                IntPtr ptr = (IntPtr)p;
                Syscall.write(fd, ptr, (ulong)buffer.Length);
            }
        }
    }
}