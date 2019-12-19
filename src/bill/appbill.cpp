/*
    App bill default implementation 1
    MSB of return value is reserved for appbill error
    bits 1-8 indicate whether or not public keys 0-6 passed appbill check 

    (to be completed)
*/

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define DEBUG 0
#define KEY_SIZE 32
#define RECORD_SIZE 64

#define FILE_BUFFER_SIZE (64*1024*1024) // this will move 0xffff entries at a time

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#define TABLE_FILE "appbill.table"


uint64_t new_balance(uint64_t balance, int64_t to_credit) {
    if (to_credit < 0 && -to_credit > balance) {
        // catch the wrap around
        balance = 0;
    } else if (to_credit > 0 && to_credit + balance < balance) {
        // and here as well
        balance = (uint64_t)-1;
    } else {
        // normal crediting
        balance += to_credit;
    }
    return balance;
}

void print_hex(uint8_t* data, int len) {
    for (int c = 0; c < len; ++c)
        printf("%02hhx", data[c]);
}

int compar (const void* p1, const void* p2) {
    for (uint8_t* c1 = (uint8_t*)p1, * c2 = (uint8_t*)p2; c1 - (uint8_t*)p1 < KEY_SIZE; ++c1, ++c2)
        if (*c1 < *c2) return -1;
        else if (*c1 > *c2) return +1;
    return 0;
}


int correct_for_ed_keys(int argc, char** argv, int incr, int offset) {
    // correct for ed keys
    for (int i = 0; i < argc; i += incr)  {
        int len = strlen(argv[i + offset]);
        if (len == KEY_SIZE*2 + 2 && (argv[i][0] == 'e' || argv[i][0] == 'E') && (argv[i][1] == 'd' || argv[i][1] == 'D'))
            argv[i]+=2;
        else if (len != KEY_SIZE*2) {
            fprintf(stderr, "appbill received an invalid key %s, expected len=%d actual len=%d\n", argv[i], KEY_SIZE*2, len);
            return 128;
        }
    }
    return 0;
}

void key_from_hex(uint8_t* key_in, uint8_t* key_out) {
        for (int c = 0; c < 32; ++c) {
            uint8_t hn = tolower(key_in[c*2]);
            uint8_t ln = tolower(key_in[c*2+1]);
            hn = ( hn >= 'a' ? 10 + (hn - 'a') : hn - '0');
            ln = ( ln >= 'a' ? 10 + (ln - 'a') : ln - '0');
            key_out[c] = (hn * 16) + ln;
        }
}

uint64_t uint64_from_bytes(uint8_t* data) {
    return 
        (((uint64_t)(data[0]))<<56) +
        (((uint64_t)(data[1]))<<48) +
        (((uint64_t)(data[2]))<<40) +
        (((uint64_t)(data[3]))<<32) + 
        (((uint64_t)(data[4]))<<24) +
        (((uint64_t)(data[5]))<<16) +
        (((uint64_t)(data[6]))<<8)  +
        (((uint64_t)(data[7])));
}


void uint64_to_bytes(uint8_t* dest, uint64_t x) {
    for (int j = 0; j < 8; j++) {
        *(dest + (7-j)) = x & 0xff;
        x >>= 8;
    }
}


// returns 1 if found and populates entry_out, 0 if not found
int binary_file_search(FILE* f, uint8_t* key, uint8_t* entry_out, uint64_t* balance_out, size_t* recordno_out, int* error_out) {

    *error_out = 0;
    *balance_out = 0;

    // find file size
    fseek(f, (size_t)0, SEEK_END);
    size_t tablesize = ftell(f);
    int recordcount = tablesize / RECORD_SIZE;

    size_t record = recordcount/2;
    size_t search_size = (recordcount == 1 ? 1 : record);

    

    uint8_t entry_array[RECORD_SIZE*2];
    uint8_t* entry = entry_array + RECORD_SIZE;
    uint8_t* prev_entry = entry_array;
    

    while (search_size) {

        if (record == 0)  {
            // special case, no previous record will be available
            fseek(f, 0, SEEK_SET);
            int r = fread(entry, 1, RECORD_SIZE, f);
            if (r != RECORD_SIZE) {
                fprintf(stderr, "failed to read %d bytes\n", RECORD_SIZE);
                *error_out = 128;
                return 0;
            } 
            memset(prev_entry, 0, RECORD_SIZE);
        } else {
            fseek(f, (record - 1) * RECORD_SIZE, SEEK_SET);
            int r = fread(entry_array, 1, RECORD_SIZE * 2, f);
            if (r != RECORD_SIZE*2) {
                fprintf(stderr, "failed to read %d bytes\n", RECORD_SIZE*2);
                *error_out = 128;
                return 0;
            } 
        }

        int search_direction = compar(entry, key);
        int check_prev = compar(prev_entry, key);

        if (DEBUG) {
            printf("prevrec: %lu\tkey: ", record-1);
            print_hex(prev_entry, RECORD_SIZE);
            printf("\tsearch dir: %d\n", check_prev);
            printf("record: %lu\tkey: ", record);
            print_hex(entry, RECORD_SIZE);
            printf("\tsearch dir: %d\n", search_direction);
        }


        if (search_direction == 0) {
            // get the balance
            *balance_out = uint64_from_bytes(entry+32);
            if (DEBUG) printf("entry found at record %lu with balance=%lu\n", record, *balance_out);
            if (entry_out)
                for (int i = 0; i < RECORD_SIZE; ++i)
                    entry_out[i] = entry[i];            
            *recordno_out = record;
            return 1;
        }

        if (check_prev == 0 && record != 0) {
            // get the balance
            *balance_out = uint64_from_bytes(prev_entry+32);
            if (DEBUG) printf("entry found at record %lu with balance=%lu\n", record-1, *balance_out);
            if (entry_out)
                for (int i = 0; i < RECORD_SIZE; ++i)
                    entry_out[i] = prev_entry[i];            
            *recordno_out = record-1;
            return 1;
        }

        if (search_direction != check_prev ) {
            // record doesn't exist, it would go between these two records if it did
            if (DEBUG) printf("record doesn't exist, would go between\n");
            *recordno_out = record;
            return 0;
        }


        search_size /= 2;

        if (search_size < 1) search_size = 1;

        if (search_direction > 0) {
            record -= search_size;
        } else {
            record += search_size;
        }

        if (DEBUG) printf("search size: %lu, current record: %lu, check_prev: %d, dir: %d\n", search_size, record, check_prev, search_direction);

        if (record < 0 || record >= recordcount) {
            if (DEBUG)
                fprintf(stderr, "could not find key record: %lu, recordcount: %d\n", record, recordcount);
            if (entry_out)
                for (int i = 0; i < RECORD_SIZE; ++i)
                    entry_out[i] = entry[i];            
            *recordno_out = record;
            *balance_out = 0;
            return 0;
        }

        

        *recordno_out = record;
    }

    return 0;
}

// inserts above recordno
// warning: expensive, must copy remaining chunk of file down
int insert_record(FILE* f, uint8_t* entry, size_t recordno) {
    
    static uint8_t* file_buffer = 0; // we're going to reuse this piece of memory until appbill closes so just alloc once

    if (!file_buffer)
        file_buffer = (uint8_t*)malloc(MAX(FILE_BUFFER_SIZE, RECORD_SIZE));
    
    if (DEBUG) printf("insert_record called with recno=%lu\n", recordno);
    //uint8_t* buffer[FILE_BUFFER_SIZE];

    size_t offset = recordno * RECORD_SIZE;

    fseek(f, (size_t)0, SEEK_END);
    size_t size = ftell(f);

    // inserting 64 bytes at offset
    // we need to first compute the short move at the end

    long long tomove = size - offset;
    if (tomove <= 0) {
        // write the record at the end of the file
        if (DEBUG) printf("new write\n");
        return fwrite(entry, RECORD_SIZE, 1, f);
    } else {
        size_t endpiece = tomove % FILE_BUFFER_SIZE;

        if (DEBUG) printf("endpiece %lu\n", endpiece);
        
        // the endpiece is always moved, some times there are also no further pieces to move
        fseek(f, size - endpiece, SEEK_SET);
        fread(file_buffer, 1, endpiece, f);
        fseek(f, size - endpiece + RECORD_SIZE, SEEK_SET);
        fwrite(file_buffer, 1, endpiece, f);
        
        size_t cursor = size - endpiece;

        tomove -= endpiece;

        // now if there are any other pieces to move along we can move them
        if (size - endpiece >= FILE_BUFFER_SIZE)
        for (size_t cursor = size - endpiece - FILE_BUFFER_SIZE; cursor > offset; cursor -= FILE_BUFFER_SIZE) {
            if (DEBUG)  printf("moving %d sized piece at %lu to %lu - size: %lu - offset: %lu\n", FILE_BUFFER_SIZE, cursor, cursor + RECORD_SIZE, size, offset);
            fseek(f, cursor, SEEK_SET);
            fread(file_buffer, 1, FILE_BUFFER_SIZE, f);
            fseek(f, cursor + RECORD_SIZE, SEEK_SET);
            fwrite(file_buffer, 1, FILE_BUFFER_SIZE, f);
        }
        
        // not sure why we need to move this last row down, something is slightly wrong with the math above?
        fseek(f, offset, SEEK_SET);
        fread(file_buffer, 1, RECORD_SIZE, f);
        fseek(f, offset + RECORD_SIZE, SEEK_SET);
        fwrite(file_buffer, 1, RECORD_SIZE, f);

        // finally it's safe to emplace our data
        fseek(f, offset, SEEK_SET);
        return fwrite(entry, 1, RECORD_SIZE, f);
    }
}


int valid_hex(char* hex, int len) {
    char* x = hex;
    for (; (x-hex) < len && *x != '\0' && *x != '\n' && *x >= '0' && (*x <= '9' || *x >= 'a' && *x <= 'f' || *x >= 'A' && *x <= 'F'); ++x);
    return x-hex == len;
}

int pass_through_mode(int argc, char** argv) {
    // full argc, argv are in tact in this mode

    if (DEBUG)
        printf("pass through mode\n");

    int teepipe[2];
    int error = pipe(teepipe);
    if (error) {
        fprintf(stderr, "appbill pass through could not create a pipe for teeing fdlist\n");
        return 128;
    }


    // todo: make this all zero copy when someone has time to debug tee and vmsplice readmode    
    // for now we'll just do a dumb read

    FILE* f = fopen(TABLE_FILE, "rb+");
    if (!f) {
        fprintf(stderr, "could not open %s\n", TABLE_FILE);
        return 128;
    }    

    char buf[1024];
    int mode = 0;
    int bytes_read = 0;

    int counter = 0;
    int toskip = 0;

    uint8_t key[KEY_SIZE];

    do {
        char c = 0;
        bytes_read = 0;
        while ( (c = getc( stdin )) != EOF && c != ',' && c != '{' && c != '}' && c != '[' && c != ']' && c != '\n' && c != ':' && bytes_read < 1023 )
            buf[bytes_read++] = c;
        buf[bytes_read] = '\0';

        if (mode == 0 && strcmp("\"usrfd\"", buf) == 0)  {
            mode = 1;
            continue;
        }  else if ( mode == 1 && c == '}' ) {
            break;
        } 

        if (buf[0] == '\0' || !mode)
            continue;
        
        ++counter %= 3;

        // this runs if there's an error in the user's public key
        if (toskip) {
            toskip--;
            continue;
        }
        

        if (DEBUG)
            printf("mode=%d counter=%d component `%s`\n", mode, counter%3, buf);

        if (counter == 1) {
            // this is the user key
            // remove trailing "
            if (!buf[strlen(buf)-1] == '"')
                continue;
            buf[strlen(buf)-1] = '\0';

            // check the key is valid
            if (DEBUG)
                printf("key length: %lu, proper length: %d\n", strlen(buf+3), KEY_SIZE*2);
            if (DEBUG)
                printf("hex: `%s`\n", buf+3);
            if (strlen(buf+3) != KEY_SIZE*2 || !valid_hex(buf+3, KEY_SIZE*2)) {
                toskip = 2;
                if (DEBUG)
                    printf("invald public key %s\n", buf+3);
                continue;
            }

            key_from_hex((uint8_t*)buf+3, key);
            if (DEBUG) {
                printf("parsed key: ");
                print_hex(key, KEY_SIZE);
                printf("\n");
            }
        } else if (counter == 2) {
            // this is the user's input fd

            int userfd = 0;
            if (!sscanf(buf, "%d", &userfd))
                continue;

            if (DEBUG) printf("mode=2 userfd=%d\n", userfd);

            // there might be some bytes pending on this input, if there are we need to bill for them, one coin per byte
            int nbytes = 0;
            ioctl(userfd, FIONREAD, &nbytes);
            int64_t to_bill = 1 + nbytes; // and one coin per round for being connected too

            if (DEBUG)
                printf("tobill: %lu\n", to_bill);

            // commence billing

            int error = 0;
            uint64_t balance = 0;
            size_t recordno = 0;
            uint8_t entry[64];
            if (binary_file_search(f, key, entry, &balance, &recordno, &error)) {
                // key already exists, update it
                if (DEBUG) printf("writing 64 bytes at record:%lu\n", recordno);
                fseek(f, recordno*RECORD_SIZE, SEEK_SET);
                uint64_t balance = uint64_from_bytes(entry+32);
                balance = new_balance(balance, -to_bill);
                uint64_to_bytes(entry+32, balance);
                fwrite(entry, RECORD_SIZE, 1, f);
            } else { 
                // is user doesn't exist this is an error but we can't do anything about it in passthrough mode so ignore 
                if (DEBUG) {
                    printf("user not found key:");
                    print_hex(key, KEY_SIZE);
                    printf("\n");
                }
                continue;
            }
        }

    } while (!feof(stdin)); 
    
    
    close(teepipe[1]);
    dup2(teepipe[0], 0);
   
    fclose(f);
 
    execv(argv[1], argv+1);
    
}



int credit_mode(int argc, char** argv) {
    // argc,v start from first useful arguments
    if (argc == 0 || argc % 2 == 1) {
        fprintf(stderr, "appbill credit mode requires args like: public_key amount public key amount\n");
        return 128;
    }

    if (correct_for_ed_keys(argc, argv, 2, 0))
        return 128;

    // sanity check our inputs
    for (int i = 0; i < argc; i += 2) {
        for (char* x = argv[i];; ++x) {
            if ( x - argv[i] == KEY_SIZE*2 && *x != '\0' ) {
                fprintf(stderr, "appbill was supplied an invalid public key\n");
                return 128;
            } 

            if (*x >= 'a' && *x <= 'f' || *x >= '0' && *x <= '9' || *x >= 'A' && *x <= 'F')
                continue;

            if (*x == '\0')
                break;

            fprintf(stderr, "appbill was supplied an invalid public key (not hex) char=%c\n", *x);
            return 128;
        }

        for (char* x = argv[i+1]; *x; ++x)
            if ( ! (*x >= '0' && *x <= '9' || *x == '-') ) {
                fprintf(stderr, "appbill was supplied invalid amount to credit, must be decimal integer entry=%s\n", argv[i+1]);
                return 128;
            }

        int64_t to_credit = 0;
        if (!sscanf(argv[i+1], "%ld", &to_credit)) {
            fprintf(stderr, "appbill was supplied invalid amount to credit, must be decimal integer entry=%s\n", argv[i+1]);
            return 128;
        }
    }

    FILE* f = fopen(TABLE_FILE, "rb+");
    if (!f) {
        fprintf(stderr, "could not open %s\n", TABLE_FILE);
        return 128;
    }
     
    // now the expensive bit
    for (int i = 0; i < argc; i += 2) {
        uint8_t key[32];
        key_from_hex((uint8_t*)argv[i], key);

        int64_t to_credit = 0;
        if (!sscanf(argv[i+1], "%ld", &to_credit)) // this has been sanity checked above 
            continue;

        int error = 0;
        uint64_t balance = 0;
        size_t recordno = 0;
        uint8_t entry[64];
        if (binary_file_search(f, key, entry, &balance, &recordno, &error)) {
            // key already exists, update it
            if (DEBUG) printf("writing 64 bytes at record:%lu\n", recordno);
            fseek(f, recordno*RECORD_SIZE, SEEK_SET);
            uint64_t balance = uint64_from_bytes(entry+32);
            balance = new_balance(balance, to_credit);
            uint64_to_bytes(entry+32, balance);
            fwrite(entry, RECORD_SIZE, 1, f);
 
        } else {

            if (DEBUG) printf("key needs to be inserted\n");
            // key doesn't exist, insert it
            uint8_t new_entry[RECORD_SIZE];
            for (int i = 0; i < KEY_SIZE; ++i)
                new_entry[i] = key[i];
            uint64_t balance = new_balance(0, to_credit);
            
            uint64_to_bytes(new_entry+32, balance);          
            
            for (int i = KEY_SIZE + 8; i < RECORD_SIZE; ++i)
                new_entry[i] = 0; 
        
            // get the existing entry
            fseek(f, recordno * RECORD_SIZE, SEEK_SET);
            fread(entry, 1, RECORD_SIZE, f);

            int insert_direction = compar(entry, new_entry);
    
            insert_record(f, new_entry, recordno + (insert_direction < 0 ? 1 : 0));
        }
        
    }

    
    fclose(f);
    return 0;
}

int check_mode(int argc, char** argv, int print_balances) {

    if (DEBUG)
        printf("check mode\n");

    if (argc > 7 && !print_balances) {
        fprintf(stderr, "appbill can only take up to 7 keys at a time\n");
        return 128;
    }

    if (correct_for_ed_keys(argc, argv, 1, 0))
        return 128;
    
    for (int i = 0; i < argc; ++i) {
        for (char* x = argv[i];; ++x) {
            if ( x - argv[i] == KEY_SIZE*2 && *x != '\0' ) {
                fprintf(stderr, "appbill was supplied an invalid public key\n");
                return 128;
            } 

            if (*x >= 'a' && *x <= 'f' || *x >= '0' && *x <= '9' || *x >= 'A' && *x <= 'F')
                continue;

            if (*x == '\0')
                break;

            fprintf(stderr, "appbill was supplied an invalid public key (not hex) char=%c\n", *x);
            return 128;
        }
    }

    if (print_balances)
        printf("{\n");

    // open app bill table

    FILE* f = fopen(TABLE_FILE, "rb");

    if (!f) {
        fprintf(stderr, "%s not found\n", TABLE_FILE);
        return 128;
    }

    int bits[7];
    for (int i = 0; i < 7; ++i)
        bits[i] = 0;

    // loop keys, check balances
    for (int i = 0; i < argc; ++i) {
        // convert the argv from hex to binary 
        uint8_t key[32];
        key_from_hex((uint8_t*)argv[i], key);

        int error = 0;
        uint64_t balance = 0;
        size_t recordno = 0;
        if (binary_file_search(f, key, 0, &balance, &recordno, &error)) {
            if (i < 7) bits[i] = 1;
            if (print_balances) {
                printf("\t\"");
                print_hex(key, KEY_SIZE);
                printf("\": %lu%s", balance, (i == argc-1 ? "\n": ",\n"));
            }
        }
    }

    if (print_balances)
        printf("}");
    fclose(f);   

    if (DEBUG)
        for (int i = 0; i < 7; ++i) 
            printf("bit %d: %d\n", i, bits[i]); 

    return bits[0] * 64 + bits[1] * 32 + bits[2] * 16 + bits[3] * 8 + bits[4] * 4 + bits[5] * 2 + bits[6];
}

int main(int argc, char** argv) {

    
    
    // input checks

    int mode = 0; // mode 0 is passthrough [ writes ]

    if (argc >= 2 && strcmp(argv[1], "--credit") == 0)
        mode = 1; // mode 1 credit mode [ writes ] 
    
    if (argc >= 2 && strcmp(argv[1], "--check") == 0)
        mode = 2; // mode 2 check mode [ read only ]

    if (argc >= 2 && strcmp(argv[1], "--balance") == 0)
        mode = 3; // mode 3 balance mode [ read only ]


    if (mode == 0) {
        if (argc < 2)  {
            fprintf(stderr, "appbill requires an executable to pass execution to as an argument when running in pass through mode\n");
            return 128;
        }
        return pass_through_mode(argc, argv);
    }
    
    if (argc < 3) {
        fprintf(stderr, "appbill was not supplied sufficient arguments\n");
        return 128;
    }

    argc-=2;
    argv+=2;

    if (mode == 1) 
        return credit_mode(argc, argv);
    
    if (mode == 2 || mode == 3)
        return check_mode(argc, argv, mode == 3);

    fprintf(stderr, "unknown mode, execution should not reach here\n");
    
    return 128;
}
