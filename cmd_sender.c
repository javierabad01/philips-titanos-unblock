/* cmd_sender.c  -- talks to cmd_daemon's SysV message queue
 * Cross-compile:  arm-linux-gnueabihf-gcc -static -o cmd_sender cmd_sender.c
 * Usage:          ./cmd_sender "id; uname -a"
 * The daemon runs the string via system() as root and replies with the
 * low byte of the return value on mtype 1.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>

struct msgbuf_cmd {
    long mtype;          /* 4 bytes on ARM32, matches daemon's undefined4 */
    char mtext[256];
};

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <command>\n", argv[0]); return 1; }

    key_t key = ftok("/tmp/cmd", 0xff);      /* same path + proj_id as daemon */
    if (key == -1) { perror("ftok"); return 1; }

    int mqid = msgget(key, 0);               /* attach to existing queue (no CREAT/EXCL) */
    if (mqid == -1) { perror("msgget"); return 1; }

    struct msgbuf_cmd m;
    m.mtype = 2;                             /* daemon does msgrcv(..., msgtyp=2) */
    strncpy(m.mtext, argv[1], sizeof(m.mtext) - 1);
    m.mtext[sizeof(m.mtext) - 1] = 0;

    if (msgsnd(mqid, &m, strlen(m.mtext) + 1, 0) == -1) { perror("msgsnd"); return 1; }

    /* optional: read the 1-byte status reply (mtype 1) */
    struct msgbuf_cmd r;
    if (msgrcv(mqid, &r, sizeof(r.mtext), 1, 0) != -1)
        printf("daemon status byte: %d\n", (unsigned char)r.mtext[0]);

    return 0;
}
