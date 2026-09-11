/*
 * 86Box     A hypervisor and IBM PC system emulator.
 *
 *           Shuttle Technology EPAT / EPATRM parallel-port to ATAPI bridge.
 *
 *           This is the bridge used by the Imation SuperDisk (LS-120)
 *           parallel-port drive. 86Box already models the drive itself in
 *           rdisk.c ("IMATION / SUPERDISK 120 ATAPI"); what was missing was
 *           the bridge that carries ATAPI over a parallel port. RDISK_BUS_LPT
 *           exists in rdisk.h and is referenced by no source file.
 *
 *           Protocol source: reverse-engineered from Imation's own DOS driver
 *           and VERIFIED ON REAL HARDWARE (a Shuttle EPATRM bridge with a
 *           Matsushita LS-120 COSM 04, on an IBM 5160). Cross-checked against
 *           Linux's drivers/block/paride/epat.c. Every constant below has a
 *           captured hardware reading behind it; see the references in each
 *           comment.
 *
 * Authors:  Mike Lycett and contributors
 *
 *           Copyright 2026 Mike Lycett.
 */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#define HAVE_STDARG_H
#include <86box/86box.h>
#include <86box/timer.h>
#include <86box/device.h>
#include <86box/lpt.h>
#include <86box/plat_unused.h>
#include <86box/log.h>

/*
 * The whole reason for modelling this bridge is VISIBILITY. On real hardware a
 * driver bug surfaces as "36 zeros" or "media is not formatted" and costs a
 * boot to narrow. Here the bridge is on both sides of the conversation, so it
 * can say what the host asked for AND what the protocol expected - which turns
 * a day of bisecting into one log line.
 *
 * Every failure this project spent 2026-09-11 on is a one-liner from in here:
 * the CDB written as twelve register writes instead of a block write; a command
 * refused with a unit attention nobody had cleared; a host reading the length
 * it asked for rather than the count the device offered.
 */
#define ENABLE_EPAT_LOG 1
#ifdef ENABLE_EPAT_LOG
int epat_do_log = ENABLE_EPAT_LOG;

static void
epat_log(void *priv, const char *fmt, ...)
{
    if (epat_do_log) {
        va_list ap;
        va_start(ap, fmt);
        log_out(priv, fmt, ap);
        va_end(ap);
    }
}
#else
#    define epat_log(priv, fmt, ...)
#endif

/*
 * The unlock frame. Eight bytes to the data port, each written TWICE - the
 * second write is the I/O delay, not a retry - then committed by pulsing
 * nINIT. The eighth byte is the command: 0xE0 connect, 0x30 disconnect.
 *
 * TRANSPORT_SPEC.md section 3, replayed byte-for-byte on the real machine
 * with all three checkpoints matching, reproducibly, twice.
 */
static const uint8_t epat_unlock[7] = { 0x22, 0xAA, 0x55, 0x00, 0xFF, 0x87, 0x78 };

#define EPAT_CPP_CONNECT    0xE0
#define EPAT_CPP_DISCONNECT 0x30

/*
 * Checkpoint values the real bridge returns on the status port part-way
 * through the unlock frame. The driver masks these; the raw readings are what
 * the hardware gave, so returning them exactly makes a capture comparison
 * meaningful rather than approximate.
 *
 *   after 22 AA 55 00 FF : status & 0xF0 == 0xB0   hardware read 0xB8
 *   after 87             : status & 0xF0 == 0x50   hardware read 0x58
 *   after 78             : status & 0xB0 == 0xB0   hardware read 0xF0
 */
#define EPAT_CHK_1 0xB8
#define EPAT_CHK_2 0x58
#define EPAT_CHK_3 0xF0

/* Idle status when connected but not mid-transfer. */
#define EPAT_STAT_IDLE 0x38

typedef enum {
    EPAT_UNLOCK_IDLE = 0, /* not in an unlock frame           */
    EPAT_UNLOCK_RUN,      /* matching the seven-byte preamble */
    EPAT_UNLOCK_CMD       /* preamble matched, command byte next */
} epat_unlock_state_t;

typedef struct epat_s {
    void *lpt;
    void *log;

    /* Parallel-port pin state as the host last wrote it. */
    uint8_t data;    /* w0 */
    uint8_t ctrl;    /* w2 */
    uint8_t status;  /* what r1 will return */

    /* Unlock-frame recogniser. */
    epat_unlock_state_t ustate;
    int                 upos;     /* how much of the preamble has matched  */
    uint8_t             ulast;    /* last data byte, to fold the double-write */
    int                 udup;     /* 1 = the next identical byte is the delay */
    uint8_t             ucmd;     /* the command byte once the preamble matched */

    int connected;

    /*
     * Register access. The host addresses a register by writing its number to
     * the DATA port - directly, as regr + cont_map[cont]; there is no index/data
     * pair. A write tags the number with 0x60; a read sends it bare. The value
     * then comes back as two nibbles, each arriving in the TOP four bits of the
     * status port across two control-port strobes.
     *
     *   read : w0(r); w2(1); w2(3); a = r1(); w2(4); b = r1();
     *          value = ((a >> 4) & 0x0f) | (b & 0xf0)
     *   write: w0(0x60 + r); w2(1); w0(val); w2(4)
     */
    uint8_t reg_addr;   /* register the host last addressed */
    int     reg_write;  /* the 0x60 tag was set - a value byte is coming */
    int     nibble_hi;  /* 0 = next status read returns the low nibble */

    /*
     * cont_map = { 0x18, 0x10, 0 }: the ATA task file lives at 0x18, device
     * control at 0x16, and the bridge's own registers at 0x00. One flat array
     * is simpler than three and the addresses do not overlap.
     */
    uint8_t regs[0x20];
} epat_t;

#define EPAT_REG_TASKFILE 0x18 /* cont 0 */
#define EPAT_REG_DEVCTL   0x16 /* cont 1 + 6 */
#define EPAT_WRITE_TAG    0x60

/* ATA/ATAPI task-file offsets, relative to EPAT_REG_TASKFILE. */
#define ATA_DATA     0
#define ATA_ERROR    1
#define ATA_IREASON  2
#define ATA_BCLO     4
#define ATA_BCHI     5
#define ATA_DRVHD    6
#define ATA_STATUS   7

#define ATA_ST_DRDY 0x40
#define ATA_ST_DSC  0x10

/* The ATAPI signature a device reports after a reset: 14 EB in LBA mid/high. */
#define ATAPI_SIG_LO 0x14
#define ATAPI_SIG_HI 0xEB

/*
 * The preamble is written as pairs. Fold a repeat of the byte we just saw
 * into a single logical step, which is what the bridge does - it is an I/O
 * delay, not data.
 */
static int
epat_unlock_feed(epat_t *dev, uint8_t val)
{
    if (dev->udup && (val == dev->ulast)) {
        dev->udup = 0;
        return 0;
    }

    dev->ulast = val;
    dev->udup  = 1;

    if (dev->ustate == EPAT_UNLOCK_CMD) {
        dev->ucmd   = val;
        dev->ustate = EPAT_UNLOCK_IDLE;
        return 1; /* a complete frame is pending its nINIT commit */
    }

    if (val == epat_unlock[dev->upos]) {
        dev->upos++;
        dev->ustate = EPAT_UNLOCK_RUN;

        /* Publish the checkpoint the driver is about to read. */
        if (dev->upos == 5)
            dev->status = EPAT_CHK_1;
        else if (dev->upos == 6)
            dev->status = EPAT_CHK_2;
        else if (dev->upos == 7) {
            dev->status = EPAT_CHK_3;
            dev->ustate = EPAT_UNLOCK_CMD;
        }
        return 0;
    }

    /*
     * A mismatch restarts the match rather than aborting it - the first byte
     * of a new frame can arrive immediately after a failed one.
     */
    if (dev->ustate == EPAT_UNLOCK_RUN)
        epat_log(dev->log, "unlock frame broken at byte %i: got %02X, expected %02X\n",
                 dev->upos, val, epat_unlock[dev->upos]);
    dev->upos   = (val == epat_unlock[0]) ? 1 : 0;
    dev->ustate = dev->upos ? EPAT_UNLOCK_RUN : EPAT_UNLOCK_IDLE;
    return 0;
}

/* Present the drive as it is immediately after a reset. */
static void
epat_device_reset(epat_t *dev)
{
    memset(dev->regs, 0x00, sizeof(dev->regs));
    dev->regs[EPAT_REG_TASKFILE + ATA_STATUS] = ATA_ST_DRDY | ATA_ST_DSC;
    dev->regs[EPAT_REG_TASKFILE + ATA_BCLO]   = ATAPI_SIG_LO;
    dev->regs[EPAT_REG_TASKFILE + ATA_BCHI]   = ATAPI_SIG_HI;
    epat_log(dev->log, "device reset: status %02X, signature %02X %02X\n",
             dev->regs[EPAT_REG_TASKFILE + ATA_STATUS], ATAPI_SIG_LO, ATAPI_SIG_HI);
}

static void
epat_write_data(uint8_t val, void *priv)
{
    epat_t *dev = (epat_t *) priv;

    dev->data = val;

    epat_unlock_feed(dev, val);

    /*
     * While an unlock frame is being matched, or one is committed but waiting
     * for its nINIT pulse, these bytes are frame content and not register
     * addresses. A register number that happens to equal 0x22 would start the
     * recogniser spuriously; epat_write_ctrl cancels a partial match the moment
     * it sees w2(1), which an unlock frame never issues.
     */
    if ((dev->ustate != EPAT_UNLOCK_IDLE) || dev->ucmd)
        return;

    if (!dev->connected)
        return;

    if (dev->reg_write) {
        /* The value for the register addressed by the previous write. */
        dev->reg_write = 0;
        if (dev->reg_addr < sizeof(dev->regs)) {
            dev->regs[dev->reg_addr] = val;
            epat_log(dev->log, "W reg %02X = %02X\n", dev->reg_addr, val);

            /* SRST asserted then released is how a cold drive is brought up. */
            if ((dev->reg_addr == EPAT_REG_DEVCTL) && !(val & 0x04))
                epat_device_reset(dev);
        } else
            epat_log(dev->log, "W reg %02X out of range\n", dev->reg_addr);
        return;
    }

    if (val & EPAT_WRITE_TAG) {
        dev->reg_addr  = val & ~EPAT_WRITE_TAG;
        dev->reg_write = 1;
    } else {
        dev->reg_addr  = val;
        dev->nibble_hi = 0;
    }
}

static void
epat_write_ctrl(uint8_t val, void *priv)
{
    epat_t *dev = (epat_t *) priv;

    /*
     * The frame is committed by pulsing nINIT: 0x04 -> 0x05 -> 0x04. Act on
     * the rising edge of bit 0 while a command byte is pending.
     */
    if (!(dev->ctrl & 0x01) && (val & 0x01) && (dev->ustate == EPAT_UNLOCK_IDLE) && dev->ucmd) {
        if (dev->ucmd == EPAT_CPP_CONNECT) {
            dev->connected = 1;
            dev->status    = EPAT_STAT_IDLE;
            epat_log(dev->log, "CONNECT\n");
        } else if (dev->ucmd == EPAT_CPP_DISCONNECT) {
            dev->connected = 0;
            dev->status    = EPAT_STAT_IDLE;
            epat_log(dev->log, "DISCONNECT\n");
        } else
            epat_log(dev->log, "unlock frame committed with unknown command %02X\n",
                     dev->ucmd);
        dev->ucmd = 0;
        dev->upos = 0;
    }

    /*
     * A register read strobes w2(1) then w2(3), then w2(4) for the second
     * nibble. An unlock frame never writes 0x01, so seeing it both cancels any
     * partial frame match and starts the nibble sequence.
     */
    if (dev->connected && (val == 0x01)) {
        dev->ustate    = EPAT_UNLOCK_IDLE;
        dev->upos      = 0;
        dev->nibble_hi = 0;
    } else if (dev->connected && (val == 0x03))
        dev->nibble_hi = 0; /* first read returns the LOW nibble */
    else if (dev->connected && (val == 0x04) && !dev->ucmd)
        dev->nibble_hi = 1; /* second read returns the HIGH nibble */

    dev->ctrl = val;
}

static uint8_t
epat_read_status(void *priv)
{
    epat_t *dev = (epat_t *) priv;
    uint8_t val;
    uint8_t ret;

    /* Mid-handshake the checkpoints take priority over any register value. */
    if ((dev->ustate != EPAT_UNLOCK_IDLE) || !dev->connected)
        return dev->status;

    if (dev->reg_addr >= sizeof(dev->regs))
        return dev->status;

    val = dev->regs[dev->reg_addr];

    /*
     * j44(a, b) = ((a >> 4) & 0x0f) | (b & 0xf0), so each nibble must arrive in
     * the TOP four bits. The low four are not used by the combine; the bridge
     * drives them from its own state and the driver ignores them.
     */
    if (dev->nibble_hi)
        ret = (val & 0xF0) | (EPAT_STAT_IDLE & 0x0F);
    else
        ret = (uint8_t) ((val & 0x0F) << 4) | (EPAT_STAT_IDLE & 0x0F);

    epat_log(dev->log, "R reg %02X %s nibble -> %02X (value %02X)\n",
             dev->reg_addr, dev->nibble_hi ? "high" : "low", ret, val);

    return ret;
}

static uint8_t
epat_read_ctrl(void *priv)
{
    const epat_t *dev = (epat_t *) priv;

    return dev->ctrl;
}

static void *
epat_init(UNUSED(const device_t *info))
{
    epat_t *dev = (epat_t *) calloc(1, sizeof(epat_t));

    if (dev == NULL)
        return NULL;

    dev->status = EPAT_STAT_IDLE;
    dev->log    = log_open("EPAT");

    dev->lpt = lpt_attach_ex(device_get_config_int("port"),
                             epat_write_data, epat_write_ctrl, NULL,
                             epat_read_status, epat_read_ctrl,
                             NULL, NULL, dev);

    return dev;
}

static void
epat_close(void *priv)
{
    epat_t *dev = (epat_t *) priv;

    if (dev != NULL) {
        if (dev->log != NULL)
            log_close(dev->log);
        free(dev);
    }
}

static const device_config_t epat_config[] = {
    {
        .name           = "port",
        .description    = "Parallel Port",
        .type           = CONFIG_SELECTION,
        .default_string = NULL,
        .default_int    = 0,
        .file_filter    = NULL,
        .spinner        = { 0 },
        .selection      = {
            { .description = "LPT1", .value = 0 },
            { .description = "LPT2", .value = 1 },
            { .description = "LPT3", .value = 2 },
            { .description = "LPT4", .value = 3 },
            { .description = ""                 }
        },
        .bios           = { { 0 } }
    },
    { .name = "", .description = "", .type = CONFIG_END }
};

const device_t lpt_epat_device = {
    .name          = "Shuttle EPAT parallel-port ATAPI bridge",
    .internal_name = "lpt_epat",
    .flags         = DEVICE_LPT,
    .local         = 0,
    .init          = epat_init,
    .close         = epat_close,
    .reset         = NULL,
    .available     = NULL,
    .speed_changed = NULL,
    .force_redraw  = NULL,
    .config        = epat_config
};
