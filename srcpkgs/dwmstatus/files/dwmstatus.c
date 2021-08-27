#define _DEFAULT_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>

#define UNKNOWN_STR "n/a"

#include <X11/Xlib.h>

char *tz = "America/New_York";
char *tzutc = "UTC";

static Display *dpy;

char *
smprintf(char *fmt, ...)
{
	va_list fmtargs;
	char *ret;
	int len;

	va_start(fmtargs, fmt);
	len = vsnprintf(NULL, 0, fmt, fmtargs);
	va_end(fmtargs);

	ret = malloc(++len);
	if (ret == NULL) {
		perror("malloc");
		exit(1);
	}

	va_start(fmtargs, fmt);
	vsnprintf(ret, len, fmt, fmtargs);
	va_end(fmtargs);

	return ret;
}

void
settz(char *tzname)
{
	setenv("TZ", tzname, 1);
}

int
parse_netdev(unsigned long long int *receivedabs, unsigned long long int *sentabs)
{
	char buf[255];
	char *datastart;
	static int bufsize;
	int rval;
	FILE *devfd;
	unsigned long long int receivedacc, sentacc;

	bufsize = 255;
	devfd = fopen("/proc/net/dev", "r");
	rval = 1;

	// Ignore the first two lines of the file
	fgets(buf, bufsize, devfd);
	fgets(buf, bufsize, devfd);

	while (fgets(buf, bufsize, devfd)) {
	    if ((datastart = strstr(buf, "lo:")) == NULL) {
		datastart = strstr(buf, ":");

		// With thanks to the conky project at http://conky.sourceforge.net/
		sscanf(datastart + 1, "%llu  %*d     %*d  %*d  %*d  %*d   %*d        %*d       %llu",\
		       &receivedacc, &sentacc);
		*receivedabs += receivedacc;
		*sentabs += sentacc;
		rval = 0;
	    }
	}

	fclose(devfd);
	return rval;
}

void
calculate_speed(char *speedstr, unsigned long long int newval, unsigned long long int oldval)
{
	double speed;
	speed = (newval - oldval) / 1024.0;
	if (speed > 1024.0) {
	    speed /= 1024.0;
	    sprintf(speedstr, "%.3f M", speed);
	} else {
	    sprintf(speedstr, "%.2f K", speed);
	}
}

char *
get_netusage(unsigned long long int *rec, unsigned long long int *sent)
{
	unsigned long long int newrec, newsent;
	newrec = newsent = 0;
	char downspeedstr[15], upspeedstr[15];
	static char retstr[42];
	int retval;

	retval = parse_netdev(&newrec, &newsent);
	if (retval) {
	    fprintf(stdout, "Error when parsing /proc/net/dev file.\n");
	    exit(1);
	}

	calculate_speed(downspeedstr, newrec, *rec);
	calculate_speed(upspeedstr, newsent, *sent);

	sprintf(retstr, "▼ %s  ▲ %s", downspeedstr, upspeedstr);

	*rec = newrec;
	*sent = newsent;
	return retstr;
}

int
runevery(time_t *ltime, int sec)
{
	/* return 1 if sec elapsed since last run
	 * else return 0
	 */
	time_t now = time(NULL);

	if (difftime(now, *ltime ) >= sec) {
		*ltime = now;
		return 1;
	}
	else
		return 0;
}

char *
mktimes(char *fmt, char *tzname)
{
	char buf[129];
	time_t tim;
	struct tm *timtm;

	memset(buf, 0, sizeof(buf));
	settz(tzname);
	tim = time(NULL);
	timtm = localtime(&tim);
	if (timtm == NULL) {
		perror("localtime");
		exit(1);
	}

	if (!strftime(buf, sizeof(buf)-1, fmt, timtm)) {
		fprintf(stderr, "strftime == 0\n");
		exit(1);
	}

	return smprintf("%s", buf);
}

void
setstatus(char *str)
{
	XStoreName(dpy, DefaultRootWindow(dpy), str);
	XSync(dpy, False);
}

char *
loadavg(void)
{
	double avgs[3];

	if (getloadavg(avgs, 3) < 0) {
		perror("getloadavg");
		exit(1);
	}

	return smprintf("%.2f %.2f %.2f", avgs[0], avgs[1], avgs[2]);
}

/* Here is a helper function that warns you if someone tries to sniff your
 * network traffic (i.e. a Man-In-The-Middle attack ran against you thanks
 * to ARP cache poisoning).
 *
 * It checks the dump file of the kernel ARP table (/proc/net/arp) to see
 * if there is more than one IP address associated with the same MAC
 * address.  If so, it shows an alert.  If an error occurs during the
 * check, it returns NULL.
 *
 * Written by vladz (vladz AT devzero.fr).
 */

/* The hard maximum number of entries kept in the ARP cache is obtained via
 * "sysctl net.ipv4.neigh.default.gc_thresh3" (see arp(7)).  Default value
 * for Linux is 1024.
 */
#define MAX_ARP_CACHE_ENTRIES  1024

char *
detect_arp_spoofing(void)
{

	FILE *fp;
	int  i = 1, j;
	char **ptr = NULL;
	char buf[100], *mac[MAX_ARP_CACHE_ENTRIES];

	if (!(fp = fopen("/proc/net/arp", "r"))) {
		return NULL;
	}

	ptr = mac;

	while (fgets(buf, sizeof(buf) - 1, fp)) {

		/* ignore the first line. */
		if (i == 1) { i = 0; continue; }

		if ((*ptr = malloc(18)) == NULL) {
			return NULL;
		}

		sscanf(buf, "%*s %*s %*s %s", *ptr);
		ptr++;
	}

	/* end table with a 0. */
	*ptr = 0;

	fclose(fp);

	for (i = 0; mac[i] != 0; i++)
		for (j = i + 1; mac[j] != 0; j++)
			if ((strcmp("00:00:00:00:00:00", mac[i]) != 0) &&
					(strcmp(mac[i], mac[j]) == 0)) {

				return "** MITM detected! Type \"arp -a\". **";
			}

	return "";
}

#define BATT_NOW        "/sys/class/power_supply/BAT0/energy_now"
#define BATT_FULL       "/sys/class/power_supply/BAT0/energy_full"
#define BATT_STATUS       "/sys/class/power_supply/BAT0/status"
#define BATT_POWER       "/sys/class/power_supply/BAT0/power_now"

char *
getbattery(){
    long lnum1, lnum2, lnum3;
    char *status = malloc(sizeof(char)*12);
    char s = '?';
    FILE *fp = NULL;
    if ((fp = fopen(BATT_NOW, "r"))) {
        fscanf(fp, "%ld\n", &lnum1);
        fclose(fp);
        fp = fopen(BATT_FULL, "r");
        fscanf(fp, "%ld\n", &lnum2);
        fclose(fp);
        fp = fopen(BATT_STATUS, "r");
        fscanf(fp, "%s\n", status);
        fclose(fp);
        fp = fopen(BATT_POWER, "r");
        fscanf(fp, "%ld\n", &lnum3);
        fclose(fp);
        if (strcmp(status,"Charging") == 0)
            s = '+';
        if (strcmp(status,"Discharging") == 0 && lnum3 != 0)
            s = '-';
        if (strcmp(status,"Full") == 0 || lnum3 == 0)
            s = '=';
        return smprintf("%c%ld%%", s,(lnum1/(lnum2/100)));
    }
    else return smprintf("");
}

static char *
ram_free(void)
{
        long free;
        FILE *fp;

        fp = fopen("/proc/meminfo", "r");
        if (fp == NULL) {
                warn("Failed to open file /proc/meminfo");
                return smprintf("%s", UNKNOWN_STR);
        }
        fscanf(fp, "MemFree: %ld kB\n", &free);
        fclose(fp);

        return smprintf("%f", (float)free / 1024 / 1024);
}

static char *
ram_perc(void)
{
        long total, free, buffers, cached;
        FILE *fp;

        fp = fopen("/proc/meminfo", "r");
        if (fp == NULL) {
                warn("Failed to open file /proc/meminfo");
                return smprintf("%s", UNKNOWN_STR);
        }
        fscanf(fp, "MemTotal: %ld kB\n", &total);
        fscanf(fp, "MemFree: %ld kB\n", &free);
        fscanf(fp, "MemAvailable: %ld kB\nBuffers: %ld kB\n", &buffers, &buffers);
        fscanf(fp, "Cached: %ld kB\n", &cached);
        fclose(fp);

        return smprintf("%d%%", 100 * ((total - free) - (buffers + cached)) / total);
}

static char *
ram_total(void)
{
        long total;
        FILE *fp;

        fp = fopen("/proc/meminfo", "r");
        if (fp == NULL) {
                warn("Failed to open file /proc/meminfo");
                return smprintf("%s", UNKNOWN_STR);
        }
        fscanf(fp, "MemTotal: %ld kB\n", &total);
        fclose(fp);

        return smprintf("%f", (float)total / 1024 / 1024);
}

int
main(void)
{
	time_t count5secs = 0;
	time_t count1mins = 0;
	time_t count10min = 0;
	char *status = NULL;
	char *avgs = NULL;
	char *tm = NULL;
	char *tmutc = NULL;
	char *mitm = NULL;
	char *battery = NULL;
	char *netstats = NULL;
	char *ram = NULL;
	unsigned long long int parA, parB;
	parA = parB = 0;

	if (!(dpy = XOpenDisplay(NULL))) {
		fprintf(stderr, "dwmstatus: cannot open display.\n");
		return 1;
	}

	parse_netdev(&parA, &parB);
	for (;;sleep(1)) {
		if (runevery(&count10min, 600)) {
			mitm = detect_arp_spoofing();
		}
		if (runevery(&count1mins, 60)) {
			free(battery);
			battery = getbattery();
		}
		if (runevery(&count5secs, 5)) {
			free(ram);
			ram = ram_perc();
		}
		free(tm);
		free(tmutc);
		free(avgs);
		avgs = loadavg();
		tm = mktimes("%F %T", tz);
		tmutc = mktimes("%H:%MZ", tzutc);
		netstats = get_netusage(&parA, &parB);

		status = smprintf("%s { %s | %s : %s | %s [ %s, %s",
				mitm, netstats, ram, avgs, battery, tm, tmutc);
		setstatus(status);
		free(status);
	}

	XCloseDisplay(dpy);

	return 0;
}
