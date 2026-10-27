
#include <pcap.h>
#include <stdio.h>
#include <signal.h>

pcap_t *handle;

void stop_capture(int sig)
{
    pcap_breakloop(handle);
}

void save_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    pcap_dumper_t *dumpfile = (pcap_dumper_t *)args;
    pcap_dump(args, header, packet);
    pcap_dump_flush(dumpfile);
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live("eth0", 65535, 1, 1000, errbuf);

    if (handle == NULL)
    {
        printf("Error: %s\n", errbuf);
        return 1;
    }

    struct bpf_program filter;

    if (pcap_compile(handle, &filter, "tcp port 9000", 1, PCAP_NETMASK_UNKNOWN) == -1)
    {
        printf("Filter error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &filter) == -1)
    {
        printf("Filter error: %s\n", pcap_geterr(handle));
        pcap_freecode(&filter);
        pcap_close(handle);
        return 1;
    }

    pcap_freecode(&filter);

    pcap_dumper_t *dumpfile = pcap_dump_open(handle, argc > 1 ? argv[1] : "/captures/as3.pcap");

    if (dumpfile == NULL)
    {
        printf("File error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    signal(SIGINT, stop_capture);

    printf("Capturing TCP port 9000. Press Ctrl+C to stop.\n");

    pcap_loop(handle, -1, save_packet, (u_char *)dumpfile);

    pcap_dump_close(dumpfile);
    pcap_close(handle);

    printf("Capture saved.\n");
    return 0;
}
